// bl-bench: ReadProperty throughput/latency and COV notification fan-out.
//
//   bl-bench rp  ADDR [--requests N] [--concurrency C] [--timeout MS]
//   bl-bench cov ADDR [--subs N] [--rounds R]
// Prints one JSON object per run.
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <thread>

#include "../src/client.hpp"
#include "cli.hpp"

using namespace bac;

static double pct(std::vector<double>& v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t i = size_t(p / 100.0 * double(v.size() - 1) + 0.5);
    return v[std::min(i, v.size() - 1)];
}

static double us_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::micro>(Clock::now() - t0).count();
}

static int bench_rp(const Addr& dst, int requests, int concurrency, int timeout_ms) {
    Client c;
    Client::Options o;
    o.apdu_timeout_ms = timeout_ms;
    o.retries = 0;  // a lost request should show up as a timeout, not a hidden retry
    if (!c.start(o)) return 1;
    Writer body;
    encode_read_property(body, {{kAnalogInput, 1}, {kPropPresentValue, std::nullopt}});

    std::mutex mu;
    std::condition_variable cv;
    std::vector<double> lat;
    lat.reserve(size_t(requests));
    int issued = 0, done = 0, failed = 0, in_flight = 0;
    auto t_start = Clock::now();
    std::unique_lock<std::mutex> lk(mu);
    while (done < requests) {
        while (in_flight < concurrency && issued < requests) {
            auto t0 = Clock::now();
            ++issued;
            ++in_flight;
            lk.unlock();
            bool sent = c.endpoint().tsm().request(dst, kSvcReadProperty, body.buf, [&, t0](Result r) {
                double us = us_since(t0);
                std::lock_guard<std::mutex> g(mu);
                if (r.kind == Result::kComplexAck) lat.push_back(us);
                else ++failed;
                ++done;
                --in_flight;
                cv.notify_one();
            });
            lk.lock();
            if (!sent) {  // all invoke IDs busy; wait for one to come back
                --issued;
                --in_flight;
                break;
            }
        }
        // Wake only when there is something to issue or we are finished. A predicate that is
        // already true once everything is issued makes wait() return without ever releasing
        // the mutex, and the completion callbacks (which need it) starve: a livelock.
        cv.wait(lk, [&] { return (in_flight < concurrency && issued < requests) || done >= requests; });
    }
    double secs = us_since(t_start) / 1e6;
    lk.unlock();
    c.stop();
    std::printf("{\"bench\":\"readproperty\",\"requests\":%d,\"concurrency\":%d,\"ok\":%zu,\"failed\":%d,"
                "\"seconds\":%.3f,\"rps\":%.0f,\"p50_us\":%.1f,\"p90_us\":%.1f,\"p99_us\":%.1f,\"p999_us\":%.1f,"
                "\"max_us\":%.1f}\n",
                requests, concurrency, lat.size(), failed, secs, double(lat.size()) / secs, pct(lat, 50),
                pct(lat, 90), pct(lat, 99), pct(lat, 99.9), pct(lat, 100));
    return failed ? 1 : 0;
}

static int bench_cov(const Addr& dst, int subs, int rounds, bool keep) {
    Client c;
    if (!c.start({})) return 1;
    const ObjectId av1{kAnalogValue, 1};
    std::mutex mu;
    std::condition_variable cv;
    float expect = 0;
    int got = 0;
    Clock::time_point first, last;
    c.on_cov([&](const Addr&, const CovNotification& n, bool) {
        for (const auto& v : n.values) {
            if (v.prop.property != kPropPresentValue || v.values.empty() || v.values[0].index() != kTagReal) continue;
            std::lock_guard<std::mutex> g(mu);
            if (std::get<float>(v.values[0]) != expect) return;  // initial / stale notification
            if (got++ == 0) first = Clock::now();
            last = Clock::now();
            cv.notify_one();
        }
    });
    // N subscriptions from one socket, distinguished by subscriber process id.
    for (int pid = 1; pid <= subs; ++pid) {
        SubscribeCovReq s{uint32_t(pid), av1, false, 600};
        Result r = c.subscribe_cov(dst, s);
        if (!r.ok()) {
            std::fprintf(stderr, "subscribe %d failed: %s\n", pid, to_string(r).c_str());
            return 1;
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));  // drain initial notifications

    std::vector<double> all_us, first_us, ack_us;
    int incomplete = 0;
    for (int round = 0; round < rounds; ++round) {
        float value = 30.0f + float(round % 2);  // alternate by 1.0 > COV increment 0.1
        {
            std::lock_guard<std::mutex> g(mu);
            expect = value;
            got = 0;
        }
        WritePropertyReq w{av1, {kPropPresentValue, std::nullopt}, {value}, uint8_t(8)};
        auto t0 = Clock::now();
        if (!c.write_property(dst, w).ok()) return 1;
        ack_us.push_back(us_since(t0));
        std::unique_lock<std::mutex> lk(mu);
        if (cv.wait_for(lk, std::chrono::seconds(2), [&] { return got >= subs; })) {
            all_us.push_back(std::chrono::duration<double, std::micro>(last - t0).count());
            first_us.push_back(std::chrono::duration<double, std::micro>(first - t0).count());
        } else {
            ++incomplete;
        }
    }
    // relinquish and cancel so the device is left as found -- leftover subscriptions
    // keep costing fan-out time until their lifetime runs out (see docs/NOTES.md)
    c.write_property(dst, {av1, {kPropPresentValue, std::nullopt}, {Null{}}, uint8_t(8)});
    if (!keep)
        for (int pid = 1; pid <= subs; ++pid) c.subscribe_cov(dst, {uint32_t(pid), av1, std::nullopt, std::nullopt});
    c.stop();
    std::printf("{\"bench\":\"cov_fanout\",\"subscriptions\":%d,\"rounds\":%d,\"incomplete\":%d,"
                "\"ack_p50_us\":%.1f,\"first_p50_us\":%.1f,\"all_p50_us\":%.1f,\"all_p99_us\":%.1f,\"per_notification_us\":%.2f}\n",
                subs, rounds, incomplete, pct(ack_us, 50), pct(first_us, 50), pct(all_us, 50), pct(all_us, 99),
                (pct(all_us, 50) - pct(first_us, 50)) / std::max(1, subs - 1));
    return incomplete ? 1 : 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: bl-bench rp|cov ADDR [--requests N] [--concurrency C] [--timeout MS]"
                             " [--subs N] [--rounds R]\n");
        return 2;
    }
    std::string mode = argv[1];
    Addr dst;
    if (!parse_addr(argv[2], dst)) return 2;
    int requests = 20000, concurrency = 1, timeout_ms = 2000, subs = 100, rounds = 50;
    bool keep = false;
    for (int i = 3; i < argc; i += 2) {
        std::string a = argv[i];
        if (a == "--keep") {  // leave the subscriptions behind (stale-subscription experiment)
            keep = true;
            --i;
            continue;
        }
        if (i + 1 >= argc) break;
        int v = std::stoi(argv[i + 1]);
        if (a == "--requests") requests = v;
        else if (a == "--concurrency") concurrency = std::clamp(v, 1, 255);
        else if (a == "--timeout") timeout_ms = v;
        else if (a == "--subs") subs = v;
        else if (a == "--rounds") rounds = v;
    }
    if (mode == "rp") return bench_rp(dst, requests, concurrency, timeout_ms);
    if (mode == "cov") return bench_cov(dst, subs, rounds, keep);
    return 2;
}
