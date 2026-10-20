// bl-client: command-line BACnet/IP client.
//
//   bl-client [--port P] [--timeout MS] [--retries N] [--pcap FILE] [--json] COMMAND ...
//     whois     ADDR [--broadcast] [--range LO HI] [--wait MS]
//     read      ADDR OBJECT PROPERTY[INDEX]
//     write     ADDR OBJECT PROPERTY VALUE|null [--priority N] [--type real|enum|bool|unsigned]
//     rpm       ADDR OBJECT PROP,PROP,... [OBJECT PROPS ...]
//     subscribe ADDR OBJECT [--lifetime S] [--confirmed] [--duration S] [--pid N]
//   ADDR = a.b.c.d[:port] (default port 47808); OBJECT = analog-input:1 / ai:1 / device:1234
#include <atomic>
#include <cmath>
#include <cstdio>
#include <thread>

#include "../src/client.hpp"
#include "cli.hpp"

using namespace bac;
using namespace cli;

static bool g_json = false;

static int usage() {
    std::fprintf(stderr,
                 "usage: bl-client [--port P] [--timeout MS] [--retries N] [--pcap FILE] [--json] COMMAND ...\n"
                 "  whois ADDR [--broadcast] [--range LO HI] [--wait MS]\n"
                 "  read ADDR OBJECT PROPERTY[INDEX]\n"
                 "  write ADDR OBJECT PROPERTY VALUE|null [--priority N] [--type real|enum|bool|unsigned]\n"
                 "  rpm ADDR OBJECT PROP,PROP,... [OBJECT PROPS ...]\n"
                 "  subscribe ADDR OBJECT [--lifetime S] [--confirmed] [--duration S] [--pid N]\n");
    return 2;
}

// Exit codes: 0 ok, 1 BACnet error/reject/abort, 3 timeout.
static int report_failure(const Result& r) {
    if (g_json) {
        std::string kind = r.kind == Result::kError    ? "error"
                           : r.kind == Result::kReject ? "reject"
                           : r.kind == Result::kAbort  ? "abort"
                                                       : "timeout";
        std::printf("{\"ok\":false,\"kind\":\"%s\",\"error_class\":%u,\"error_code\":%u,\"reason\":%u,"
                    "\"attempts\":%d}\n",
                    kind.c_str(), r.error.cls, r.error.code, unsigned(r.reason), r.attempts);
    } else {
        std::printf("%s\n", to_string(r).c_str());
    }
    return r.kind == Result::kTimeout ? 3 : 1;
}

static bool parse_value(const std::string& s, const std::string& type, ObjectId oid, uint32_t prop, Value& v) {
    if (s == "null") {
        v = Null{};
        return true;
    }
    std::string t = type;
    if (t.empty()) {  // infer from the property and object type
        if (prop == kPropOutOfService) t = "bool";
        else if (prop == kPropCovIncrement) t = "real";
        else if (oid.type <= kAnalogValue) t = "real";
        else if (oid.type <= kBinaryValue) t = "enum";
        else t = "unsigned";
    }
    try {
        if (t == "real") v = std::stof(s);
        else if (t == "enum") v = Enumerated{s == "active" ? 1u : s == "inactive" ? 0u : uint32_t(std::stoul(s))};
        else if (t == "bool") v = s == "true" || s == "1";
        else if (t == "unsigned") v = uint32_t(std::stoul(s));
        else return false;
    } catch (...) {
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    Client::Options opt;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; ++i) {
        std::string a = argv[i];
        if (i + 1 >= argc && a != "--json") return usage();
        if (a == "--port") opt.port = uint16_t(std::stoul(argv[++i]));
        else if (a == "--timeout") opt.apdu_timeout_ms = std::stoi(argv[++i]);
        else if (a == "--retries") opt.retries = std::stoi(argv[++i]);
        else if (a == "--pcap") opt.pcap = argv[++i];
        else if (a == "--json") g_json = true;
        else return usage();
    }
    if (argc - i < 2) return usage();
    std::string cmd = argv[i++];
    Addr dst;
    if (!parse_addr(argv[i++], dst)) return std::fprintf(stderr, "bad address\n"), 2;
    std::vector<std::string> args(argv + i, argv + argc);

    Client client;
    if (!client.start(opt)) return std::fprintf(stderr, "cannot open UDP socket\n"), 1;

    if (cmd == "whois") {
        WhoIs range;
        int wait = 1000;
        bool bcast = false;
        for (size_t k = 0; k < args.size(); ++k) {
            if (args[k] == "--broadcast") bcast = true;
            else if (args[k] == "--wait" && k + 1 < args.size()) wait = std::stoi(args[++k]);
            else if (args[k] == "--range" && k + 2 < args.size()) {
                range.low = uint32_t(std::stoul(args[++k]));
                range.high = uint32_t(std::stoul(args[++k]));
            } else return usage();
        }
        auto found = client.who_is(dst, range, wait, bcast);
        for (const auto& d : found) {
            if (g_json)
                std::printf("{\"device\":%u,\"addr\":\"%s\",\"max_apdu\":%u,\"segmentation\":%u,\"vendor\":%u}\n",
                            d.iam.device.instance, to_string(d.addr).c_str(), d.iam.max_apdu, d.iam.segmentation,
                            d.iam.vendor_id);
            else
                std::printf("device:%u at %s max-apdu=%u vendor=%u\n", d.iam.device.instance,
                            to_string(d.addr).c_str(), d.iam.max_apdu, d.iam.vendor_id);
        }
        client.stop();
        return found.empty() ? 3 : 0;
    }

    if (cmd == "read") {
        if (args.size() != 2) return usage();
        ReadPropertyReq req;
        if (!parse_oid(args[0], req.oid) || !parse_prop(args[1], req.prop)) return usage();
        ReadPropertyAck ack;
        Result r = client.read_property(dst, req, &ack);
        client.stop();
        if (!r.ok()) return report_failure(r);
        if (g_json)
            std::printf("{\"ok\":true,\"object\":\"%s\",\"property\":\"%s\",\"values\":%s,\"attempts\":%d}\n",
                        oid_str(ack.oid).c_str(), prop_str(ack.prop).c_str(), values_json(ack.values).c_str(),
                        r.attempts);
        else
            std::printf("%s %s = %s\n", oid_str(ack.oid).c_str(), prop_str(ack.prop).c_str(),
                        values_text(ack.values).c_str());
        return 0;
    }

    if (cmd == "write") {
        if (args.size() < 3) return usage();
        WritePropertyReq req;
        if (!parse_oid(args[0], req.oid) || !parse_prop(args[1], req.prop)) return usage();
        std::string type;
        for (size_t k = 3; k < args.size(); ++k) {
            if (args[k] == "--priority" && k + 1 < args.size()) req.priority = uint8_t(std::stoul(args[++k]));
            else if (args[k] == "--type" && k + 1 < args.size()) type = args[++k];
            else return usage();
        }
        Value v;
        if (!parse_value(args[2], type, req.oid, req.prop.property, v)) return std::fprintf(stderr, "bad value\n"), 2;
        req.values = {v};
        Result r = client.write_property(dst, req);
        client.stop();
        if (!r.ok()) return report_failure(r);
        std::printf(g_json ? "{\"ok\":true,\"attempts\":%d}\n" : "ok (%d attempt(s))\n", r.attempts);
        return 0;
    }

    if (cmd == "rpm") {
        if (args.empty() || args.size() % 2) return usage();
        std::vector<ReadAccessSpec> specs;
        for (size_t k = 0; k < args.size(); k += 2) {
            ReadAccessSpec s;
            if (!parse_oid(args[k], s.oid)) return usage();
            size_t start = 0;
            const std::string& list = args[k + 1];
            while (start <= list.size()) {
                size_t comma = list.find(',', start);
                PropertyRef p;
                if (!parse_prop(list.substr(start, comma - start), p)) return usage();
                s.props.push_back(p);
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
            specs.push_back(s);
        }
        std::vector<RpmResult> out;
        Result r = client.read_property_multiple(dst, specs, &out);
        client.stop();
        if (!r.ok()) return report_failure(r);
        for (const auto& res : out) {
            for (const auto& item : res.items) {
                bool ok = item.result.index() == 0;
                if (g_json) {
                    if (ok)
                        std::printf("{\"object\":\"%s\",\"property\":\"%s\",\"values\":%s}\n", oid_str(res.oid).c_str(),
                                    prop_str(item.prop).c_str(), values_json(std::get<0>(item.result)).c_str());
                    else
                        std::printf("{\"object\":\"%s\",\"property\":\"%s\",\"error_class\":%u,\"error_code\":%u}\n",
                                    oid_str(res.oid).c_str(), prop_str(item.prop).c_str(),
                                    std::get<1>(item.result).cls, std::get<1>(item.result).code);
                } else {
                    std::printf("%s %s = %s\n", oid_str(res.oid).c_str(), prop_str(item.prop).c_str(),
                                ok ? values_text(std::get<0>(item.result)).c_str()
                                   : to_string(std::get<1>(item.result)).c_str());
                }
            }
        }
        return 0;
    }

    if (cmd == "subscribe") {
        if (args.empty()) return usage();
        SubscribeCovReq req;
        if (!parse_oid(args[0], req.oid)) return usage();
        req.process_id = 1;
        req.confirmed = false;
        req.lifetime = 60;
        double duration = 10;
        bool cancel = false;
        for (size_t k = 1; k < args.size(); ++k) {
            if (args[k] == "--lifetime" && k + 1 < args.size()) req.lifetime = uint32_t(std::stoul(args[++k]));
            else if (args[k] == "--confirmed") req.confirmed = true;
            else if (args[k] == "--duration" && k + 1 < args.size()) duration = std::stod(args[++k]);
            else if (args[k] == "--pid" && k + 1 < args.size()) req.process_id = uint32_t(std::stoul(args[++k]));
            else if (args[k] == "--cancel") cancel = true;
            else return usage();
        }
        if (cancel) {
            req.confirmed.reset();
            req.lifetime.reset();
        }
        std::atomic<int> count{0};
        client.on_cov([&](const Addr& from, const CovNotification& n, bool confirmed) {
            ++count;
            std::string pv, flags;
            for (const auto& v : n.values) {
                if (v.prop.property == kPropPresentValue && !v.values.empty())
                    pv = g_json ? value_json(v.values[0]) : to_string(v.values[0]);
                if (v.prop.property == kPropStatusFlags && !v.values.empty())
                    flags = g_json ? value_json(v.values[0]) : to_string(v.values[0]);
            }
            if (g_json)
                std::printf("{\"cov\":true,\"from\":\"%s\",\"pid\":%u,\"object\":\"%s\",\"confirmed\":%s,"
                            "\"time_remaining\":%u,\"present_value\":%s,\"status_flags\":%s}\n",
                            to_string(from).c_str(), n.process_id, oid_str(n.oid).c_str(),
                            confirmed ? "true" : "false", n.time_remaining, pv.empty() ? "null" : pv.c_str(),
                            flags.empty() ? "null" : flags.c_str());
            else
                std::printf("COV %s from device:%u: present-value=%s status-flags=%s (%u s left%s)\n",
                            oid_str(n.oid).c_str(), n.device.instance, pv.c_str(), flags.c_str(), n.time_remaining,
                            confirmed ? ", confirmed" : "");
            std::fflush(stdout);
        });
        Result r = client.subscribe_cov(dst, req);
        if (!r.ok()) {
            client.stop();
            return report_failure(r);
        }
        std::printf(g_json ? "{\"ok\":true,\"subscribed\":%s}\n" : "subscribed=%s\n", cancel ? "false" : "true");
        std::fflush(stdout);
        if (!cancel) std::this_thread::sleep_for(std::chrono::milliseconds(long(duration * 1000)));
        client.stop();
        return 0;
    }
    return usage();
}
