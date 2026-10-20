#include "stack.hpp"

#include <future>

namespace bac {

std::string to_string(const Result& r) {
    switch (r.kind) {
        case Result::kSimpleAck: return "ack";
        case Result::kComplexAck: return "complex-ack";
        case Result::kError: return to_string(r.error);
        case Result::kReject: return "reject(reason=" + std::to_string(r.reason) + ")";
        case Result::kAbort: return "abort(reason=" + std::to_string(r.reason) + ")";
        case Result::kTimeout: return "timeout after " + std::to_string(r.attempts) + " attempts";
    }
    return "?";
}

// ------------------------------------------------------------------ TSM

bool Tsm::request(const Addr& dst, uint8_t service, const Bytes& body, Callback cb) {
    Bytes apdu;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (pending_.size() >= 256) return false;
        while (pending_.count(next_id_)) ++next_id_;  // uint8_t wraps 255 -> 0
        uint8_t id = next_id_++;
        Writer w;
        encode_confirmed_header(w, id, service);
        w.raw(body);
        apdu = w.buf;
        pending_[id] = Pending{dst, service, apdu, Clock::now() + std::chrono::milliseconds(timeout_ms_), 1,
                               std::move(cb)};
    }
    send_(dst, apdu);
    return true;
}

Result Tsm::request_sync(const Addr& dst, uint8_t service, const Bytes& body) {
    auto prom = std::make_shared<std::promise<Result>>();
    auto fut = prom->get_future();
    if (!request(dst, service, body, [prom](Result r) { prom->set_value(std::move(r)); })) {
        Result r;
        r.kind = Result::kAbort;
        r.reason = kAbortOther;
        return r;
    }
    return fut.get();
}

bool Tsm::on_response(const Addr& src, const Apdu& a, const uint8_t* body, size_t n) {
    Pending p;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pending_.find(a.invoke_id);
        // The invoke ID is only unique per peer: a reply from anyone else is not ours.
        if (it == pending_.end() || !(it->second.dst == src)) return false;
        if ((a.type == kPduSimpleAck || a.type == kPduComplexAck || a.type == kPduError) &&
            a.service != it->second.service)
            return false;
        p = std::move(it->second);
        pending_.erase(it);
    }
    Result r;
    r.attempts = p.attempts;
    Reader rd(body, n);
    switch (a.type) {
        case kPduSimpleAck: r.kind = Result::kSimpleAck; break;
        case kPduComplexAck:
            if (a.segmented) {  // we never accept segmented responses
                r.kind = Result::kAbort;
                r.reason = kAbortSegmentationNotSupported;
                break;
            }
            r.kind = Result::kComplexAck;
            r.body.assign(body, body + n);
            break;
        case kPduError:
            r.kind = Result::kError;
            if (!decode_error_body(rd, r.error)) r.error = {kErrClassServices, kErrOther};
            break;
        case kPduReject: r.kind = Result::kReject; r.reason = a.service; break;
        case kPduAbort: r.kind = Result::kAbort; r.reason = a.service; break;
        default: r.kind = Result::kAbort; break;
    }
    p.cb(std::move(r));
    return true;
}

void Tsm::tick() {
    std::vector<Pending> expired;
    std::vector<std::pair<Addr, Bytes>> resend;
    auto now = Clock::now();
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            Pending& p = it->second;
            if (now < p.deadline) {
                ++it;
                continue;
            }
            if (p.attempts <= retries_) {
                ++p.attempts;
                p.deadline = now + std::chrono::milliseconds(timeout_ms_);
                resend.emplace_back(p.dst, p.apdu);
                ++it;
            } else {
                expired.push_back(std::move(p));
                it = pending_.erase(it);
            }
        }
    }
    for (auto& [dst, apdu] : resend) {
        ++retransmits_;
        send_(dst, apdu);
    }
    for (auto& p : expired) {
        Result r;
        r.kind = Result::kTimeout;
        r.attempts = p.attempts;
        p.cb(std::move(r));
    }
}

size_t Tsm::outstanding() const {
    std::lock_guard<std::mutex> lk(mu_);
    return pending_.size();
}

// ------------------------------------------------------------------ Endpoint

Endpoint::Endpoint() = default;
Endpoint::~Endpoint() { stop(); }

bool Endpoint::start(const Options& opt, Handler handler) {
    opt_ = opt;
    handler_ = std::move(handler);
    if (!net_init() || !sock_.open(opt.port)) return false;
    if (!opt.pcap.empty() && !pcap_.open(opt.pcap)) return false;
    tsm_ = std::make_unique<Tsm>([this](const Addr& d, const Bytes& apdu) { send_apdu(d, apdu, true); },
                                 opt.apdu_timeout_ms, opt.retries);
    running_ = true;
    rx_thread_ = std::thread(&Endpoint::recv_loop, this);
    timer_thread_ = std::thread(&Endpoint::timer_loop, this);
    for (int i = 0; i < opt.workers; ++i) workers_.emplace_back(&Endpoint::worker_loop, this);
    return true;
}

void Endpoint::start_offline(Handler handler, std::function<void(const Addr&, const Bytes&)> sink) {
    handler_ = std::move(handler);
    sink_ = std::move(sink);
    opt_.workers = 0;
    tsm_ = std::make_unique<Tsm>([this](const Addr& d, const Bytes& apdu) { send_apdu(d, apdu, true); }, 3000, 0);
}

void Endpoint::stop() {
    if (!running_.exchange(false)) return;
    q_cv_.notify_all();
    if (rx_thread_.joinable()) rx_thread_.join();
    if (timer_thread_.joinable()) timer_thread_.join();
    for (auto& t : workers_) t.join();
    workers_.clear();
    sock_.close();
}

void Endpoint::send_frame(const Addr& dst, const Bytes& frame) {
    ++tx_frames;
    if (sink_) {
        sink_(dst, frame);
        return;
    }
    if (pcap_.is_open()) pcap_.write({0x7F000001, port()}, dst, frame.data(), frame.size());
    sock_.send_to(dst, frame.data(), frame.size());
}

void Endpoint::send_apdu(const Addr& dst, const Bytes& apdu, bool expecting_reply,
                         const std::optional<NetAddr>& route) {
    Writer w;
    encode_npdu(w, expecting_reply, route);
    w.raw(apdu);
    send_frame(dst, encode_bvlc(kBvlcOriginalUnicast, w.buf));
}

void Endpoint::broadcast_apdu(const Bytes& apdu, const Addr& fallback) {
    Writer w;
    encode_npdu(w, false);
    w.raw(apdu);
    if (opt_.broadcast) {
        send_frame(*opt_.broadcast, encode_bvlc(kBvlcOriginalBroadcast, w.buf));
        return;
    }
    // no broadcast domain configured (e.g. loopback tests): answer the asker directly
    send_frame(fallback, encode_bvlc(kBvlcOriginalUnicast, w.buf));
}

void Endpoint::send_broadcast(const Addr& bcast, const Bytes& apdu) {
    Writer w;
    encode_npdu(w, false);
    w.raw(apdu);
    send_frame(bcast, encode_bvlc(kBvlcOriginalBroadcast, w.buf));
}

void Endpoint::process_datagram(const Addr& src_in, const uint8_t* p, size_t n) {
    ++rx_frames;
    Bvlc b;
    if (!decode_bvlc(p, n, b)) {
        ++rx_dropped;
        return;
    }
    Addr src = b.originator.value_or(src_in);
    Reader r(p + b.npdu_offset, n - b.npdu_offset);
    Incoming in;
    if (!decode_npdu(r, in.npdu) || in.npdu.network_message) {  // we are not a router
        ++rx_dropped;
        return;
    }
    if (in.npdu.dest && in.npdu.dest->net != 0xFFFF) {  // addressed to a remote network
        ++rx_dropped;
        return;
    }
    size_t apdu_off = b.npdu_offset + r.pos();
    Reader ra(p + apdu_off, n - apdu_off);
    if (!decode_apdu(ra, in.apdu)) {
        ++rx_dropped;
        return;
    }
    in.apdu.body_offset += apdu_off;
    if (in.apdu.type != kPduConfirmedRequest && in.apdu.type != kPduUnconfirmedRequest) {
        if (!tsm_->on_response(src, in.apdu, p + in.apdu.body_offset, n - in.apdu.body_offset)) ++rx_dropped;
        return;
    }
    in.src = src;
    in.broadcast = b.function != kBvlcOriginalUnicast;
    in.frame.assign(p, p + n);
    if (opt_.workers == 0) {
        handler_(in);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(q_mu_);
        if (queue_.size() >= 4096) {  // overload: shed rather than queue unboundedly
            ++rx_dropped;
            return;
        }
        queue_.push_back(std::move(in));
    }
    q_cv_.notify_one();
}

void Endpoint::recv_loop() {
    uint8_t buf[2048];
    while (running_) {
        Addr src;
        int got = sock_.recv_from(buf, sizeof buf, src, 100);
        if (got < 0) ++rx_errors;  // never fatal: on UDP an error here is about an earlier send
        if (got <= 0) continue;
        if (pcap_.is_open()) pcap_.write(src, {0x7F000001, port()}, buf, size_t(got));
        process_datagram(src, buf, size_t(got));
    }
}

void Endpoint::worker_loop() {
    for (;;) {
        Incoming in;
        {
            std::unique_lock<std::mutex> lk(q_mu_);
            q_cv_.wait(lk, [&] { return !queue_.empty() || !running_; });
            if (!running_ && queue_.empty()) return;
            in = std::move(queue_.front());
            queue_.pop_front();
        }
        handler_(in);
    }
}

void Endpoint::timer_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        tsm_->tick();
        if (on_tick) on_tick();
    }
}

}  // namespace bac
