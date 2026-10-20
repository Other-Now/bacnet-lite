#include "client.hpp"

namespace bac {

bool Client::start(const Options& opt) {
    Endpoint::Options eo;
    eo.port = opt.port;
    eo.workers = 0;  // the client's handlers are tiny; run them on the receive thread
    eo.apdu_timeout_ms = opt.apdu_timeout_ms;
    eo.retries = opt.retries;
    eo.pcap = opt.pcap;
    return ep_.start(eo, [this](const Incoming& in) { handle(in); });
}

void Client::handle(const Incoming& in) {
    const Bytes& f = in.frame;
    Reader r(f.data() + in.apdu.body_offset, f.size() - in.apdu.body_offset);
    if (in.apdu.type == kPduUnconfirmedRequest) {
        if (in.apdu.service == kSvcIAm) {
            IAm iam;
            if (!decode_iam(r, iam)) return;
            std::lock_guard<std::mutex> lk(mu_);
            iams_.push_back({in.src, iam});
        } else if (in.apdu.service == kSvcUnconfirmedCovNotification) {
            CovNotification n;
            if (!decode_cov_notification(r, n)) return;
            std::lock_guard<std::mutex> lk(mu_);
            if (cov_) cov_(in.src, n, false);
        }
        return;
    }
    // Confirmed requests: the only one a client executes is ConfirmedCOVNotification.
    Writer w;
    if (in.apdu.service == kSvcConfirmedCovNotification) {
        CovNotification n;
        if (!decode_cov_notification(r, n)) {
            encode_reject(w, in.apdu.invoke_id, kRejectInvalidTag);
        } else {
            encode_simple_ack(w, in.apdu.invoke_id, kSvcConfirmedCovNotification);
            std::lock_guard<std::mutex> lk(mu_);
            if (cov_) cov_(in.src, n, true);
        }
    } else {
        encode_reject(w, in.apdu.invoke_id, kRejectUnrecognizedService);
    }
    ep_.send_apdu(in.src, w.buf, false, in.npdu.source);
}

std::vector<Discovered> Client::who_is(const Addr& dst, const WhoIs& range, int wait_ms, bool broadcast) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        iams_.clear();
    }
    Writer w;
    encode_unconfirmed_header(w, kSvcWhoIs);
    encode_whois(w, range);
    if (broadcast)
        ep_.send_broadcast(dst, w.buf);
    else
        ep_.send_apdu(dst, w.buf);
    std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
    std::lock_guard<std::mutex> lk(mu_);
    return iams_;
}

Result Client::read_property(const Addr& dst, const ReadPropertyReq& req, ReadPropertyAck* ack) {
    Writer w;
    encode_read_property(w, req);
    Result r = ep_.tsm().request_sync(dst, kSvcReadProperty, w.buf);
    if (r.kind == Result::kComplexAck && ack) {
        Reader rd(r.body);
        if (!decode_read_property_ack(rd, *ack)) {
            r.kind = Result::kReject;  // malformed ack: report it rather than half-decode it
            r.reason = kRejectInvalidTag;
        }
    }
    return r;
}

Result Client::write_property(const Addr& dst, const WritePropertyReq& req) {
    Writer w;
    encode_write_property(w, req);
    return ep_.tsm().request_sync(dst, kSvcWriteProperty, w.buf);
}

Result Client::read_property_multiple(const Addr& dst, const std::vector<ReadAccessSpec>& specs,
                                      std::vector<RpmResult>* out) {
    Writer w;
    encode_rpm(w, specs);
    Result r = ep_.tsm().request_sync(dst, kSvcReadPropertyMultiple, w.buf);
    if (r.kind == Result::kComplexAck && out) {
        Reader rd(r.body);
        if (!decode_rpm_ack(rd, *out)) {
            r.kind = Result::kReject;
            r.reason = kRejectInvalidTag;
        }
    }
    return r;
}

Result Client::subscribe_cov(const Addr& dst, const SubscribeCovReq& req) {
    Writer w;
    encode_subscribe_cov(w, req);
    return ep_.tsm().request_sync(dst, kSvcSubscribeCov, w.buf);
}

}  // namespace bac
