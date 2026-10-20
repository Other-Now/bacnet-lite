// BACnet/IP client: Who-Is discovery, ReadProperty(Multiple), WriteProperty and
// SubscribeCOV, on top of the same Endpoint/TSM the device uses.
#pragma once
#include "stack.hpp"

namespace bac {

struct Discovered {
    Addr addr;
    IAm iam;
};

class Client {
public:
    struct Options {
        uint16_t port = 0;  // 0 = ephemeral
        int apdu_timeout_ms = 3000;
        int retries = 3;
        std::string pcap;
    };
    using CovHandler = std::function<void(const Addr&, const CovNotification&, bool confirmed)>;

    bool start(const Options& opt);
    void stop() { ep_.stop(); }

    std::vector<Discovered> who_is(const Addr& dst, const WhoIs& range, int wait_ms, bool broadcast);
    Result read_property(const Addr& dst, const ReadPropertyReq& req, ReadPropertyAck* ack);
    Result write_property(const Addr& dst, const WritePropertyReq& req);
    Result read_property_multiple(const Addr& dst, const std::vector<ReadAccessSpec>& specs,
                                  std::vector<RpmResult>* out);
    Result subscribe_cov(const Addr& dst, const SubscribeCovReq& req);
    void on_cov(CovHandler h) {
        std::lock_guard<std::mutex> lk(mu_);
        cov_ = std::move(h);
    }
    Endpoint& endpoint() { return ep_; }

private:
    void handle(const Incoming& in);
    Endpoint ep_;
    std::mutex mu_;
    std::vector<Discovered> iams_;
    CovHandler cov_;
};

}  // namespace bac
