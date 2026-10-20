// BACnet/IP device server: dispatches Who-Is, ReadProperty, ReadPropertyMultiple,
// WriteProperty and SubscribeCOV against an ObjectDb, and sends COV notifications.
#pragma once
#include "objects.hpp"
#include "stack.hpp"

namespace bac {

struct DeviceConfig {
    uint32_t instance = 1234;
    std::string name = "bacnet-lite";
    Endpoint::Options net;
    bool simulate = true;
    size_t max_subscriptions = 4096;
};

class Device {
public:
    explicit Device(DeviceConfig cfg);
    ~Device();
    bool start();
    void stop();
    // Offline: no socket; every outgoing frame is passed to sink (fuzzer / --replay).
    void start_offline(std::function<void(const Addr&, const Bytes&)> sink);
    void handle(const Incoming& in);
    void process_datagram(const Addr& src, const uint8_t* p, size_t n) { ep_.process_datagram(src, p, n); }

    ObjectDb& db() { return db_; }
    Endpoint& endpoint() { return ep_; }
    size_t subscription_count() const;
    std::atomic<uint64_t> requests{0}, cov_sent{0};

private:
    struct Subscription {
        Addr addr;
        std::optional<NetAddr> route;
        uint32_t process_id;
        ObjectId oid;
        bool confirmed;
        bool indefinite;
        Clock::time_point expires;
        CovState last;
    };

    void reply(const Incoming& in, const Bytes& apdu);
    void reject(const Incoming& in, uint8_t reason);
    void handle_whois(const Incoming& in, Reader& r);
    void handle_read_property(const Incoming& in, Reader& r);
    void handle_rpm(const Incoming& in, Reader& r);
    void handle_write_property(const Incoming& in, Reader& r);
    void handle_subscribe_cov(const Incoming& in, Reader& r);
    void send_notification(Subscription& s, const CovState& st);
    void check_cov(ObjectId oid);
    void on_tick();
    void build_objects();

    DeviceConfig cfg_;
    ObjectDb db_;
    Endpoint ep_;
    mutable std::mutex sub_mu_;
    std::vector<Subscription> subs_;
    Clock::time_point last_sim_ = Clock::now();
    double sim_t_ = 0;
};

}  // namespace bac
