// Transaction state machine (invoke IDs, APDU timeout, retries) and the
// Endpoint that owns the socket, the receive thread and the worker pool.
#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <thread>

#include "net.hpp"

namespace bac {

using Clock = std::chrono::steady_clock;

struct Result {  // outcome of one confirmed request
    enum Kind { kSimpleAck, kComplexAck, kError, kReject, kAbort, kTimeout } kind = kTimeout;
    Bytes body;       // ComplexACK service-ack bytes
    BacError error;   // kError
    uint8_t reason = 0;  // kReject / kAbort
    int attempts = 0;
    bool ok() const { return kind == kSimpleAck || kind == kComplexAck; }
};
std::string to_string(const Result& r);

class Tsm {
public:
    using SendFn = std::function<void(const Addr&, const Bytes& apdu)>;
    using Callback = std::function<void(Result)>;

    Tsm(SendFn send, int timeout_ms, int retries) : send_(std::move(send)), timeout_ms_(timeout_ms), retries_(retries) {}

    // Sends a confirmed request; cb runs exactly once (from the receive or timer thread).
    // Returns false when all 256 invoke IDs are in flight.
    bool request(const Addr& dst, uint8_t service, const Bytes& body, Callback cb);
    // Blocking convenience wrapper (needs the Endpoint's threads running).
    Result request_sync(const Addr& dst, uint8_t service, const Bytes& body);
    // Feed a response PDU; returns true when it matched an outstanding transaction.
    bool on_response(const Addr& src, const Apdu& a, const uint8_t* body, size_t n);
    void tick();  // retransmit / time out
    size_t outstanding() const;
    uint64_t retransmits() const { return retransmits_; }

private:
    struct Pending {
        Addr dst;
        uint8_t service;
        Bytes apdu;
        Clock::time_point deadline;
        int attempts;
        Callback cb;
    };
    SendFn send_;
    int timeout_ms_, retries_;
    mutable std::mutex mu_;
    std::map<uint8_t, Pending> pending_;
    uint8_t next_id_ = 0;
    std::atomic<uint64_t> retransmits_{0};
};

struct Incoming {
    Addr src;
    Npdu npdu;
    Apdu apdu;
    Bytes frame;   // the whole datagram; apdu.body_offset indexes into it
    bool broadcast = false;
};

class Endpoint {
public:
    using Handler = std::function<void(const Incoming&)>;
    struct Options {
        uint16_t port = kBacnetPort;
        int workers = 2;       // 0 = handle requests on the receive thread
        int apdu_timeout_ms = 3000;
        int retries = 3;
        std::string pcap;
        std::optional<Addr> broadcast;  // where "broadcast" APDUs go
    };

    Endpoint();
    ~Endpoint();
    // Opens the socket and starts the threads. handler receives requests (confirmed + unconfirmed).
    bool start(const Options& opt, Handler handler);
    void stop();
    // Offline mode (fuzzing / --replay): no socket, outgoing frames go to sink.
    void start_offline(Handler handler, std::function<void(const Addr&, const Bytes&)> sink);

    void send_apdu(const Addr& dst, const Bytes& apdu, bool expecting_reply = false,
                   const std::optional<NetAddr>& route = std::nullopt);
    void broadcast_apdu(const Bytes& apdu, const Addr& fallback);  // to Options::broadcast, else unicast
    void send_broadcast(const Addr& bcast, const Bytes& apdu);       // Original-Broadcast-NPDU to bcast
    void process_datagram(const Addr& src, const uint8_t* p, size_t n);  // decode + dispatch

    Tsm& tsm() { return *tsm_; }
    uint16_t port() const { return sock_.local_port(); }
    std::function<void()> on_tick;  // called every ~50 ms from the timer thread
    std::atomic<uint64_t> rx_frames{0}, rx_dropped{0}, rx_errors{0}, tx_frames{0};

private:
    void recv_loop();
    void worker_loop();
    void timer_loop();
    void send_frame(const Addr& dst, const Bytes& frame);

    Options opt_;
    Handler handler_;
    UdpSocket sock_;
    PcapWriter pcap_;
    std::unique_ptr<Tsm> tsm_;
    std::function<void(const Addr&, const Bytes&)> sink_;
    std::atomic<bool> running_{false};
    std::thread rx_thread_, timer_thread_;
    std::vector<std::thread> workers_;
    std::mutex q_mu_;
    std::condition_variable q_cv_;
    std::deque<Incoming> queue_;
};

}  // namespace bac
