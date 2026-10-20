// Cross-platform UDP socket (Winsock2 / BSD) and a pcap writer for the frames
// we send and receive (lets tshark validate traffic without capture privileges).
#pragma once
#include <cstdio>
#include <mutex>
#include <string>

#include "protocol.hpp"

namespace bac {

bool net_init();  // WSAStartup on Windows; no-op elsewhere

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket() { close(); }
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    // Bind 0.0.0.0:port (0 = ephemeral) with SO_BROADCAST enabled.
    bool open(uint16_t port);
    bool send_to(const Addr& dst, const uint8_t* p, size_t n);
    // >0 bytes received, 0 on timeout, -1 on error.
    int recv_from(uint8_t* buf, size_t cap, Addr& src, int timeout_ms);
    uint16_t local_port() const { return port_; }
    void close();

private:
#if defined(_WIN32)
    uintptr_t fd_ = ~uintptr_t(0);  // SOCKET is pointer-sized on Win64; never squeeze it into an int
#else
    int fd_ = -1;
#endif
    uint16_t port_ = 0;
};

class PcapWriter {
public:
    ~PcapWriter();
    bool open(const std::string& path);
    bool is_open() const { return f_ != nullptr; }
    // Writes the UDP payload wrapped in synthetic IPv4 + UDP headers (LINKTYPE_RAW).
    void write(const Addr& src, const Addr& dst, const uint8_t* p, size_t n);

private:
    std::FILE* f_ = nullptr;
    std::mutex mu_;
};

}  // namespace bac
