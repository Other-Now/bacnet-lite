#include "net.hpp"

#include <chrono>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
// mstcpip.h (SIO_UDP_CONNRESET) depends on winsock2.h being included first
#include <mstcpip.h>
#include <ws2tcpip.h>
#ifndef SIO_UDP_CONNRESET  // not exposed by every SDK configuration
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#pragma comment(lib, "ws2_32.lib")
#define SOCK(x) ((SOCKET)(x))
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#define SOCK(x) (x)
#endif

namespace bac {

bool net_init() {
#if defined(_WIN32)
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}

// AF_INET only: B/IP addresses are IPv4 by definition (BACnet/IPv6 is Annex U, not built).
bool UdpSocket::open(uint16_t port) {
    close();
    auto fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#if defined(_WIN32)
    if (fd == INVALID_SOCKET) return false;
    // Without this, an ICMP port-unreachable for an earlier sendto (e.g. a COV
    // notification to a subscriber that has exited) makes the NEXT recvfrom on
    // this socket fail with WSAECONNRESET -- on a datagram socket.
#if !defined(BL_KEEP_CONNRESET)  // experiment switch: see docs/NOTES.md
    BOOL off = FALSE;
    DWORD ret = 0;
    WSAIoctl(fd, SIO_UDP_CONNRESET, &off, sizeof off, nullptr, 0, &ret, nullptr, nullptr);
#endif
#else
    if (fd < 0) return false;
#endif
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&one), sizeof one);
    int rcvbuf = 1 << 20;  // COV fan-out and benchmarks burst hundreds of datagrams
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof rcvbuf);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
#if defined(_WIN32)
        closesocket(fd);
#else
        ::close(fd);
#endif
        return false;
    }
    socklen_t len = sizeof sa;
    getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    port_ = ntohs(sa.sin_port);
#if defined(_WIN32)
    fd_ = uintptr_t(fd);
#else
    fd_ = fd;
#endif
    return true;
}

void UdpSocket::close() {
#if defined(_WIN32)
    if (fd_ != ~uintptr_t(0)) closesocket(SOCK(fd_));
    fd_ = ~uintptr_t(0);
#else
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
#endif
}

bool UdpSocket::send_to(const Addr& dst, const uint8_t* p, size_t n) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(dst.ip);
    sa.sin_port = htons(dst.port);
    auto sent = sendto(SOCK(fd_), reinterpret_cast<const char*>(p), int(n), 0, reinterpret_cast<sockaddr*>(&sa),
                       sizeof sa);
    return sent == int(n);
}

int UdpSocket::recv_from(uint8_t* buf, size_t cap, Addr& src, int timeout_ms) {
#if defined(_WIN32)
    WSAPOLLFD pfd{SOCK(fd_), POLLRDNORM, 0};
    int rc = WSAPoll(&pfd, 1, timeout_ms);
#else
    pollfd pfd{fd_, POLLIN, 0};
    int rc = poll(&pfd, 1, timeout_ms);
#endif
    if (rc == 0) return 0;
    if (rc < 0) return -1;
    sockaddr_in sa{};
    socklen_t len = sizeof sa;
    auto got = recvfrom(SOCK(fd_), reinterpret_cast<char*>(buf), int(cap), 0, reinterpret_cast<sockaddr*>(&sa), &len);
    if (got < 0) return -1;
    src.ip = ntohl(sa.sin_addr.s_addr);
    src.port = ntohs(sa.sin_port);
    return int(got);
}

// ------------------------------------------------------------------ pcap

PcapWriter::~PcapWriter() {
    if (f_) std::fclose(f_);
}

static void put32le(std::FILE* f, uint32_t v) {
    uint8_t b[4] = {uint8_t(v), uint8_t(v >> 8), uint8_t(v >> 16), uint8_t(v >> 24)};
    std::fwrite(b, 1, 4, f);
}

bool PcapWriter::open(const std::string& path) {
    f_ = std::fopen(path.c_str(), "wb");
    if (!f_) return false;
    put32le(f_, 0xA1B2C3D4);                 // magic, microsecond timestamps
    put32le(f_, 2 | (4u << 16));             // version 2.4
    put32le(f_, 0);                          // thiszone
    put32le(f_, 0);                          // sigfigs
    put32le(f_, 65535);                      // snaplen
    put32le(f_, 101);                        // LINKTYPE_RAW: packets start at the IPv4 header
    std::fflush(f_);
    return true;
}

void PcapWriter::write(const Addr& src, const Addr& dst, const uint8_t* p, size_t n) {
    if (!f_) return;
    uint8_t hdr[28] = {};
    size_t total = 28 + n;
    hdr[0] = 0x45;  // IPv4, IHL 5
    hdr[2] = uint8_t(total >> 8);
    hdr[3] = uint8_t(total);
    hdr[8] = 64;   // TTL
    hdr[9] = 17;   // UDP
    for (int i = 0; i < 4; ++i) {
        hdr[12 + i] = uint8_t(src.ip >> (24 - 8 * i));
        hdr[16 + i] = uint8_t(dst.ip >> (24 - 8 * i));
    }
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) sum += uint32_t(hdr[i] << 8 | hdr[i + 1]);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t csum = uint16_t(~sum);
    hdr[10] = uint8_t(csum >> 8);
    hdr[11] = uint8_t(csum);
    size_t ulen = 8 + n;
    hdr[20] = uint8_t(src.port >> 8);
    hdr[21] = uint8_t(src.port);
    hdr[22] = uint8_t(dst.port >> 8);
    hdr[23] = uint8_t(dst.port);
    hdr[24] = uint8_t(ulen >> 8);
    hdr[25] = uint8_t(ulen);  // UDP checksum 0 = not computed (legal for IPv4)

    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    std::lock_guard<std::mutex> lk(mu_);
    put32le(f_, uint32_t(us / 1000000));
    put32le(f_, uint32_t(us % 1000000));
    put32le(f_, uint32_t(total));
    put32le(f_, uint32_t(total));
    std::fwrite(hdr, 1, sizeof hdr, f_);
    std::fwrite(p, 1, n, f_);
    std::fflush(f_);
}

}  // namespace bac
