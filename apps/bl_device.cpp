// bl-device: a BACnet/IP device simulating a few building points.
//
//   bl-device [--instance N] [--port P] [--name S] [--bcast A.B.C.D[:port]]
//             [--workers N] [--no-sim] [--pcap FILE] [--dump-dir DIR]
//   bl-device --replay FILE...     feed raw datagrams to the request handler offline
#include <atomic>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <thread>

#include "../src/device.hpp"
#include "cli.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
// dbghelp.h needs windows.h first
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

using namespace bac;

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

#if defined(_WIN32)
static char g_dump_dir[MAX_PATH] = ".";

// Unhandled SEH exception (access violation, stack overflow, abort via
// __fastfail is NOT caught here): write a minidump next to the binary or into
// --dump-dir, then let the process die normally.
static LONG WINAPI write_minidump(EXCEPTION_POINTERS* ep) {
    char path[MAX_PATH];
    std::snprintf(path, sizeof path, "%s\\bl-device-%lu.dmp", g_dump_dir, GetCurrentProcessId());
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mei{GetCurrentThreadId(), ep, FALSE};
        auto type = MINIDUMP_TYPE(MiniDumpWithDataSegs | MiniDumpWithThreadInfo | MiniDumpWithIndirectlyReferencedMemory);
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f, type, &mei, nullptr, nullptr);
        CloseHandle(f);
        std::fprintf(stderr, "bl-device: crashed (0x%08lx), minidump written to %s\n",
                     ep->ExceptionRecord->ExceptionCode, path);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static int replay(Device& dev, int argc, char** argv, int first) {
    size_t replies = 0;
    dev.start_offline([&](const Addr&, const Bytes&) { ++replies; });
    for (int i = first; i < argc; ++i) {
        std::ifstream f(argv[i], std::ios::binary);
        if (!f) {
            std::fprintf(stderr, "cannot open %s\n", argv[i]);
            return 2;
        }
        Bytes data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        size_t before = replies;
        dev.process_datagram(Addr{0x7F000001, 47809}, data.data(), data.size());
        std::printf("%s: %zu bytes -> %zu reply frame(s)\n", argv[i], data.size(), replies - before);
    }
    return 0;
}

int main(int argc, char** argv) {
    DeviceConfig cfg;
    cfg.net.port = kBacnetPort;
    int replay_from = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "%s needs a value\n", a.c_str());
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--instance") cfg.instance = uint32_t(std::stoul(next()));
        else if (a == "--port") cfg.net.port = uint16_t(std::stoul(next()));
        else if (a == "--name") cfg.name = next();
        else if (a == "--workers") cfg.net.workers = std::stoi(next());
        else if (a == "--no-sim") cfg.simulate = false;
        else if (a == "--pcap") cfg.net.pcap = next();
        else if (a == "--bcast") {
            Addr b;
            if (!parse_addr(next(), b)) return std::fprintf(stderr, "bad --bcast\n"), 2;
            cfg.net.broadcast = b;
        }
#if defined(_WIN32)
        else if (a == "--dump-dir") std::snprintf(g_dump_dir, sizeof g_dump_dir, "%s", next().c_str());
#else
        else if (a == "--dump-dir") next();  // Linux: the kernel writes core files (ulimit -c)
#endif
        else if (a == "--replay") { replay_from = i + 1; break; }
        else {
            std::fprintf(stderr, "usage: bl-device [--instance N] [--port P] [--name S] [--bcast A] [--workers N]"
                                 " [--no-sim] [--pcap FILE] [--dump-dir DIR] | --replay FILE...\n");
            return 2;
        }
    }
    if (cfg.instance >= kMaxInstance) return std::fprintf(stderr, "instance must be < 4194303\n"), 2;
#if defined(_WIN32)
    SetUnhandledExceptionFilter(write_minidump);
#endif
    Device dev(cfg);
    if (replay_from) return replay(dev, argc, argv, replay_from);

    if (!dev.start()) {
        std::fprintf(stderr, "bl-device: cannot bind UDP port %u\n", cfg.net.port);
        return 1;
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
#if defined(SIGBREAK)
    std::signal(SIGBREAK, on_signal);  // Windows: CTRL_BREAK_EVENT from a parent process
#endif
    std::printf("bl-device ready instance=%u port=%u workers=%d\n", cfg.instance, dev.endpoint().port(),
                cfg.net.workers);
    std::fflush(stdout);
    while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    dev.stop();
    auto& ep = dev.endpoint();
    std::printf("bl-device stopped requests=%llu rx=%llu dropped=%llu rx_errors=%llu tx=%llu cov_sent=%llu\n",
                (unsigned long long)dev.requests.load(), (unsigned long long)ep.rx_frames.load(),
                (unsigned long long)ep.rx_dropped.load(), (unsigned long long)ep.rx_errors.load(),
                (unsigned long long)ep.tx_frames.load(),
                (unsigned long long)dev.cov_sent.load());
    return 0;
}
