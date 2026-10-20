// libFuzzer target: one UDP datagram into the device's full receive path
// (BVLC -> NPDU -> APDU -> service decoder -> object database -> reply encoder).
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "../src/device.hpp"

using namespace bac;

static Device& device() {
    static Device* d = [] {
        DeviceConfig cfg;
        cfg.simulate = false;
        auto* dev = new Device(cfg);
        dev->start_offline([](const Addr&, const Bytes&) {});
        if (std::getenv("BL_FUZZ_STATS"))  // how much state did the fuzzer leave behind?
            std::atexit([] { std::fprintf(stderr, "subscriptions=%zu\n", device().subscription_count()); });
        return dev;
    }();
    return *d;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    device().process_datagram(Addr{0x7F000001, 47809}, data, size);
    return 0;
}
