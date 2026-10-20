// libFuzzer target: the decoders a client runs on what a (possibly hostile)
// device sends back -- ReadProperty-ACK, RPM-ACK, COV notifications, I-Am.
#include <cstddef>
#include <cstdint>

#include "../src/protocol.hpp"

using namespace bac;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    Reader r(data + 1, size - 1);
    switch (data[0] & 3) {
        case 0: { ReadPropertyAck a; decode_read_property_ack(r, a); break; }
        case 1: { std::vector<RpmResult> v; decode_rpm_ack(r, v); break; }
        case 2: { CovNotification n; decode_cov_notification(r, n); break; }
        case 3: { IAm i; decode_iam(r, i); break; }
    }
    return 0;
}
