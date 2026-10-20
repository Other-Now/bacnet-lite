// BACnet/IP link layer (BVLC, Annex J), network layer (NPDU, clause 6) and
// application layer (APDU headers + the services this stack implements).
#pragma once
#include <optional>
#include <variant>

#include "codec.hpp"
#include "enums.hpp"

namespace bac {

// A B/IP address: IPv4 (host byte order) + UDP port.
struct Addr {
    uint32_t ip = 0;
    uint16_t port = 0;
    bool operator==(const Addr& o) const { return ip == o.ip && port == o.port; }
    bool operator<(const Addr& o) const { return ip != o.ip ? ip < o.ip : port < o.port; }
};
std::string to_string(const Addr& a);
bool parse_addr(const std::string& s, Addr& out);  // "a.b.c.d[:port]"

// ------------------------------------------------------------------ BVLC
enum BvlcFunction : uint8_t {
    kBvlcResult = 0x00, kBvlcForwardedNpdu = 0x04, kBvlcDistributeBroadcast = 0x09,
    kBvlcOriginalUnicast = 0x0A, kBvlcOriginalBroadcast = 0x0B,
};
struct Bvlc {
    uint8_t function = 0;
    std::optional<Addr> originator;  // Forwarded-NPDU: the real source, not the BBMD
    size_t npdu_offset = 0;
};
bool decode_bvlc(const uint8_t* p, size_t n, Bvlc& out);
// Wrap an NPDU (+APDU) into an Original-Unicast/Broadcast frame.
Bytes encode_bvlc(uint8_t function, const Bytes& npdu_apdu);

// ------------------------------------------------------------------ NPDU
struct NetAddr {  // remote-network routing info (DNET/DADR or SNET/SADR)
    uint16_t net = 0;
    Bytes mac;
};
struct Npdu {
    bool network_message = false;
    bool expecting_reply = false;
    uint8_t priority = 0;
    std::optional<NetAddr> dest, source;
    uint8_t hop_count = 0;
    uint8_t message_type = 0;
};
bool decode_npdu(Reader& r, Npdu& out);
// reply_to: when replying to a routed request, its SNET/SADR becomes our DNET/DADR.
void encode_npdu(Writer& w, bool expecting_reply, const std::optional<NetAddr>& reply_to = std::nullopt);

// ------------------------------------------------------------------ APDU header
struct Apdu {
    uint8_t type = 0;
    bool segmented = false, more_follows = false, seg_response_accepted = false, server = false;
    uint8_t max_segments = 0, max_apdu_code = 0;
    uint8_t invoke_id = 0;
    uint8_t service = 0;  // service choice; reject/abort reason for Reject/Abort
    size_t body_offset = 0;
};
bool decode_apdu(Reader& r, Apdu& out);
uint32_t max_apdu_from_code(uint8_t code);  // 0..5 -> 50..1476
uint8_t max_apdu_to_code(uint32_t len);

void encode_confirmed_header(Writer& w, uint8_t invoke_id, uint8_t service, uint32_t max_apdu = 1476);
void encode_unconfirmed_header(Writer& w, uint8_t service);
void encode_simple_ack(Writer& w, uint8_t invoke_id, uint8_t service);
void encode_complex_ack_header(Writer& w, uint8_t invoke_id, uint8_t service);
void encode_error(Writer& w, uint8_t invoke_id, uint8_t service, uint32_t err_class, uint32_t err_code);
void encode_reject(Writer& w, uint8_t invoke_id, uint8_t reason);
void encode_abort(Writer& w, uint8_t invoke_id, uint8_t reason, bool server);

// ------------------------------------------------------------------ services
struct BacError {
    uint32_t cls = 0, code = 0;
};
std::string to_string(const BacError& e);

struct WhoIs {
    std::optional<uint32_t> low, high;
};
void encode_whois(Writer& w, const WhoIs& s);
bool decode_whois(Reader& r, WhoIs& s);

struct IAm {
    ObjectId device;
    uint32_t max_apdu = 1476;
    uint32_t segmentation = 3;  // no-segmentation
    uint32_t vendor_id = kVendorId;
};
void encode_iam(Writer& w, const IAm& s);
bool decode_iam(Reader& r, IAm& s);

struct PropertyRef {
    uint32_t property = 0;
    std::optional<uint32_t> index;
};

struct ReadPropertyReq {
    ObjectId oid;
    PropertyRef prop;
};
void encode_read_property(Writer& w, const ReadPropertyReq& s);
bool decode_read_property(Reader& r, ReadPropertyReq& s);

struct ReadPropertyAck {
    ObjectId oid;
    PropertyRef prop;
    std::vector<Value> values;
    size_t skipped = 0;  // constructed members we did not model
};
bool decode_read_property_ack(Reader& r, ReadPropertyAck& s);

struct WritePropertyReq {
    ObjectId oid;
    PropertyRef prop;
    std::vector<Value> values;
    std::optional<uint8_t> priority;
};
void encode_write_property(Writer& w, const WritePropertyReq& s);
bool decode_write_property(Reader& r, WritePropertyReq& s);

struct ReadAccessSpec {
    ObjectId oid;
    std::vector<PropertyRef> props;
};
void encode_rpm(Writer& w, const std::vector<ReadAccessSpec>& specs);
bool decode_rpm(Reader& r, std::vector<ReadAccessSpec>& specs);

struct RpmResultItem {
    PropertyRef prop;
    std::variant<std::vector<Value>, BacError> result;
};
struct RpmResult {
    ObjectId oid;
    std::vector<RpmResultItem> items;
};
bool decode_rpm_ack(Reader& r, std::vector<RpmResult>& out);

struct SubscribeCovReq {
    uint32_t process_id = 0;
    ObjectId oid;
    std::optional<bool> confirmed;   // both absent => cancellation
    std::optional<uint32_t> lifetime;  // seconds, 0 = indefinite
};
void encode_subscribe_cov(Writer& w, const SubscribeCovReq& s);
bool decode_subscribe_cov(Reader& r, SubscribeCovReq& s);

struct PropertyValue {
    PropertyRef prop;
    std::vector<Value> values;
};
struct CovNotification {
    uint32_t process_id = 0;
    ObjectId device;
    ObjectId oid;
    uint32_t time_remaining = 0;
    std::vector<PropertyValue> values;
};
void encode_cov_notification(Writer& w, const CovNotification& s);
bool decode_cov_notification(Reader& r, CovNotification& s);

bool decode_error_body(Reader& r, BacError& e);

}  // namespace bac
