#include "protocol.hpp"

#include <cstdio>
#include <cstdlib>

namespace bac {

std::string to_string(const Addr& a) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u:%u", a.ip >> 24, (a.ip >> 16) & 255, (a.ip >> 8) & 255, a.ip & 255,
                  a.port);
    return buf;
}

bool parse_addr(const std::string& s, Addr& out) {
    unsigned a, b, c, d, port = kBacnetPort;
    char tail;
    int n = std::sscanf(s.c_str(), "%u.%u.%u.%u:%u%c", &a, &b, &c, &d, &port, &tail);
    if (n != 4 && n != 5) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255 || port > 65535) return false;
    out.ip = a << 24 | b << 16 | c << 8 | d;
    out.port = uint16_t(port);
    return true;
}

std::string to_string(const BacError& e) {
    return "error(class=" + std::to_string(e.cls) + ", code=" + std::to_string(e.code) + ")";
}

// ------------------------------------------------------------------ BVLC

bool decode_bvlc(const uint8_t* p, size_t n, Bvlc& out) {
    if (n < 4 || p[0] != 0x81) return false;
    size_t len = size_t(p[2]) << 8 | p[3];
    if (len != n) return false;  // length field must cover exactly the datagram
    out = Bvlc{};
    out.function = p[1];
    switch (out.function) {
        case kBvlcOriginalUnicast:
        case kBvlcOriginalBroadcast:
        case kBvlcDistributeBroadcast:
            out.npdu_offset = 4;
            return true;
        case kBvlcForwardedNpdu:
            if (n < 10) return false;
            out.originator = Addr{uint32_t(p[4]) << 24 | uint32_t(p[5]) << 16 | uint32_t(p[6]) << 8 | p[7],
                                  uint16_t(p[8] << 8 | p[9])};
            out.npdu_offset = 10;
            return true;
        default:
            return false;  // BBMD management functions (Result, BDT/FDT ops) are not handled
    }
}

Bytes encode_bvlc(uint8_t function, const Bytes& npdu_apdu) {
    Writer w;
    w.u8(0x81);
    w.u8(function);
    w.u16(uint16_t(4 + npdu_apdu.size()));
    w.raw(npdu_apdu);
    return std::move(w.buf);
}

// ------------------------------------------------------------------ NPDU

static bool decode_netaddr(Reader& r, NetAddr& a, bool allow_empty_mac) {
    uint8_t len;
    if (!r.u16(a.net) || !r.u8(len)) return false;
    if (len == 0 && !allow_empty_mac) return false;
    const uint8_t* p;
    if (!r.take(len, p)) return false;
    a.mac.assign(p, p + len);
    return true;
}

bool decode_npdu(Reader& r, Npdu& out) {
    uint8_t version, ctrl;
    if (!r.u8(version) || version != 1 || !r.u8(ctrl)) return false;
    out = Npdu{};
    out.network_message = ctrl & 0x80;
    out.expecting_reply = ctrl & 0x04;
    out.priority = ctrl & 0x03;
    if (ctrl & 0x20) {  // DNET, DLEN, DADR (DLEN 0 = broadcast on DNET)
        NetAddr d;
        if (!decode_netaddr(r, d, true)) return false;
        out.dest = std::move(d);
    }
    if (ctrl & 0x08) {  // SNET, SLEN, SADR
        NetAddr s;
        if (!decode_netaddr(r, s, false)) return false;
        out.source = std::move(s);
    }
    if (out.dest && !r.u8(out.hop_count)) return false;
    if (out.network_message) {
        if (!r.u8(out.message_type)) return false;
        uint16_t vendor;
        if (out.message_type >= 0x80 && !r.u16(vendor)) return false;
    }
    return true;
}

void encode_npdu(Writer& w, bool expecting_reply, const std::optional<NetAddr>& reply_to) {
    w.u8(1);
    uint8_t ctrl = expecting_reply ? 0x04 : 0x00;
    if (reply_to) ctrl |= 0x20;
    w.u8(ctrl);
    if (reply_to) {
        w.u16(reply_to->net);
        w.u8(uint8_t(reply_to->mac.size()));
        w.raw(reply_to->mac);
        w.u8(255);  // hop count
    }
}

// ------------------------------------------------------------------ APDU

static const uint32_t kMaxApdu[] = {50, 128, 206, 480, 1024, 1476};

uint32_t max_apdu_from_code(uint8_t code) { return code < 6 ? kMaxApdu[code] : 50; }
uint8_t max_apdu_to_code(uint32_t len) {
    for (int i = 5; i >= 0; --i)
        if (len >= kMaxApdu[i]) return uint8_t(i);
    return 0;
}

bool decode_apdu(Reader& r, Apdu& a) {
    uint8_t b0;
    if (!r.u8(b0)) return false;
    a = Apdu{};
    a.type = b0 >> 4;
    uint8_t seq, window;
    switch (a.type) {
        case kPduConfirmedRequest: {
            a.segmented = b0 & 0x08;
            a.more_follows = b0 & 0x04;
            a.seg_response_accepted = b0 & 0x02;
            uint8_t b1;
            if (!r.u8(b1) || !r.u8(a.invoke_id)) return false;
            a.max_segments = (b1 >> 4) & 0x07;
            a.max_apdu_code = b1 & 0x0F;
            if (a.segmented && (!r.u8(seq) || !r.u8(window))) return false;
            if (!r.u8(a.service)) return false;
            break;
        }
        case kPduUnconfirmedRequest:
            if (!r.u8(a.service)) return false;
            break;
        case kPduSimpleAck:
        case kPduError:
        case kPduReject:
            if (!r.u8(a.invoke_id) || !r.u8(a.service)) return false;
            break;
        case kPduComplexAck:
            a.segmented = b0 & 0x08;
            a.more_follows = b0 & 0x04;
            if (!r.u8(a.invoke_id)) return false;
            if (a.segmented && (!r.u8(seq) || !r.u8(window))) return false;
            if (!r.u8(a.service)) return false;
            break;
        case kPduSegmentAck:
            if (!r.u8(a.invoke_id) || !r.u8(seq) || !r.u8(window)) return false;
            break;
        case kPduAbort:
            a.server = b0 & 0x01;
            if (!r.u8(a.invoke_id) || !r.u8(a.service)) return false;
            break;
        default:
            return false;
    }
    a.body_offset = r.pos();
    return true;
}

void encode_confirmed_header(Writer& w, uint8_t invoke_id, uint8_t service, uint32_t max_apdu) {
    w.u8(0x00);  // not segmented, segmented response not accepted
    w.u8(max_apdu_to_code(max_apdu));
    w.u8(invoke_id);
    w.u8(service);
}
void encode_unconfirmed_header(Writer& w, uint8_t service) {
    w.u8(0x10);
    w.u8(service);
}
void encode_simple_ack(Writer& w, uint8_t invoke_id, uint8_t service) {
    w.u8(0x20);
    w.u8(invoke_id);
    w.u8(service);
}
void encode_complex_ack_header(Writer& w, uint8_t invoke_id, uint8_t service) {
    w.u8(0x30);
    w.u8(invoke_id);
    w.u8(service);
}
void encode_error(Writer& w, uint8_t invoke_id, uint8_t service, uint32_t err_class, uint32_t err_code) {
    w.u8(0x50);
    w.u8(invoke_id);
    w.u8(service);
    encode_app(w, Enumerated{err_class});
    encode_app(w, Enumerated{err_code});
}
void encode_reject(Writer& w, uint8_t invoke_id, uint8_t reason) {
    w.u8(0x60);
    w.u8(invoke_id);
    w.u8(reason);
}
void encode_abort(Writer& w, uint8_t invoke_id, uint8_t reason, bool server) {
    w.u8(uint8_t(0x70 | (server ? 1 : 0)));
    w.u8(invoke_id);
    w.u8(reason);
}

// ------------------------------------------------------------------ services

static void encode_prop_ref(Writer& w, const PropertyRef& p, uint8_t prop_tag) {
    encode_ctx_enum(w, prop_tag, p.property);
    if (p.index) encode_ctx_unsigned(w, uint8_t(prop_tag + 1), *p.index);
}
static bool decode_prop_ref(Reader& r, PropertyRef& p, uint8_t prop_tag) {
    if (!decode_ctx_enum(r, prop_tag, p.property)) return false;
    p.index.reset();
    if (next_is_ctx(r, uint8_t(prop_tag + 1))) {
        uint32_t idx;
        if (!decode_ctx_unsigned(r, uint8_t(prop_tag + 1), idx)) return false;
        p.index = idx;
    }
    return true;
}

void encode_whois(Writer& w, const WhoIs& s) {
    if (s.low && s.high) {
        encode_ctx_unsigned(w, 0, *s.low);
        encode_ctx_unsigned(w, 1, *s.high);
    }
}
bool decode_whois(Reader& r, WhoIs& s) {
    s = WhoIs{};
    if (r.empty()) return true;
    uint32_t lo, hi;
    if (!decode_ctx_unsigned(r, 0, lo) || !decode_ctx_unsigned(r, 1, hi)) return false;
    if (lo > kMaxInstance || hi > kMaxInstance) return false;
    s.low = lo;
    s.high = hi;
    return r.empty();
}

void encode_iam(Writer& w, const IAm& s) {
    encode_app(w, s.device);
    encode_app(w, s.max_apdu);
    encode_app(w, Enumerated{s.segmentation});
    encode_app(w, s.vendor_id);
}
bool decode_iam(Reader& r, IAm& s) {
    Value a, b, c, d;
    if (!decode_app(r, a) || !decode_app(r, b) || !decode_app(r, c) || !decode_app(r, d)) return false;
    if (a.index() != kTagObjectId || b.index() != kTagUnsigned || c.index() != kTagEnumerated ||
        d.index() != kTagUnsigned)
        return false;
    s.device = std::get<ObjectId>(a);
    s.max_apdu = std::get<uint32_t>(b);
    s.segmentation = std::get<Enumerated>(c).v;
    s.vendor_id = std::get<uint32_t>(d);
    return s.device.type == kDevice;
}

void encode_read_property(Writer& w, const ReadPropertyReq& s) {
    encode_ctx_oid(w, 0, s.oid);
    encode_prop_ref(w, s.prop, 1);
}
bool decode_read_property(Reader& r, ReadPropertyReq& s) {
    return decode_ctx_oid(r, 0, s.oid) && decode_prop_ref(r, s.prop, 1) && r.empty();
}

bool decode_read_property_ack(Reader& r, ReadPropertyAck& s) {
    if (!decode_ctx_oid(r, 0, s.oid) || !decode_prop_ref(r, s.prop, 1)) return false;
    if (!decode_opening(r, 3)) return false;
    s.values.clear();
    s.skipped = 0;
    return decode_value_list(r, 3, s.values, &s.skipped) && r.empty();
}

void encode_write_property(Writer& w, const WritePropertyReq& s) {
    encode_ctx_oid(w, 0, s.oid);
    encode_prop_ref(w, s.prop, 1);
    encode_opening(w, 3);
    for (const auto& v : s.values) encode_app(w, v);
    encode_closing(w, 3);
    if (s.priority) encode_ctx_unsigned(w, 4, *s.priority);
}
bool decode_write_property(Reader& r, WritePropertyReq& s) {
    if (!decode_ctx_oid(r, 0, s.oid) || !decode_prop_ref(r, s.prop, 1)) return false;
    if (!decode_opening(r, 3)) return false;
    s.values.clear();
    size_t skipped = 0;
    if (!decode_value_list(r, 3, s.values, &skipped) || skipped) return false;
    s.priority.reset();
    if (next_is_ctx(r, 4)) {
        uint32_t prio;
        if (!decode_ctx_unsigned(r, 4, prio) || prio > 255) return false;
        s.priority = uint8_t(prio);
    }
    return r.empty();
}

void encode_rpm(Writer& w, const std::vector<ReadAccessSpec>& specs) {
    for (const auto& spec : specs) {
        encode_ctx_oid(w, 0, spec.oid);
        encode_opening(w, 1);
        for (const auto& p : spec.props) encode_prop_ref(w, p, 0);
        encode_closing(w, 1);
    }
}
bool decode_rpm(Reader& r, std::vector<ReadAccessSpec>& specs) {
    specs.clear();
    while (!r.empty()) {
        ReadAccessSpec spec;
        if (!decode_ctx_oid(r, 0, spec.oid) || !decode_opening(r, 1)) return false;
        while (!next_is_closing(r, 1)) {
            PropertyRef p;
            if (!decode_prop_ref(r, p, 0)) return false;
            spec.props.push_back(p);
        }
        if (!decode_closing(r, 1) || spec.props.empty()) return false;
        specs.push_back(std::move(spec));
    }
    return !specs.empty();
}

bool decode_error_body(Reader& r, BacError& e) {
    Value c, k;
    if (!decode_app(r, c) || !decode_app(r, k)) return false;
    if (c.index() != kTagEnumerated || k.index() != kTagEnumerated) return false;
    e.cls = std::get<Enumerated>(c).v;
    e.code = std::get<Enumerated>(k).v;
    return true;
}

bool decode_rpm_ack(Reader& r, std::vector<RpmResult>& out) {
    out.clear();
    while (!r.empty()) {
        RpmResult res;
        if (!decode_ctx_oid(r, 0, res.oid) || !decode_opening(r, 1)) return false;
        while (!next_is_closing(r, 1)) {
            RpmResultItem item;
            if (!decode_prop_ref(r, item.prop, 2)) return false;
            if (next_is_opening(r, 4)) {
                decode_opening(r, 4);
                std::vector<Value> vals;
                if (!decode_value_list(r, 4, vals)) return false;
                item.result = std::move(vals);
            } else if (next_is_opening(r, 5)) {
                decode_opening(r, 5);
                BacError e;
                if (!decode_error_body(r, e) || !decode_closing(r, 5)) return false;
                item.result = e;
            } else {
                return false;
            }
            res.items.push_back(std::move(item));
        }
        decode_closing(r, 1);
        out.push_back(std::move(res));
    }
    return true;
}

void encode_subscribe_cov(Writer& w, const SubscribeCovReq& s) {
    encode_ctx_unsigned(w, 0, s.process_id);
    encode_ctx_oid(w, 1, s.oid);
    if (s.confirmed) encode_ctx_bool(w, 2, *s.confirmed);
    if (s.lifetime) encode_ctx_unsigned(w, 3, *s.lifetime);
}
bool decode_subscribe_cov(Reader& r, SubscribeCovReq& s) {
    s = SubscribeCovReq{};
    if (!decode_ctx_unsigned(r, 0, s.process_id) || !decode_ctx_oid(r, 1, s.oid)) return false;
    if (next_is_ctx(r, 2)) {
        bool b;
        if (!decode_ctx_bool(r, 2, b)) return false;
        s.confirmed = b;
    }
    if (next_is_ctx(r, 3)) {
        uint32_t l;
        if (!decode_ctx_unsigned(r, 3, l)) return false;
        s.lifetime = l;
    }
    return r.empty();
}

void encode_cov_notification(Writer& w, const CovNotification& s) {
    encode_ctx_unsigned(w, 0, s.process_id);
    encode_ctx_oid(w, 1, s.device);
    encode_ctx_oid(w, 2, s.oid);
    encode_ctx_unsigned(w, 3, s.time_remaining);
    encode_opening(w, 4);
    for (const auto& pv : s.values) {
        encode_prop_ref(w, pv.prop, 0);
        encode_opening(w, 2);
        for (const auto& v : pv.values) encode_app(w, v);
        encode_closing(w, 2);
    }
    encode_closing(w, 4);
}
bool decode_cov_notification(Reader& r, CovNotification& s) {
    s = CovNotification{};
    if (!decode_ctx_unsigned(r, 0, s.process_id) || !decode_ctx_oid(r, 1, s.device) ||
        !decode_ctx_oid(r, 2, s.oid) || !decode_ctx_unsigned(r, 3, s.time_remaining) || !decode_opening(r, 4))
        return false;
    while (!next_is_closing(r, 4)) {
        PropertyValue pv;
        if (!decode_prop_ref(r, pv.prop, 0) || !decode_opening(r, 2)) return false;
        if (!decode_value_list(r, 2, pv.values)) return false;
        if (next_is_ctx(r, 3)) {
            uint32_t prio;
            if (!decode_ctx_unsigned(r, 3, prio)) return false;
        }
        s.values.push_back(std::move(pv));
    }
    return decode_closing(r, 4) && r.empty();
}

}  // namespace bac
