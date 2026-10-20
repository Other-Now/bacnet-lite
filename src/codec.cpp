#include "codec.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>

namespace bac {

// ------------------------------------------------------------------ encode

void encode_tag(Writer& w, uint8_t tag_number, bool context, uint32_t len_value) {
    uint8_t first = context ? 0x08 : 0x00;
    bool ext_tag = tag_number >= 15;
    first |= uint8_t((ext_tag ? 15 : tag_number) << 4);
    if (len_value <= 4) {
        w.u8(uint8_t(first | len_value));
        if (ext_tag) w.u8(tag_number);
        return;
    }
    w.u8(uint8_t(first | 5));
    if (ext_tag) w.u8(tag_number);
    if (len_value <= 253) {
        w.u8(uint8_t(len_value));
    } else if (len_value <= 0xFFFF) {
        w.u8(254);
        w.u16(uint16_t(len_value));
    } else {
        w.u8(255);
        w.u32(len_value);
    }
}

static void encode_opening_closing(Writer& w, uint8_t tag_number, uint8_t lvt) {
    if (tag_number >= 15) {
        w.u8(uint8_t(0xF8 | lvt));
        w.u8(tag_number);
    } else {
        w.u8(uint8_t((tag_number << 4) | 0x08 | lvt));
    }
}
void encode_opening(Writer& w, uint8_t tag_number) { encode_opening_closing(w, tag_number, 6); }
void encode_closing(Writer& w, uint8_t tag_number) { encode_opening_closing(w, tag_number, 7); }

static uint8_t unsigned_len(uint32_t v) { return v < 0x100 ? 1 : v < 0x10000 ? 2 : v < 0x1000000 ? 3 : 4; }
static void put_unsigned(Writer& w, uint32_t v, uint8_t n) {
    for (int i = n - 1; i >= 0; --i) w.u8(uint8_t(v >> (8 * i)));
}
static uint8_t signed_len(int32_t v) {
    if (v >= -128 && v <= 127) return 1;
    if (v >= -32768 && v <= 32767) return 2;
    if (v >= -8388608 && v <= 8388607) return 3;
    return 4;
}

// Content octets of a primitive, without the tag.
static void encode_content(Writer& w, const Value& v, uint32_t& len_out, bool context) {
    Writer c;
    switch (v.index()) {
        case kTagNull: break;
        case kTagBoolean:
            if (context) c.u8(std::get<bool>(v) ? 1 : 0);
            break;
        case kTagUnsigned: {
            uint32_t x = std::get<uint32_t>(v);
            put_unsigned(c, x, unsigned_len(x));
            break;
        }
        case kTagSigned: {
            int32_t x = std::get<int32_t>(v);
            put_unsigned(c, uint32_t(x), signed_len(x));
            break;
        }
        case kTagReal: {
            float f = std::get<float>(v);
            uint32_t bits;
            std::memcpy(&bits, &f, 4);
            c.u32(bits);
            break;
        }
        case kTagDouble: {
            double d = std::get<double>(v);
            uint64_t bits;
            std::memcpy(&bits, &d, 8);
            c.u32(uint32_t(bits >> 32));
            c.u32(uint32_t(bits));
            break;
        }
        case kTagOctetString: c.raw(std::get<OctetString>(v).data); break;
        case kTagCharString: {
            const auto& s = std::get<std::string>(v);
            c.u8(0);  // character set 0 = ISO 10646 (UTF-8)
            c.raw(reinterpret_cast<const uint8_t*>(s.data()), s.size());
            break;
        }
        case kTagBitString: {
            const auto& b = std::get<BitString>(v).bits;
            size_t nbytes = (b.size() + 7) / 8;
            c.u8(uint8_t(nbytes * 8 - b.size()));  // unused bits in the last octet
            for (size_t i = 0; i < nbytes; ++i) {
                uint8_t o = 0;
                for (size_t j = 0; j < 8; ++j)
                    if (i * 8 + j < b.size() && b[i * 8 + j]) o |= uint8_t(0x80 >> j);
                c.u8(o);
            }
            break;
        }
        case kTagEnumerated: {
            uint32_t x = std::get<Enumerated>(v).v;
            put_unsigned(c, x, unsigned_len(x));
            break;
        }
        case kTagDate: {
            auto d = std::get<Date>(v);
            c.u8(d.year_minus_1900); c.u8(d.month); c.u8(d.day); c.u8(d.weekday);
            break;
        }
        case kTagTime: {
            auto t = std::get<Time>(v);
            c.u8(t.hour); c.u8(t.minute); c.u8(t.second); c.u8(t.hundredths);
            break;
        }
        case kTagObjectId: c.u32(std::get<ObjectId>(v).raw()); break;
    }
    len_out = uint32_t(c.size());
    w.raw(c.buf);
}

void encode_app(Writer& w, const Value& v) {
    if (v.index() == kTagBoolean) {  // application boolean carries its value in the LVT field
        encode_tag(w, kTagBoolean, false, std::get<bool>(v) ? 1 : 0);
        return;
    }
    Writer c;
    uint32_t len = 0;
    encode_content(c, v, len, false);
    encode_tag(w, uint8_t(v.index()), false, len);
    w.raw(c.buf);
}

void encode_ctx_unsigned(Writer& w, uint8_t tag, uint32_t v) {
    encode_tag(w, tag, true, unsigned_len(v));
    put_unsigned(w, v, unsigned_len(v));
}
void encode_ctx_enum(Writer& w, uint8_t tag, uint32_t v) { encode_ctx_unsigned(w, tag, v); }
void encode_ctx_oid(Writer& w, uint8_t tag, ObjectId oid) {
    encode_tag(w, tag, true, 4);
    w.u32(oid.raw());
}
void encode_ctx_bool(Writer& w, uint8_t tag, bool v) {
    encode_tag(w, tag, true, 1);
    w.u8(v ? 1 : 0);
}

// ------------------------------------------------------------------ decode

bool decode_tag(Reader& r, Tag& t) {
    uint8_t b;
    if (!r.u8(b)) return false;
    t = Tag{};
    t.number = uint8_t(b >> 4);
    t.context = (b & 0x08) != 0;
    uint8_t lvt = b & 0x07;
    if (t.number == 15) {
        if (!r.u8(t.number)) return false;
        if (t.number == 255) return false;  // reserved
    }
    if (lvt == 6 || lvt == 7) {
        if (!t.context) return false;  // opening/closing only exist in the context class
        t.opening = lvt == 6;
        t.closing = lvt == 7;
        return true;
    }
    if (lvt < 5) {
        t.len_value = lvt;
        return true;
    }
    uint8_t ext;
    if (!r.u8(ext)) return false;
    if (ext < 254) {
        t.len_value = ext;
    } else if (ext == 254) {
        uint16_t v;
        if (!r.u16(v)) return false;
        t.len_value = v;
    } else {
        uint16_t hi, lo;
        if (!r.u16(hi) || !r.u16(lo)) return false;
        t.len_value = uint32_t(hi) << 16 | lo;
    }
    return true;
}

bool peek_tag(const Reader& r, Tag& t) {
    Reader copy = r;
    return decode_tag(copy, t);
}

static bool get_unsigned(Reader& r, uint32_t len, uint32_t& out) {
    if (len < 1 || len > 4) return false;
    const uint8_t* p;
    if (!r.take(len, p)) return false;
    out = 0;
    for (uint32_t i = 0; i < len; ++i) out = (out << 8) | p[i];
    return true;
}

bool decode_content(Reader& r, uint8_t app_type, uint32_t len, Value& v) {
    if (len > r.left()) return false;
    const uint8_t* p;
    switch (app_type) {
        case kTagNull:
            if (len != 0) return false;
            v = Null{};
            return true;
        case kTagBoolean: {  // context-tagged boolean: one content octet
            if (len != 1 || !r.take(1, p)) return false;
            v = p[0] != 0;
            return true;
        }
        case kTagUnsigned: {
            uint32_t x;
            if (!get_unsigned(r, len, x)) return false;
            v = x;
            return true;
        }
        case kTagSigned: {
            uint32_t x;
            if (!get_unsigned(r, len, x)) return false;
            if (len < 4 && (x & (1u << (8 * len - 1)))) x |= ~0u << (8 * len);  // sign-extend
            v = int32_t(x);
            return true;
        }
        case kTagReal: {
            if (len != 4 || !r.take(4, p)) return false;
            uint32_t bits = uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
            float f;
            std::memcpy(&f, &bits, 4);
            v = f;
            return true;
        }
        case kTagDouble: {
            if (len != 8 || !r.take(8, p)) return false;
            uint64_t bits = 0;
            for (int i = 0; i < 8; ++i) bits = (bits << 8) | p[i];
            double d;
            std::memcpy(&d, &bits, 8);
            v = d;
            return true;
        }
        case kTagOctetString:
            if (!r.take(len, p)) return false;
            v = OctetString{Bytes(p, p + len)};
            return true;
        case kTagCharString: {
            if (len < 1 || !r.take(len, p)) return false;
            if (p[0] != 0) return false;  // only UTF-8 supported
            v = std::string(reinterpret_cast<const char*>(p + 1), len - 1);
            return true;
        }
        case kTagBitString: {
            if (len < 1 || !r.take(len, p)) return false;
            uint8_t unused = p[0];
            if (unused > 7 || (len == 1 && unused != 0)) return false;
            BitString bs;
            size_t nbits = (len - 1) * 8 - unused;
            for (size_t i = 0; i < nbits; ++i) bs.bits.push_back((p[1 + i / 8] & (0x80 >> (i % 8))) != 0);
            v = std::move(bs);
            return true;
        }
        case kTagEnumerated: {
            uint32_t x;
            if (!get_unsigned(r, len, x)) return false;
            v = Enumerated{x};
            return true;
        }
        case kTagDate:
            if (len != 4 || !r.take(4, p)) return false;
            v = Date{p[0], p[1], p[2], p[3]};
            return true;
        case kTagTime:
            if (len != 4 || !r.take(4, p)) return false;
            v = Time{p[0], p[1], p[2], p[3]};
            return true;
        case kTagObjectId: {
            if (len != 4 || !r.take(4, p)) return false;
            v = ObjectId::from_raw(uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]);
            return true;
        }
    }
    return false;  // application tags 13..15 are reserved
}

bool decode_app(Reader& r, Value& v) {
    Tag t;
    if (!decode_tag(r, t) || t.context) return false;
    if (t.number == kTagBoolean) {
        if (t.len_value > 1) return false;
        v = t.len_value == 1;
        return true;
    }
    return decode_content(r, t.number, t.len_value, v);
}

static bool decode_ctx_prim(Reader& r, uint8_t tag, uint8_t app_type, Value& v) {
    Tag t;
    if (!decode_tag(r, t) || !t.context || t.opening || t.closing || t.number != tag) return false;
    return decode_content(r, app_type, t.len_value, v);
}

bool decode_ctx_unsigned(Reader& r, uint8_t tag, uint32_t& out) {
    Value v;
    if (!decode_ctx_prim(r, tag, kTagUnsigned, v)) return false;
    out = std::get<uint32_t>(v);
    return true;
}
bool decode_ctx_enum(Reader& r, uint8_t tag, uint32_t& out) {
    Value v;
    if (!decode_ctx_prim(r, tag, kTagEnumerated, v)) return false;
    out = std::get<Enumerated>(v).v;
    return true;
}
bool decode_ctx_oid(Reader& r, uint8_t tag, ObjectId& out) {
    Value v;
    if (!decode_ctx_prim(r, tag, kTagObjectId, v)) return false;
    out = std::get<ObjectId>(v);
    return true;
}
bool decode_ctx_bool(Reader& r, uint8_t tag, bool& out) {
    Value v;
    if (!decode_ctx_prim(r, tag, kTagBoolean, v)) return false;
    out = std::get<bool>(v);
    return true;
}

bool decode_opening(Reader& r, uint8_t tag) {
    Tag t;
    return decode_tag(r, t) && t.opening && t.number == tag;
}
bool decode_closing(Reader& r, uint8_t tag) {
    Tag t;
    return decode_tag(r, t) && t.closing && t.number == tag;
}
bool next_is_ctx(const Reader& r, uint8_t tag) {
    Tag t;
    return peek_tag(r, t) && t.context && !t.opening && !t.closing && t.number == tag;
}
bool next_is_opening(const Reader& r, uint8_t tag) {
    Tag t;
    return peek_tag(r, t) && t.opening && t.number == tag;
}
bool next_is_closing(const Reader& r, uint8_t tag) {
    Tag t;
    return peek_tag(r, t) && t.closing && t.number == tag;
}

bool skip_element(Reader& r) {
    int depth = 0;
    do {
        Tag t;
        if (!decode_tag(r, t)) return false;
        if (t.opening) {
            ++depth;
        } else if (t.closing) {
            if (--depth < 0) return false;
        } else if (!(t.number == kTagBoolean && !t.context)) {
            const uint8_t* p;
            if (!r.take(t.len_value, p)) return false;
        }
    } while (depth > 0);
    return true;
}

bool decode_value_list(Reader& r, uint8_t tag, std::vector<Value>& out, size_t* skipped) {
    for (;;) {
        Tag t;
        if (!peek_tag(r, t)) return false;
        if (t.closing && t.number == tag) {
            decode_tag(r, t);
            return true;
        }
        if (t.context) {  // constructed / context-tagged member: not modelled, skip it
            if (!skip_element(r)) return false;
            if (skipped) ++*skipped;
            continue;
        }
        Value v;
        if (!decode_app(r, v)) return false;
        out.push_back(std::move(v));
    }
}

// ------------------------------------------------------------------ printing

std::string to_string(const Value& v) {
    char buf[64];
    switch (v.index()) {
        case kTagNull: return "null";
        case kTagBoolean: return std::get<bool>(v) ? "true" : "false";
        case kTagUnsigned: return std::to_string(std::get<uint32_t>(v));
        case kTagSigned: return std::to_string(std::get<int32_t>(v));
        case kTagReal: std::snprintf(buf, sizeof buf, "%g", double(std::get<float>(v))); return buf;
        case kTagDouble: std::snprintf(buf, sizeof buf, "%g", std::get<double>(v)); return buf;
        case kTagOctetString: {
            std::string s = "0x";
            for (uint8_t b : std::get<OctetString>(v).data) {
                std::snprintf(buf, sizeof buf, "%02x", b);
                s += buf;
            }
            return s;
        }
        case kTagCharString: return "\"" + std::get<std::string>(v) + "\"";
        case kTagBitString: {
            std::string s = "{";
            for (bool b : std::get<BitString>(v).bits) s += b ? '1' : '0';
            return s + "}";
        }
        case kTagEnumerated: return "enum:" + std::to_string(std::get<Enumerated>(v).v);
        case kTagDate: {
            auto d = std::get<Date>(v);
            std::snprintf(buf, sizeof buf, "date:%d-%d-%d", 1900 + d.year_minus_1900, d.month, d.day);
            return buf;
        }
        case kTagTime: {
            auto t = std::get<Time>(v);
            std::snprintf(buf, sizeof buf, "time:%02d:%02d:%02d.%02d", t.hour, t.minute, t.second, t.hundredths);
            return buf;
        }
        case kTagObjectId: {
            auto o = std::get<ObjectId>(v);
            std::snprintf(buf, sizeof buf, "(%u,%u)", unsigned(o.type), unsigned(o.instance));
            return buf;
        }
    }
    return "?";
}

}  // namespace bac
