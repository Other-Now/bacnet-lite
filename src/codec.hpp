// BACnet tag encoding (ASHRAE 135 clause 20.2): application tags, context tags,
// opening/closing tags, and the 13 primitive application datatypes.
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace bac {

using Bytes = std::vector<uint8_t>;

struct Null {
    bool operator==(const Null&) const { return true; }
};
struct Enumerated {
    uint32_t v = 0;
    bool operator==(const Enumerated& o) const { return v == o.v; }
};
struct OctetString {
    Bytes data;
    bool operator==(const OctetString& o) const { return data == o.data; }
};
struct BitString {
    std::vector<bool> bits;  // bit 0 first, i.e. the MSB of the first data octet
    bool operator==(const BitString& o) const { return bits == o.bits; }
};
struct Date {
    uint8_t year_minus_1900 = 0xFF, month = 0xFF, day = 0xFF, weekday = 0xFF;
    bool operator==(const Date& o) const {
        return year_minus_1900 == o.year_minus_1900 && month == o.month && day == o.day && weekday == o.weekday;
    }
};
struct Time {
    uint8_t hour = 0xFF, minute = 0xFF, second = 0xFF, hundredths = 0xFF;
    bool operator==(const Time& o) const {
        return hour == o.hour && minute == o.minute && second == o.second && hundredths == o.hundredths;
    }
};
struct ObjectId {
    uint16_t type = 0;      // 10 bits
    uint32_t instance = 0;  // 22 bits
    bool operator==(const ObjectId& o) const { return type == o.type && instance == o.instance; }
    bool operator<(const ObjectId& o) const { return type != o.type ? type < o.type : instance < o.instance; }
    uint32_t raw() const { return (uint32_t(type) << 22) | (instance & 0x3FFFFF); }
    static ObjectId from_raw(uint32_t r) { return {uint16_t(r >> 22), r & 0x3FFFFF}; }
};
constexpr uint32_t kMaxInstance = 0x3FFFFF;  // 4194303 is the "wildcard" instance

// The variant index IS the application tag number (0 = Null ... 12 = ObjectIdentifier).
using Value = std::variant<Null, bool, uint32_t, int32_t, float, double, OctetString, std::string, BitString,
                           Enumerated, Date, Time, ObjectId>;

enum AppTag : uint8_t {
    kTagNull = 0, kTagBoolean, kTagUnsigned, kTagSigned, kTagReal, kTagDouble, kTagOctetString,
    kTagCharString, kTagBitString, kTagEnumerated, kTagDate, kTagTime, kTagObjectId
};

// ---------------------------------------------------------------- writer
class Writer {
public:
    Bytes buf;
    void u8(uint8_t v) { buf.push_back(v); }
    void u16(uint16_t v) { u8(uint8_t(v >> 8)); u8(uint8_t(v)); }
    void u32(uint32_t v) { u16(uint16_t(v >> 16)); u16(uint16_t(v)); }
    void raw(const uint8_t* p, size_t n) { buf.insert(buf.end(), p, p + n); }
    void raw(const Bytes& b) { raw(b.data(), b.size()); }
    size_t size() const { return buf.size(); }
};

void encode_tag(Writer& w, uint8_t tag_number, bool context, uint32_t len_value);
void encode_opening(Writer& w, uint8_t tag_number);
void encode_closing(Writer& w, uint8_t tag_number);
void encode_app(Writer& w, const Value& v);
void encode_ctx_unsigned(Writer& w, uint8_t tag, uint32_t v);
void encode_ctx_enum(Writer& w, uint8_t tag, uint32_t v);
void encode_ctx_oid(Writer& w, uint8_t tag, ObjectId oid);
void encode_ctx_bool(Writer& w, uint8_t tag, bool v);

// ---------------------------------------------------------------- reader
// Every accessor is bounds-checked and returns false instead of reading past the end.
class Reader {
public:
    Reader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
    explicit Reader(const Bytes& b) : p_(b.data()), n_(b.size()) {}
    size_t left() const { return n_ - pos_; }
    size_t pos() const { return pos_; }
    bool empty() const { return pos_ >= n_; }
    const uint8_t* cur() const { return p_ + pos_; }
    bool u8(uint8_t& v) {
        if (left() < 1) return false;
        v = p_[pos_++];
        return true;
    }
    bool u16(uint16_t& v) {
        if (left() < 2) return false;
        v = uint16_t(p_[pos_] << 8 | p_[pos_ + 1]);
        pos_ += 2;
        return true;
    }
    bool take(size_t k, const uint8_t*& out) {
        if (left() < k) return false;
        out = p_ + pos_;
        pos_ += k;
        return true;
    }
    void seek(size_t pos) { pos_ = pos; }

private:
    const uint8_t* p_;
    size_t n_;
    size_t pos_ = 0;
};

struct Tag {
    uint8_t number = 0;
    bool context = false;
    bool opening = false;
    bool closing = false;
    uint32_t len_value = 0;  // length of content, or the value itself for application booleans
};

bool decode_tag(Reader& r, Tag& t);
bool peek_tag(const Reader& r, Tag& t);
bool decode_app(Reader& r, Value& v);
// Decode primitive content of a known application type (used for context tags).
bool decode_content(Reader& r, uint8_t app_type, uint32_t len, Value& v);
// Context-tagged primitives: fail if the next tag is not [tag].
bool decode_ctx_unsigned(Reader& r, uint8_t tag, uint32_t& v);
bool decode_ctx_enum(Reader& r, uint8_t tag, uint32_t& v);
bool decode_ctx_oid(Reader& r, uint8_t tag, ObjectId& v);
bool decode_ctx_bool(Reader& r, uint8_t tag, bool& v);
bool decode_opening(Reader& r, uint8_t tag);
bool decode_closing(Reader& r, uint8_t tag);
bool next_is_ctx(const Reader& r, uint8_t tag);  // primitive context tag [tag] next?
bool next_is_opening(const Reader& r, uint8_t tag);
bool next_is_closing(const Reader& r, uint8_t tag);
// Skip one complete element (primitive, or constructed through its matching closing tag).
bool skip_element(Reader& r);
// Decode application-tagged values up to closing tag [tag] (consumed). Constructed
// (context-tagged) content inside is skipped and counted in *skipped.
bool decode_value_list(Reader& r, uint8_t tag, std::vector<Value>& out, size_t* skipped = nullptr);

std::string to_string(const Value& v);

}  // namespace bac
