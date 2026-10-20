// Shared command-line helpers: object/property names, value formatting, JSON.
#pragma once
#include <cstdlib>
#include <cstring>
#include <string>

#include "../src/protocol.hpp"

namespace cli {

using namespace bac;

struct Name {
    const char* name;
    uint32_t id;
};

inline const Name kObjectTypes[] = {
    {"analog-input", kAnalogInput}, {"analog-output", kAnalogOutput}, {"analog-value", kAnalogValue},
    {"binary-input", kBinaryInput}, {"binary-output", kBinaryOutput}, {"binary-value", kBinaryValue},
    {"device", kDevice}, {"ai", kAnalogInput}, {"ao", kAnalogOutput}, {"av", kAnalogValue},
    {"bi", kBinaryInput}, {"bo", kBinaryOutput}, {"bv", kBinaryValue}, {"dev", kDevice},
};

inline const Name kProperties[] = {
    {"all", kPropAll}, {"required", kPropRequired}, {"optional", kPropOptional},
    {"apdu-timeout", kPropApduTimeout}, {"application-software-version", kPropAppSoftwareVersion},
    {"cov-increment", kPropCovIncrement}, {"description", kPropDescription},
    {"device-address-binding", kPropDeviceAddressBinding}, {"event-state", kPropEventState},
    {"firmware-revision", kPropFirmwareRevision}, {"max-apdu-length-accepted", kPropMaxApduLength},
    {"model-name", kPropModelName}, {"number-of-apdu-retries", kPropNumberOfApduRetries},
    {"object-identifier", kPropObjectIdentifier}, {"object-list", kPropObjectList},
    {"object-name", kPropObjectName}, {"object-type", kPropObjectType}, {"out-of-service", kPropOutOfService},
    {"present-value", kPropPresentValue}, {"priority-array", kPropPriorityArray},
    {"protocol-object-types-supported", kPropProtocolObjectTypesSupported},
    {"protocol-services-supported", kPropProtocolServicesSupported}, {"protocol-version", kPropProtocolVersion},
    {"relinquish-default", kPropRelinquishDefault}, {"segmentation-supported", kPropSegmentationSupported},
    {"status-flags", kPropStatusFlags}, {"system-status", kPropSystemStatus}, {"units", kPropUnits},
    {"vendor-identifier", kPropVendorIdentifier}, {"vendor-name", kPropVendorName},
    {"protocol-revision", kPropProtocolRevision}, {"database-revision", kPropDatabaseRevision},
    {"property-list", kPropPropertyList},
};

template <size_t N>
inline bool lookup(const Name (&table)[N], const std::string& s, uint32_t& out) {
    for (const auto& n : table)
        if (s == n.name) {
            out = n.id;
            return true;
        }
    char* end = nullptr;
    unsigned long v = std::strtoul(s.c_str(), &end, 10);
    if (s.empty() || *end) return false;
    out = uint32_t(v);
    return true;
}

template <size_t N>
inline std::string name_of(const Name (&table)[N], uint32_t id) {
    for (const auto& n : table)
        if (n.id == id) return n.name;
    return std::to_string(id);
}

// "analog-input:1", "ai:1", "0:1"
inline bool parse_oid(const std::string& s, ObjectId& oid) {
    auto colon = s.find(':');
    if (colon == std::string::npos) return false;
    uint32_t type, inst;
    if (!lookup(kObjectTypes, s.substr(0, colon), type) || type > 1023) return false;
    char* end = nullptr;
    unsigned long v = std::strtoul(s.c_str() + colon + 1, &end, 10);
    if (*end || v > kMaxInstance) return false;
    inst = uint32_t(v);
    oid = {uint16_t(type), inst};
    return true;
}

// "present-value", "priority-array[8]"
inline bool parse_prop(const std::string& s, PropertyRef& p) {
    auto br = s.find('[');
    p.index.reset();
    if (br != std::string::npos) {
        if (s.back() != ']') return false;
        p.index = uint32_t(std::strtoul(s.c_str() + br + 1, nullptr, 10));
    }
    return lookup(kProperties, s.substr(0, br), p.property);
}

inline std::string oid_str(ObjectId o) { return name_of(kObjectTypes, o.type) + ":" + std::to_string(o.instance); }
inline std::string prop_str(const PropertyRef& p) {
    std::string s = name_of(kProperties, p.property);
    if (p.index) s += "[" + std::to_string(*p.index) + "]";
    return s;
}

inline std::string json_escape(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') {
            o += '\\';
            o += c;
        } else if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            o += buf;
        } else {
            o += c;
        }
    }
    return o + "\"";
}

inline const char* kTypeNames[] = {"null", "boolean", "unsigned", "signed", "real", "double", "octet-string",
                                   "character-string", "bit-string", "enumerated", "date", "time", "object-id"};

inline std::string value_json(const Value& v) {
    std::string val;
    char buf[64];
    switch (v.index()) {
        case kTagNull: val = "null"; break;
        case kTagBoolean: val = std::get<bool>(v) ? "true" : "false"; break;
        case kTagUnsigned: val = std::to_string(std::get<uint32_t>(v)); break;
        case kTagSigned: val = std::to_string(std::get<int32_t>(v)); break;
        case kTagReal: std::snprintf(buf, sizeof buf, "%.9g", double(std::get<float>(v))); val = buf; break;
        case kTagDouble: std::snprintf(buf, sizeof buf, "%.17g", std::get<double>(v)); val = buf; break;
        case kTagCharString: val = json_escape(std::get<std::string>(v)); break;
        case kTagEnumerated: val = std::to_string(std::get<Enumerated>(v).v); break;
        case kTagObjectId: val = json_escape(oid_str(std::get<ObjectId>(v))); break;
        case kTagBitString: {
            std::string b;
            for (bool x : std::get<BitString>(v).bits) b += x ? '1' : '0';
            val = json_escape(b);
            break;
        }
        default: val = json_escape(to_string(v));
    }
    return std::string("{\"type\":\"") + kTypeNames[v.index()] + "\",\"value\":" + val + "}";
}

inline std::string values_json(const std::vector<Value>& vs) {
    std::string s = "[";
    for (size_t i = 0; i < vs.size(); ++i) s += (i ? "," : "") + value_json(vs[i]);
    return s + "]";
}

inline std::string values_text(const std::vector<Value>& vs) {
    if (vs.size() == 1) return to_string(vs[0]);
    std::string s = "{";
    for (size_t i = 0; i < vs.size(); ++i) {
        s += i ? ", " : "";
        s += vs[i].index() == kTagObjectId ? oid_str(std::get<ObjectId>(vs[i])) : to_string(vs[i]);
    }
    return s + "}";
}

}  // namespace cli
