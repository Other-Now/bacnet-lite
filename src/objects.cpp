#include "objects.hpp"

#include <cmath>

namespace bac {

namespace {

const BacError kUnknownObject = {kErrClassObject, kErrUnknownObject};
const BacError kUnknownProperty = {kErrClassProperty, kErrUnknownProperty};
const BacError kNotAnArray = {kErrClassProperty, kErrPropertyIsNotAnArray};
const BacError kBadIndex = {kErrClassProperty, kErrInvalidArrayIndex};
const BacError kWriteDenied = {kErrClassProperty, kErrWriteAccessDenied};
const BacError kBadType = {kErrClassProperty, kErrInvalidDataType};
const BacError kOutOfRange = {kErrClassProperty, kErrValueOutOfRange};

// Arrays: no index = whole array, [0] = length, [1..n] = one element.
template <class F>
std::optional<BacError> encode_array(size_t n, const std::optional<uint32_t>& idx, Writer& out, F elem) {
    if (!idx) {
        for (size_t i = 0; i < n; ++i) elem(i);
        return std::nullopt;
    }
    if (*idx == 0) {
        encode_app(out, uint32_t(n));
        return std::nullopt;
    }
    if (*idx > n) return kBadIndex;
    elem(*idx - 1);
    return std::nullopt;
}

BitString bits(size_t n, std::initializer_list<size_t> set) {
    BitString b;
    b.bits.assign(n, false);
    for (size_t i : set) b.bits[i] = true;
    return b;
}

const std::vector<uint32_t> kDeviceRequired = {
    kPropObjectIdentifier, kPropObjectName, kPropObjectType, kPropSystemStatus, kPropVendorName,
    kPropVendorIdentifier, kPropModelName, kPropFirmwareRevision, kPropAppSoftwareVersion,
    kPropProtocolVersion, kPropProtocolRevision, kPropProtocolServicesSupported,
    kPropProtocolObjectTypesSupported, kPropObjectList, kPropMaxApduLength, kPropSegmentationSupported,
    kPropApduTimeout, kPropNumberOfApduRetries, kPropDeviceAddressBinding, kPropDatabaseRevision,
    kPropPropertyList};
const std::vector<uint32_t> kDeviceOptional = {kPropDescription};

}  // namespace

ObjectDb::ObjectDb(uint32_t device_instance, std::string device_name)
    : device_instance_(device_instance), device_name_(std::move(device_name)) {}

void ObjectDb::add(Object o) {
    std::lock_guard<std::mutex> lk(mu_);
    objects_[o.id] = std::move(o);
    ++database_revision_;
}

ObjectId ObjectDb::resolve(ObjectId oid) const {
    if (oid.type == kDevice && oid.instance == kMaxInstance) return device_id();
    return oid;
}

bool ObjectDb::exists(ObjectId oid) const {
    oid = resolve(oid);
    std::lock_guard<std::mutex> lk(mu_);
    return oid == device_id() || objects_.count(oid);
}

Value ObjectDb::effective_pv(const Object& o) const {
    if (!o.commandable) return o.present_value;
    for (const auto& slot : o.priority_array)
        if (slot) return *slot;
    return o.relinquish_default;
}

BitString ObjectDb::status_flags(const Object& o) const {
    // {in-alarm, fault, overridden, out-of-service}
    return bits(4, o.out_of_service ? std::initializer_list<size_t>{3} : std::initializer_list<size_t>{});
}

std::vector<uint32_t> ObjectDb::properties(ObjectId oid, uint32_t which) const {
    oid = resolve(oid);
    if (oid == device_id()) {
        if (which == kPropRequired) return kDeviceRequired;
        if (which == kPropOptional) return kDeviceOptional;
        auto all = kDeviceRequired;
        all.insert(all.end(), kDeviceOptional.begin(), kDeviceOptional.end());
        return all;
    }
    std::lock_guard<std::mutex> lk(mu_);
    auto it = objects_.find(oid);
    if (it == objects_.end()) return {};
    const Object& o = it->second;
    std::vector<uint32_t> req = {kPropObjectIdentifier, kPropObjectName, kPropObjectType, kPropPresentValue,
                                 kPropStatusFlags, kPropEventState, kPropOutOfService};
    if (o.analog()) req.push_back(kPropUnits);
    if (o.commandable) {
        req.push_back(kPropPriorityArray);
        req.push_back(kPropRelinquishDefault);
    }
    req.push_back(kPropPropertyList);
    std::vector<uint32_t> opt = {kPropDescription};
    if (o.analog()) opt.push_back(kPropCovIncrement);
    if (which == kPropRequired) return req;
    if (which == kPropOptional) return opt;
    req.insert(req.end(), opt.begin(), opt.end());
    return req;
}

std::optional<BacError> ObjectDb::read(ObjectId oid, const PropertyRef& p, Writer& out) const {
    oid = resolve(oid);
    if (oid == device_id()) return read_device(p, out);
    // property-list needs properties(), which locks; compute it before taking the lock
    std::vector<uint32_t> plist;
    if (p.property == kPropPropertyList) plist = properties(oid, kPropAll);
    std::lock_guard<std::mutex> lk(mu_);
    auto it = objects_.find(oid);
    if (it == objects_.end()) return kUnknownObject;
    if (p.property == kPropPropertyList) {
        std::vector<uint32_t> listed;
        for (uint32_t id : plist)
            if (id != kPropObjectIdentifier && id != kPropObjectName && id != kPropObjectType &&
                id != kPropPropertyList)
                listed.push_back(id);
        return encode_array(listed.size(), p.index, out, [&](size_t i) { encode_app(out, Enumerated{listed[i]}); });
    }
    return read_object(it->second, p, out);
}

std::optional<BacError> ObjectDb::read_object(const Object& o, const PropertyRef& p, Writer& out) const {
    if (p.index && p.property != kPropPriorityArray) return kNotAnArray;
    switch (p.property) {
        case kPropObjectIdentifier: encode_app(out, o.id); return std::nullopt;
        case kPropObjectName: encode_app(out, o.name); return std::nullopt;
        case kPropObjectType: encode_app(out, Enumerated{o.id.type}); return std::nullopt;
        case kPropDescription: encode_app(out, o.description); return std::nullopt;
        case kPropPresentValue: encode_app(out, effective_pv(o)); return std::nullopt;
        case kPropStatusFlags: encode_app(out, status_flags(o)); return std::nullopt;
        case kPropEventState: encode_app(out, Enumerated{0}); return std::nullopt;  // normal
        case kPropOutOfService: encode_app(out, o.out_of_service); return std::nullopt;
        case kPropUnits:
            if (!o.analog()) return kUnknownProperty;
            encode_app(out, Enumerated{o.units});
            return std::nullopt;
        case kPropCovIncrement:
            if (!o.analog()) return kUnknownProperty;
            encode_app(out, o.cov_increment);
            return std::nullopt;
        case kPropPriorityArray:
            if (!o.commandable) return kUnknownProperty;
            return encode_array(16, p.index, out, [&](size_t i) {
                const auto& slot = o.priority_array[i];
                encode_app(out, slot ? *slot : Value{Null{}});
            });
        case kPropRelinquishDefault:
            if (!o.commandable) return kUnknownProperty;
            encode_app(out, o.relinquish_default);
            return std::nullopt;
    }
    return kUnknownProperty;
}

std::optional<BacError> ObjectDb::read_device(const PropertyRef& p, Writer& out) const {
    std::lock_guard<std::mutex> lk(mu_);
    bool is_array = p.property == kPropObjectList || p.property == kPropPropertyList;
    if (p.index && !is_array) return kNotAnArray;
    switch (p.property) {
        case kPropObjectIdentifier: encode_app(out, device_id()); return std::nullopt;
        case kPropObjectName: encode_app(out, device_name_); return std::nullopt;
        case kPropObjectType: encode_app(out, Enumerated{kDevice}); return std::nullopt;
        case kPropDescription: encode_app(out, std::string("bacnet-lite simulated device")); return std::nullopt;
        case kPropSystemStatus: encode_app(out, Enumerated{0}); return std::nullopt;  // operational
        case kPropVendorName: encode_app(out, std::string("bacnet-lite")); return std::nullopt;
        case kPropVendorIdentifier: encode_app(out, kVendorId); return std::nullopt;
        case kPropModelName: encode_app(out, std::string("bl-device")); return std::nullopt;
        case kPropFirmwareRevision: encode_app(out, std::string("0.1")); return std::nullopt;
        case kPropAppSoftwareVersion: encode_app(out, std::string("0.1.0")); return std::nullopt;
        case kPropProtocolVersion: encode_app(out, uint32_t(1)); return std::nullopt;
        case kPropProtocolRevision: encode_app(out, uint32_t(14)); return std::nullopt;
        case kPropProtocolServicesSupported:
            encode_app(out, bits(49, {kSvcSubscribeCov, kSvcReadProperty, kSvcReadPropertyMultiple,
                                      kSvcWriteProperty, 34 /* who-Is */}));
            return std::nullopt;
        case kPropProtocolObjectTypesSupported:
            encode_app(out, bits(60, {kAnalogInput, kAnalogOutput, kAnalogValue, kBinaryValue, kDevice}));
            return std::nullopt;
        case kPropObjectList: {
            std::vector<ObjectId> ids = {device_id()};
            for (const auto& kv : objects_) ids.push_back(kv.first);
            return encode_array(ids.size(), p.index, out, [&](size_t i) { encode_app(out, ids[i]); });
        }
        case kPropPropertyList: {
            std::vector<uint32_t> listed;
            for (uint32_t id : kDeviceRequired)
                if (id != kPropObjectIdentifier && id != kPropObjectName && id != kPropObjectType &&
                    id != kPropPropertyList)
                    listed.push_back(id);
            listed.insert(listed.end(), kDeviceOptional.begin(), kDeviceOptional.end());
            return encode_array(listed.size(), p.index, out,
                                [&](size_t i) { encode_app(out, Enumerated{listed[i]}); });
        }
        case kPropMaxApduLength: encode_app(out, uint32_t(1476)); return std::nullopt;
        case kPropSegmentationSupported: encode_app(out, Enumerated{3}); return std::nullopt;  // none
        case kPropApduTimeout: encode_app(out, uint32_t(3000)); return std::nullopt;
        case kPropNumberOfApduRetries: encode_app(out, uint32_t(3)); return std::nullopt;
        case kPropDeviceAddressBinding: return std::nullopt;  // empty list
        case kPropDatabaseRevision: encode_app(out, database_revision_); return std::nullopt;
    }
    return kUnknownProperty;
}

std::optional<BacError> ObjectDb::write(ObjectId oid, const PropertyRef& p, const std::vector<Value>& vals,
                                        uint8_t priority) {
    oid = resolve(oid);
    if (priority < 1 || priority > 16) return kOutOfRange;
    std::lock_guard<std::mutex> lk(mu_);
    if (oid == device_id()) {
        // Every device property we expose is read-only.
        auto required = kDeviceRequired;
        bool known = p.property == kPropDescription;
        for (uint32_t id : required) known |= id == p.property;
        return known ? kWriteDenied : kUnknownProperty;
    }
    auto it = objects_.find(oid);
    Object* obj = it == objects_.end() ? nullptr : &it->second;
#if defined(BL_PLANT_BUG)
    // PLANTED BUG (off by default; -DBL_PLANT_BUG=ON) for the crash-dump exercise in
    // docs/CRASH_ANALYSIS.md: an Out_Of_Service "fast path" that runs before the
    // unknown-object check, so writing it on a nonexistent object dereferences null.
    if (p.property == kPropOutOfService && vals.size() == 1 && vals[0].index() == kTagBoolean) {
        obj->out_of_service = std::get<bool>(vals[0]);
        return std::nullopt;
    }
#endif
    if (!obj) return kUnknownObject;
    Object& o = *obj;
    if (p.index && p.property != kPropPriorityArray) return kNotAnArray;
    if (vals.size() != 1) return kBadType;
    const Value& v = vals[0];
    switch (p.property) {
        case kPropPresentValue:
            return write_pv(o, vals, priority);
        case kPropOutOfService:
            if (v.index() != kTagBoolean) return kBadType;
            o.out_of_service = std::get<bool>(v);
            return std::nullopt;
        case kPropCovIncrement:
            if (!o.analog()) return kUnknownProperty;
            if (v.index() != kTagReal) return kBadType;
            if (!(std::get<float>(v) >= 0)) return kOutOfRange;  // also rejects NaN
            o.cov_increment = std::get<float>(v);
            return std::nullopt;
        case kPropRelinquishDefault:
            if (!o.commandable) return kUnknownProperty;
            if (v.index() != o.relinquish_default.index()) return kBadType;
            o.relinquish_default = v;
            return std::nullopt;
        case kPropObjectIdentifier: case kPropObjectName: case kPropObjectType: case kPropDescription:
        case kPropStatusFlags: case kPropEventState: case kPropPriorityArray: case kPropPropertyList:
        case kPropUnits:
            return kWriteDenied;
    }
    return kUnknownProperty;
}

std::optional<BacError> ObjectDb::write_pv(Object& o, const std::vector<Value>& vals, uint8_t priority) {
    const Value& v = vals[0];
    if (o.commandable) {
        // Writing NULL relinquishes that priority level; the effective value then
        // falls through to the next non-NULL slot, or to Relinquish_Default.
        if (v.index() == kTagNull) {
            o.priority_array[priority - 1].reset();
            return std::nullopt;
        }
    } else if (o.id.type == kAnalogInput && !o.out_of_service) {
        return kWriteDenied;  // an input's value comes from the field unless it is out of service
    }
    if (o.analog()) {
        if (v.index() != kTagReal) return kBadType;
        if (std::isnan(std::get<float>(v))) return kOutOfRange;
    } else {
        if (v.index() != kTagEnumerated) return kBadType;
        if (std::get<Enumerated>(v).v > 1) return kOutOfRange;  // inactive(0) / active(1)
    }
    if (o.commandable)
        o.priority_array[priority - 1] = v;
    else
        o.present_value = v;
    return std::nullopt;
}

std::optional<CovState> ObjectDb::cov_state(ObjectId oid) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = objects_.find(oid);
    if (it == objects_.end()) return std::nullopt;
    const Object& o = it->second;
    return CovState{effective_pv(o), status_flags(o), o.cov_increment, o.analog()};
}

void ObjectDb::simulate(ObjectId oid, float value) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = objects_.find(oid);
    if (it == objects_.end() || it->second.out_of_service || it->second.commandable) return;
    it->second.present_value = value;
}

std::optional<float> ObjectDb::analog_value(ObjectId oid) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = objects_.find(oid);
    if (it == objects_.end() || !it->second.analog()) return std::nullopt;
    Value v = effective_pv(it->second);
    if (v.index() != kTagReal) return std::nullopt;
    return std::get<float>(v);
}

}  // namespace bac
