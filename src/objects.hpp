// Object database: Device, Analog Input/Output/Value, Binary Value, with the
// 16-level command priority array for commandable objects.
#pragma once
#include <array>
#include <map>
#include <mutex>
#include <optional>

#include "protocol.hpp"

namespace bac {

struct Object {
    ObjectId id;
    std::string name;
    std::string description;
    Value present_value;          // float for analog, Enumerated{0|1} for binary (when not commandable)
    bool out_of_service = false;
    uint32_t units = kUnitsNoUnits;
    float cov_increment = 0.1f;   // analog only
    bool commandable = false;
    std::array<std::optional<Value>, 16> priority_array;  // slot 0 = priority 1 (highest)
    Value relinquish_default;

    bool analog() const { return id.type <= kAnalogValue; }
    bool binary() const { return id.type >= kBinaryInput && id.type <= kBinaryValue; }
};

inline Object make_object(ObjectId id, std::string name, std::string description, Value pv) {
    Object o;
    o.id = id;
    o.name = std::move(name);
    o.description = std::move(description);
    o.present_value = std::move(pv);
    return o;
}

// What a COV subscription compares against (clause 13.1).
struct CovState {
    Value present_value;
    BitString status_flags;
    float cov_increment = 0;
    bool analog = false;
};

class ObjectDb {
public:
    ObjectDb(uint32_t device_instance, std::string device_name);

    void add(Object o);
    ObjectId device_id() const { return {kDevice, device_instance_}; }
    bool exists(ObjectId oid) const;

    // Appends the application-tagged encoding of the property (or one array element).
    std::optional<BacError> read(ObjectId oid, const PropertyRef& p, Writer& out) const;
    std::optional<BacError> write(ObjectId oid, const PropertyRef& p, const std::vector<Value>& vals,
                                  uint8_t priority);
    // Property identifiers for RPM's ALL / REQUIRED / OPTIONAL special properties.
    std::vector<uint32_t> properties(ObjectId oid, uint32_t which) const;

    std::optional<CovState> cov_state(ObjectId oid) const;
    // Simulation hook: changes an input's present value unless it is out of service.
    void simulate(ObjectId oid, float value);
    std::optional<float> analog_value(ObjectId oid) const;

private:
    ObjectId resolve(ObjectId oid) const;  // device:4194303 means "this device"
    Value effective_pv(const Object& o) const;
    BitString status_flags(const Object& o) const;
    std::optional<BacError> read_device(const PropertyRef& p, Writer& out) const;
    std::optional<BacError> read_object(const Object& o, const PropertyRef& p, Writer& out) const;
    std::optional<BacError> write_pv(Object& o, const std::vector<Value>& vals, uint8_t priority);

    uint32_t device_instance_;
    std::string device_name_;
    uint32_t database_revision_ = 1;
    std::map<ObjectId, Object> objects_;
    mutable std::mutex mu_;
};

}  // namespace bac
