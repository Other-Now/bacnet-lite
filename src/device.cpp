#include "device.hpp"

#include <algorithm>
#include <cmath>

namespace bac {

Device::Device(DeviceConfig cfg) : cfg_(std::move(cfg)), db_(cfg_.instance, cfg_.name) { build_objects(); }
Device::~Device() { stop(); }

void Device::build_objects() {
    Object zone = make_object({kAnalogInput, 1}, "Zone Temp", "Zone air temperature", 21.5f);
    zone.units = kUnitsDegreesCelsius;
    zone.cov_increment = 0.2f;
    db_.add(zone);

    Object outdoor = make_object({kAnalogInput, 2}, "Outdoor Air Temp", "Outdoor air temperature", 15.0f);
    outdoor.units = kUnitsDegreesCelsius;
    outdoor.cov_increment = 0.5f;
    db_.add(outdoor);

    Object damper = make_object({kAnalogOutput, 1}, "Damper Command", "Supply air damper", 0.0f);
    damper.units = kUnitsPercent;
    damper.cov_increment = 1.0f;
    damper.commandable = true;
    damper.relinquish_default = 0.0f;
    db_.add(damper);

    Object setpoint = make_object({kAnalogValue, 1}, "Zone Setpoint", "Occupied cooling setpoint", 21.0f);
    setpoint.units = kUnitsDegreesCelsius;
    setpoint.cov_increment = 0.1f;
    setpoint.commandable = true;
    setpoint.relinquish_default = 21.0f;
    db_.add(setpoint);

    Object occupied = make_object({kBinaryValue, 1}, "Occupied", "Occupancy mode", Enumerated{0});
    occupied.commandable = true;
    occupied.relinquish_default = Enumerated{0};
    db_.add(occupied);
}

bool Device::start() {
    ep_.on_tick = [this] { on_tick(); };
    return ep_.start(cfg_.net, [this](const Incoming& in) { handle(in); });
}

void Device::start_offline(std::function<void(const Addr&, const Bytes&)> sink) {
    ep_.start_offline([this](const Incoming& in) { handle(in); }, std::move(sink));
}

void Device::stop() { ep_.stop(); }

size_t Device::subscription_count() const {
    std::lock_guard<std::mutex> lk(sub_mu_);
    return subs_.size();
}

// ------------------------------------------------------------------ dispatch

void Device::handle(const Incoming& in) {
    ++requests;
    const Bytes& f = in.frame;
    Reader r(f.data() + in.apdu.body_offset, f.size() - in.apdu.body_offset);
    if (in.apdu.type == kPduUnconfirmedRequest) {
        if (in.apdu.service == kSvcWhoIs) handle_whois(in, r);
        return;  // I-Am, COV notifications etc. from other devices are ignored
    }
    Writer w;
    if (in.apdu.segmented) {  // we cannot reassemble segmented requests
        encode_abort(w, in.apdu.invoke_id, kAbortSegmentationNotSupported, true);
        reply(in, w.buf);
        return;
    }
    switch (in.apdu.service) {
        case kSvcReadProperty: handle_read_property(in, r); break;
        case kSvcReadPropertyMultiple: handle_rpm(in, r); break;
        case kSvcWriteProperty: handle_write_property(in, r); break;
        case kSvcSubscribeCov: handle_subscribe_cov(in, r); break;
        default:
            encode_reject(w, in.apdu.invoke_id, kRejectUnrecognizedService);
            reply(in, w.buf);
    }
}

void Device::reply(const Incoming& in, const Bytes& apdu) {
    // A response that does not fit the requester's Max-APDU would need segmentation,
    // which this device does not support (clause 5.4.5.3).
    size_t limit = std::min<size_t>(1476, max_apdu_from_code(in.apdu.max_apdu_code));
    if (apdu.size() > limit) {
        Writer w;
        encode_abort(w, in.apdu.invoke_id, kAbortSegmentationNotSupported, true);
        ep_.send_apdu(in.src, w.buf, false, in.npdu.source);
        return;
    }
    ep_.send_apdu(in.src, apdu, false, in.npdu.source);
}

void Device::reject(const Incoming& in, uint8_t reason) {
    Writer w;
    encode_reject(w, in.apdu.invoke_id, reason);
    reply(in, w.buf);
}

void Device::handle_whois(const Incoming& in, Reader& r) {
    WhoIs s;
    if (!decode_whois(r, s)) return;
    if (s.low && (cfg_.instance < *s.low || cfg_.instance > *s.high)) return;
    Writer w;
    encode_unconfirmed_header(w, kSvcIAm);
    encode_iam(w, IAm{db_.device_id()});
    ep_.broadcast_apdu(w.buf, in.src);
}

void Device::handle_read_property(const Incoming& in, Reader& r) {
    ReadPropertyReq req;
    if (!decode_read_property(r, req)) return reject(in, kRejectInvalidTag);
    Writer value;
    auto e = db_.read(req.oid, req.prop, value);
    Writer w;
    if (e) {
        encode_error(w, in.apdu.invoke_id, kSvcReadProperty, e->cls, e->code);
    } else {
        if (req.oid.type == kDevice && req.oid.instance == kMaxInstance) req.oid = db_.device_id();
        encode_complex_ack_header(w, in.apdu.invoke_id, kSvcReadProperty);
        encode_read_property(w, req);
        encode_opening(w, 3);
        w.raw(value.buf);
        encode_closing(w, 3);
    }
    reply(in, w.buf);
}

void Device::handle_rpm(const Incoming& in, Reader& r) {
    std::vector<ReadAccessSpec> specs;
    if (!decode_rpm(r, specs)) return reject(in, kRejectInvalidTag);
    Writer w;
    encode_complex_ack_header(w, in.apdu.invoke_id, kSvcReadPropertyMultiple);
    for (auto& spec : specs) {
        if (spec.oid.type == kDevice && spec.oid.instance == kMaxInstance) spec.oid = db_.device_id();
        encode_ctx_oid(w, 0, spec.oid);
        encode_opening(w, 1);
        bool exists = db_.exists(spec.oid);
        for (const auto& ref : spec.props) {
            std::vector<PropertyRef> expanded;
            bool special = ref.property == kPropAll || ref.property == kPropRequired || ref.property == kPropOptional;
            if (special && exists) {
                for (uint32_t id : db_.properties(spec.oid, ref.property)) expanded.push_back({id, std::nullopt});
            } else {
                expanded.push_back(ref);
            }
            for (const auto& p : expanded) {
                encode_ctx_enum(w, 2, p.property);
                if (p.index) encode_ctx_unsigned(w, 3, *p.index);
                Writer value;
                std::optional<BacError> e;
                if (!exists)
                    e = BacError{kErrClassObject, kErrUnknownObject};
                else
                    e = db_.read(spec.oid, p, value);
                if (e) {
                    encode_opening(w, 5);
                    encode_app(w, Enumerated{e->cls});
                    encode_app(w, Enumerated{e->code});
                    encode_closing(w, 5);
                } else {
                    encode_opening(w, 4);
                    w.raw(value.buf);
                    encode_closing(w, 4);
                }
            }
        }
        encode_closing(w, 1);
    }
    reply(in, w.buf);
}

void Device::handle_write_property(const Incoming& in, Reader& r) {
    WritePropertyReq req;
    if (!decode_write_property(r, req)) return reject(in, kRejectInvalidTag);
    auto e = db_.write(req.oid, req.prop, req.values, req.priority.value_or(16));
    Writer w;
    if (e)
        encode_error(w, in.apdu.invoke_id, kSvcWriteProperty, e->cls, e->code);
    else
        encode_simple_ack(w, in.apdu.invoke_id, kSvcWriteProperty);
    reply(in, w.buf);
    if (!e) check_cov(req.oid);
}

void Device::handle_subscribe_cov(const Incoming& in, Reader& r) {
    SubscribeCovReq req;
    if (!decode_subscribe_cov(r, req)) return reject(in, kRejectInvalidTag);
    Writer w;
    auto error = [&](uint32_t cls, uint32_t code) {
        encode_error(w, in.apdu.invoke_id, kSvcSubscribeCov, cls, code);
        reply(in, w.buf);
    };
    bool cancel = !req.confirmed && !req.lifetime;
    if (!cancel && !req.confirmed) return reject(in, kRejectMissingRequiredParameter);
    if (!db_.exists(req.oid)) return error(kErrClassObject, kErrUnknownObject);
    auto st = db_.cov_state(req.oid);
    if (!st) return error(kErrClassServices, kErrCovSubscriptionFailed);  // e.g. the Device object

    std::lock_guard<std::mutex> lk(sub_mu_);
    auto it = std::find_if(subs_.begin(), subs_.end(), [&](const Subscription& s) {
        return s.addr == in.src && s.process_id == req.process_id && s.oid == req.oid;
    });
    if (cancel) {
        if (it != subs_.end()) subs_.erase(it);
        encode_simple_ack(w, in.apdu.invoke_id, kSvcSubscribeCov);
        reply(in, w.buf);
        return;
    }
    if (it == subs_.end()) {
        if (subs_.size() >= cfg_.max_subscriptions) return error(kErrClassResources, kErrCovSubscriptionFailed);
        subs_.push_back(Subscription{in.src, in.npdu.source, req.process_id, req.oid, false, false, {}, *st});
        it = subs_.end() - 1;
    }
    uint32_t lifetime = req.lifetime.value_or(0);
    it->confirmed = *req.confirmed;
    it->indefinite = lifetime == 0;
    it->expires = Clock::now() + std::chrono::seconds(lifetime);
    it->last = *st;
    encode_simple_ack(w, in.apdu.invoke_id, kSvcSubscribeCov);
    reply(in, w.buf);
    send_notification(*it, *st);  // the initial notification follows a successful subscription
}

// ------------------------------------------------------------------ COV

void Device::send_notification(Subscription& s, const CovState& st) {
    CovNotification n;
    n.process_id = s.process_id;
    n.device = db_.device_id();
    n.oid = s.oid;
    if (!s.indefinite) {
        auto left = std::chrono::duration_cast<std::chrono::seconds>(s.expires - Clock::now()).count();
        n.time_remaining = uint32_t(std::max<long long>(left, 0));
    }
    n.values.push_back({{kPropPresentValue, std::nullopt}, {st.present_value}});
    n.values.push_back({{kPropStatusFlags, std::nullopt}, {st.status_flags}});
    Writer body;
    encode_cov_notification(body, n);
    ++cov_sent;
    if (s.confirmed) {
        ep_.tsm().request(s.addr, kSvcConfirmedCovNotification, body.buf, [](Result) {});
        return;
    }
    Writer w;
    encode_unconfirmed_header(w, kSvcUnconfirmedCovNotification);
    w.raw(body.buf);
    ep_.send_apdu(s.addr, w.buf, false, s.route);
}

static bool cov_changed(const CovState& old, const CovState& now) {
    if (!(old.status_flags == now.status_flags)) return true;
    if (now.analog && old.present_value.index() == kTagReal && now.present_value.index() == kTagReal)
        return std::fabs(std::get<float>(now.present_value) - std::get<float>(old.present_value)) >=
               now.cov_increment;
    return !(old.present_value == now.present_value);
}

void Device::check_cov(ObjectId oid) {
    auto st = db_.cov_state(oid);
    if (!st) return;
    std::lock_guard<std::mutex> lk(sub_mu_);
    for (auto& s : subs_) {
        if (!(s.oid == oid) || !cov_changed(s.last, *st)) continue;
        s.last = *st;
        send_notification(s, *st);
    }
}

void Device::on_tick() {
    auto now = Clock::now();
    {
        std::lock_guard<std::mutex> lk(sub_mu_);
        subs_.erase(std::remove_if(subs_.begin(), subs_.end(),
                                   [&](const Subscription& s) { return !s.indefinite && now >= s.expires; }),
                    subs_.end());
    }
    if (!cfg_.simulate || now - last_sim_ < std::chrono::seconds(1)) return;
    last_sim_ = now;
    sim_t_ += 1.0;
    // A one-zone thermal toy: the zone drifts toward the setpoint, the outdoor air
    // pulls it, and an open damper cools it.
    float outdoor = float(15.0 + 8.0 * std::sin(sim_t_ / 120.0));
    float zone = db_.analog_value({kAnalogInput, 1}).value_or(21.5f);
    float sp = db_.analog_value({kAnalogValue, 1}).value_or(21.0f);
    float damper = db_.analog_value({kAnalogOutput, 1}).value_or(0.0f);
    zone += 0.05f * (sp - zone) + 0.01f * (outdoor - zone) - 0.002f * damper;
    db_.simulate({kAnalogInput, 2}, outdoor);
    db_.simulate({kAnalogInput, 1}, zone);
    check_cov({kAnalogInput, 1});
    check_cov({kAnalogInput, 2});
}

}  // namespace bac
