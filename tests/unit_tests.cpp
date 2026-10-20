// Unit tests: tag codec, the ASHRAE 135 Annex F example encodings, service
// round-trips, the priority array, and the device request handler offline.
#include <cmath>
#include <cstdio>
#include <functional>
#include <string>

#include "../src/client.hpp"
#include "../src/device.hpp"

using namespace bac;

static int g_checks = 0, g_failures = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        ++g_checks;                                                              \
        if (!(cond)) {                                                           \
            ++g_failures;                                                        \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
        }                                                                        \
    } while (0)

struct TestCase {
    const char* name;
    void (*fn)();
};
static std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}
#define TEST(name)                                                     \
    static void name();                                                \
    static bool name##_reg = (registry().push_back({#name, name}), true); \
    static void name()

static Bytes hex(const char* s) {
    Bytes b;
    for (; s[0] && s[1]; s += 2) {
        while (*s == ' ') ++s;
        b.push_back(uint8_t(std::stoul(std::string(s, 2), nullptr, 16)));
    }
    return b;
}

static Bytes enc(const Value& v) {
    Writer w;
    encode_app(w, v);
    return w.buf;
}

static bool roundtrip(const Value& v) {
    Bytes b = enc(v);
    Reader r(b);
    Value out;
    return decode_app(r, out) && r.empty() && out == v;
}

// ------------------------------------------------------------------ codec

TEST(tag_primitives_match_clause_20_examples) {
    CHECK(enc(Null{}) == hex("00"));
    CHECK(enc(false) == hex("10"));
    CHECK(enc(true) == hex("11"));
    CHECK(enc(uint32_t(72)) == hex("2148"));
    CHECK(enc(int32_t(72)) == hex("3148"));
    CHECK(enc(72.0f) == hex("4442900000"));
    CHECK(enc(Enumerated{0}) == hex("9100"));
    CHECK(enc(std::string("This is a BACnet string!")) ==
          hex("751900546869732069732061204241436e657420737472696e6721"));
    CHECK(enc(BitString{{true, false, true, false, true}}) == hex("8203a8"));
    CHECK(enc(ObjectId{kAnalogInput, 15}) == hex("C40000000F"));
    CHECK(enc(Date{91, 1, 24, 4}) == hex("A45B011804"));
    CHECK(enc(Time{17, 35, 45, 17}) == hex("B411232D11"));
}

TEST(signed_uses_minimal_twos_complement) {
    CHECK(enc(int32_t(-1)) == hex("31FF"));
    CHECK(enc(int32_t(127)) == hex("317F"));
    CHECK(enc(int32_t(128)) == hex("320080"));
    CHECK(enc(int32_t(-129)) == hex("32FF7F"));
    CHECK(enc(int32_t(INT32_MIN)) == hex("3480000000"));
    for (int32_t v : {0, -1, 1, 127, 128, -128, -129, 32767, -32768, 8388607, -8388608, INT32_MAX, INT32_MIN})
        CHECK(roundtrip(v));
}

TEST(extended_length_and_tag_number) {
    std::string s300(300, 'x');
    Bytes b = enc(s300);  // 301 content octets -> LVT 5, 254, two-byte length
    CHECK(b[0] == 0x75 && b[1] == 254 && b[2] == 0x01 && b[3] == 0x2D);
    CHECK(roundtrip(s300));
    CHECK(roundtrip(std::string(10, 'y')));  // 11 octets -> LVT 5, one-byte length
    Writer w;
    encode_ctx_unsigned(w, 20, 7);  // context tag number >= 15 uses the extension octet
    CHECK(w.buf == hex("F91407"));
    Reader r(w.buf);
    uint32_t v = 0;
    CHECK(decode_ctx_unsigned(r, 20, v) && v == 7);
    Writer o;
    encode_opening(o, 3);
    encode_closing(o, 3);
    CHECK(o.buf == hex("3E3F"));
}

TEST(roundtrip_all_types) {
    CHECK(roundtrip(Null{}));
    CHECK(roundtrip(true));
    for (uint32_t v : {0u, 255u, 256u, 65535u, 65536u, 0xFFFFFFu, 0x1000000u, 0xFFFFFFFFu}) CHECK(roundtrip(v));
    CHECK(roundtrip(-12.5f));
    CHECK(roundtrip(3.141592653589793));
    CHECK(roundtrip(OctetString{{1, 2, 3}}));
    CHECK(roundtrip(std::string("")));
    CHECK(roundtrip(BitString{{}}));
    CHECK(roundtrip(BitString{std::vector<bool>(49, true)}));
    CHECK(roundtrip(Enumerated{0xFFFFFFFF}));
    CHECK(roundtrip(ObjectId{kDevice, kMaxInstance}));
}

TEST(decoder_rejects_malformed) {
    auto bad = [](const char* h) {
        Bytes b = hex(h);
        Reader r(b);
        Value v;
        return !decode_app(r, v);
    };
    CHECK(bad(""));            // nothing
    CHECK(bad("24"));          // unsigned claims 4 bytes, has 0
    CHECK(bad("4400"));        // real truncated
    CHECK(bad("43000000"));    // real with length 3
    CHECK(bad("2500"));        // extended length octet says 0... then no content: len 0 unsigned
    CHECK(bad("8208FF"));      // 8 unused bits
    CHECK(bad("7101"));        // character set 1 (not UTF-8)
    CHECK(bad("D0"));          // reserved application tag 13
    CHECK(bad("0E"));          // application-class opening tag
    CHECK(bad("12"));          // application boolean with LVT 2
}

TEST(skip_element_handles_nesting) {
    Bytes b = hex("3E 0E 2101 0F 1E 0F 3F 21 05");
    Reader r(b);
    CHECK(skip_element(r));
    Value v;
    CHECK(decode_app(r, v) && v == Value{uint32_t(5)});
    Bytes unbalanced = hex("3E 0E 2101 3F");
    Reader r2(unbalanced);
    CHECK(!skip_element(r2));
}

// ------------------------------------------------------------------ Annex F examples

TEST(annex_f_iam) {
    // F.1.2 I-Am from device 1, max APDU 480, segmented-both, vendor 99
    Bytes apdu = hex("1000C4020000012201E0910021 63");
    Reader r(apdu);
    Apdu a;
    CHECK(decode_apdu(r, a) && a.type == kPduUnconfirmedRequest && a.service == kSvcIAm);
    IAm iam;
    CHECK(decode_iam(r, iam));
    CHECK(iam.device.instance == 1 && iam.max_apdu == 480 && iam.segmentation == 0 && iam.vendor_id == 99);
    Writer w;
    encode_unconfirmed_header(w, kSvcIAm);
    encode_iam(w, iam);
    CHECK(w.buf == apdu);
}

TEST(annex_f_read_property) {
    // F.3.5 ReadProperty(analog-input 5, present-value), invoke id 1, max APDU 206... the
    // example's max-APDU octet is 0x02 (206 octets)
    Bytes apdu = hex("0002010C 0C00000005 1955");
    Reader r(apdu);
    Apdu a;
    CHECK(decode_apdu(r, a) && a.type == kPduConfirmedRequest && a.invoke_id == 1 && a.service == kSvcReadProperty);
    CHECK(max_apdu_from_code(a.max_apdu_code) == 206);
    ReadPropertyReq req;
    CHECK(decode_read_property(r, req));
    CHECK(req.oid == (ObjectId{kAnalogInput, 5}) && req.prop.property == kPropPresentValue && !req.prop.index);
    Writer w;
    encode_confirmed_header(w, 1, kSvcReadProperty, 206);
    encode_read_property(w, req);
    CHECK(w.buf == apdu);
    // ...and its ComplexACK, value 72.3
    Bytes ack = hex("30010C 0C00000005 1955 3E 4442909999 3F");
    Reader ra(ack);
    CHECK(decode_apdu(ra, a) && a.type == kPduComplexAck);
    ReadPropertyAck rpa;
    CHECK(decode_read_property_ack(ra, rpa));
    CHECK(rpa.values.size() == 1 && std::fabs(std::get<float>(rpa.values[0]) - 72.3f) < 1e-4);
}

TEST(annex_f_write_property) {
    // F.3.10 WriteProperty(analog-value 2, present-value, 180.0) -> SimpleACK
    Bytes body = hex("0C00800002 1955 3E 4443340000 3F");
    Reader r(body);
    WritePropertyReq req;
    CHECK(decode_write_property(r, req));
    CHECK(req.oid == (ObjectId{kAnalogValue, 2}) && std::get<float>(req.values[0]) == 180.0f && !req.priority);
    Writer w;
    encode_write_property(w, req);
    CHECK(w.buf == body);
}

TEST(rpm_and_cov_roundtrip) {
    std::vector<ReadAccessSpec> specs = {
        {{kAnalogInput, 16}, {{kPropPresentValue, std::nullopt}, {kPropPriorityArray, 3u}}}};
    Writer w;
    encode_rpm(w, specs);
    // F.3.7: 0C 00000010 1E 0955 0957 1F (first spec, without our array index)
    CHECK(Bytes(w.buf.begin(), w.buf.begin() + 8) == hex("0C000000101E0955"));
    Reader r(w.buf);
    std::vector<ReadAccessSpec> back;
    CHECK(decode_rpm(r, back) && back.size() == 1 && back[0].props.size() == 2 && *back[0].props[1].index == 3);

    CovNotification n{18, {kDevice, 4}, {kAnalogInput, 10}, 0,
                      {{{kPropPresentValue, std::nullopt}, {65.0f}}, {{kPropStatusFlags, std::nullopt}, {BitString{{0, 0, 0, 0}}}}}};
    Writer c;
    encode_cov_notification(c, n);
    // F.1.3 (unconfirmed COV notification body)
    CHECK(c.buf == hex("0912 1C02000004 2C0000000A 3900 4E 0955 2E 4442820000 2F 096F 2E 820400 2F 4F"));
    Reader rc(c.buf);
    CovNotification nb;
    CHECK(decode_cov_notification(rc, nb) && nb.process_id == 18 && nb.values.size() == 2);
}

TEST(bvlc_npdu) {
    Writer n;
    encode_npdu(n, true);
    Bytes frame = encode_bvlc(kBvlcOriginalUnicast, n.buf);
    CHECK(frame == hex("810A0006 0104"));
    Bvlc b;
    CHECK(decode_bvlc(frame.data(), frame.size(), b) && b.npdu_offset == 4);
    CHECK(!decode_bvlc(frame.data(), frame.size() - 1, b));  // length field mismatch
    Bytes fwd = hex("8104000E C0A80102BAC0 0100 1008");  // Forwarded-NPDU of a Who-Is
    CHECK(decode_bvlc(fwd.data(), fwd.size(), b) && b.originator && b.originator->port == 0xBAC0);
    // routed request: SNET 5, SADR 1 byte
    Bytes npdu = hex("0108 0005 01 2A");
    Reader r(npdu);
    Npdu np;
    CHECK(decode_npdu(r, np) && np.source && np.source->net == 5 && np.source->mac == Bytes{0x2A});
    Writer reply;
    encode_npdu(reply, false, np.source);
    CHECK(reply.buf == hex("0120 0005 01 2A FF"));
}

// ------------------------------------------------------------------ objects

TEST(priority_array_and_relinquish) {
    ObjectDb db(1, "t");
    Object av = make_object({kAnalogValue, 1}, "SP", "", 0.0f);
    av.commandable = true;
    av.relinquish_default = 21.0f;
    db.add(av);
    ObjectId id{kAnalogValue, 1};
    PropertyRef pv{kPropPresentValue, std::nullopt};
    auto value = [&] { return *db.analog_value(id); };
    CHECK(value() == 21.0f);                                   // all NULL -> relinquish default
    CHECK(!db.write(id, pv, {23.0f}, 16));
    CHECK(value() == 23.0f);
    CHECK(!db.write(id, pv, {19.0f}, 8));                      // higher priority wins
    CHECK(value() == 19.0f);
    CHECK(!db.write(id, pv, {25.0f}, 10));                     // lower than 8: stored, not effective
    CHECK(value() == 19.0f);
    CHECK(!db.write(id, pv, {Null{}}, 8));                     // relinquish 8 -> falls to 10
    CHECK(value() == 25.0f);
    CHECK(!db.write(id, pv, {Null{}}, 10));
    CHECK(!db.write(id, pv, {Null{}}, 16));
    CHECK(value() == 21.0f);
    auto e = db.write(id, pv, {1.0f}, 17);
    CHECK(e && e->code == kErrValueOutOfRange);
    e = db.write(id, pv, {Enumerated{1}}, 16);
    CHECK(e && e->code == kErrInvalidDataType);
    // priority-array[0] is the size; [8] is NULL again
    Writer w;
    CHECK(!db.read(id, {kPropPriorityArray, 0u}, w) && w.buf == hex("2110"));
    Writer w8;
    CHECK(!db.read(id, {kPropPriorityArray, 8u}, w8) && w8.buf == hex("00"));
    Writer w17;
    e = db.read(id, {kPropPriorityArray, 17u}, w17);
    CHECK(e && e->code == kErrInvalidArrayIndex);
}

TEST(analog_input_writable_only_out_of_service) {
    ObjectDb db(1, "t");
    db.add(make_object({kAnalogInput, 1}, "T", "", 20.0f));
    ObjectId id{kAnalogInput, 1};
    auto e = db.write(id, {kPropPresentValue, std::nullopt}, {30.0f}, 16);
    CHECK(e && e->code == kErrWriteAccessDenied);
    CHECK(!db.write(id, {kPropOutOfService, std::nullopt}, {true}, 16));
    CHECK(!db.write(id, {kPropPresentValue, std::nullopt}, {30.0f}, 16));
    db.simulate(id, 99.0f);  // the "field" cannot overwrite an out-of-service input
    CHECK(*db.analog_value(id) == 30.0f);
    auto st = db.cov_state(id);
    CHECK(st && st->status_flags.bits[3]);  // out-of-service flag
}

TEST(device_object_and_errors) {
    ObjectDb db(77, "dev");
    db.add(make_object({kAnalogInput, 1}, "T", "", 20.0f));
    Writer w;
    CHECK(!db.read({kDevice, kMaxInstance}, {kPropObjectIdentifier, std::nullopt}, w));  // wildcard instance
    CHECK(w.buf == enc(ObjectId{kDevice, 77}));
    Writer n;
    CHECK(!db.read({kDevice, 77}, {kPropObjectList, 0u}, n) && n.buf == hex("2102"));
    Writer x;
    auto e = db.read({kAnalogInput, 9}, {kPropPresentValue, std::nullopt}, x);
    CHECK(e && e->cls == kErrClassObject && e->code == kErrUnknownObject);
    e = db.read({kAnalogInput, 1}, {9999, std::nullopt}, x);
    CHECK(e && e->code == kErrUnknownProperty);
    e = db.read({kAnalogInput, 1}, {kPropPresentValue, 1u}, x);
    CHECK(e && e->code == kErrPropertyIsNotAnArray);
    // Out_Of_Service on a nonexistent object (the crash in docs/CRASH_ANALYSIS.md when BL_PLANT_BUG is on)
    e = db.write({kAnalogInput, 131074}, {kPropOutOfService, std::nullopt}, {false}, 16);
    CHECK(e && e->code == kErrUnknownObject);
    e = db.write({kDevice, 77}, {kPropObjectName, std::nullopt}, {std::string("x")}, 16);
    CHECK(e && e->code == kErrWriteAccessDenied);
}

// ------------------------------------------------------------------ device, offline

struct Harness {
    DeviceConfig cfg;
    std::unique_ptr<Device> dev;
    std::vector<std::pair<Addr, Bytes>> out;
    Harness() {
        cfg.simulate = false;
        dev = std::make_unique<Device>(cfg);
        dev->start_offline([this](const Addr& a, const Bytes& f) { out.emplace_back(a, f); });
    }
    // Send one APDU; return the APDU part of the single reply ({} if none).
    Bytes request(const Bytes& apdu, Addr from = {0x7F000001, 50000}) {
        out.clear();
        Writer n;
        encode_npdu(n, true);
        n.raw(apdu);
        Bytes frame = encode_bvlc(kBvlcOriginalUnicast, n.buf);
        dev->process_datagram(from, frame.data(), frame.size());
        if (out.empty()) return {};
        const Bytes& f = out.back().second;
        return Bytes(f.begin() + 6, f.end());  // BVLC(4) + NPDU(2)
    }
};

TEST(device_read_write_rpm) {
    Harness h;
    Writer rp;
    encode_confirmed_header(rp, 7, kSvcReadProperty);
    encode_read_property(rp, {{kAnalogValue, 1}, {kPropPresentValue, std::nullopt}});
    Bytes ack = h.request(rp.buf);
    CHECK(ack.size() > 3 && ack[0] == 0x30 && ack[1] == 7);
    Reader r(ack.data() + 3, ack.size() - 3);
    ReadPropertyAck rpa;
    CHECK(decode_read_property_ack(r, rpa) && std::get<float>(rpa.values[0]) == 21.0f);

    Writer wp;
    encode_confirmed_header(wp, 8, kSvcWriteProperty);
    encode_write_property(wp, {{kAnalogValue, 1}, {kPropPresentValue, std::nullopt}, {24.5f}, uint8_t(9)});
    CHECK(h.request(wp.buf) == hex("20080F"));  // SimpleACK

    Writer rpm;
    encode_confirmed_header(rpm, 9, kSvcReadPropertyMultiple);
    encode_rpm(rpm, {{{kAnalogValue, 1}, {{kPropAll, std::nullopt}}}, {{kAnalogValue, 42}, {{kPropPresentValue, std::nullopt}}}});
    Bytes rpm_ack = h.request(rpm.buf);
    Reader rr(rpm_ack.data() + 3, rpm_ack.size() - 3);
    std::vector<RpmResult> res;
    CHECK(decode_rpm_ack(rr, res) && res.size() == 2);
    CHECK(res[0].items.size() == h.dev->db().properties({kAnalogValue, 1}, kPropAll).size());
    CHECK(res[1].items.size() == 1 && res[1].items[0].result.index() == 1);  // unknown-object error
    bool saw_pv = false;
    for (auto& it : res[0].items)
        if (it.prop.property == kPropPresentValue) saw_pv = std::get<float>(std::get<0>(it.result)[0]) == 24.5f;
    CHECK(saw_pv);
}

TEST(device_rejects_and_aborts) {
    Harness h;
    CHECK(h.request(hex("0005010C 0C")) == hex("600104"));       // truncated RP -> Reject invalid-tag
    CHECK(h.request(hex("00050211")) == hex("600209"));          // unknown service 17 -> Reject unrecognized
    CHECK(h.request(hex("08050300 010C")) == hex("710304"));  // segmented request -> Abort seg-not-supported
    // RPM ALL on the device with Max-APDU 50: the answer does not fit, no segmentation -> Abort
    Writer rpm;
    encode_confirmed_header(rpm, 4, kSvcReadPropertyMultiple, 50);
    encode_rpm(rpm, {{{kDevice, 1234}, {{kPropAll, std::nullopt}}}});
    CHECK(h.request(rpm.buf) == hex("710404"));
    // Who-Is outside our range: silence; inside: I-Am
    Writer wi;
    encode_unconfirmed_header(wi, kSvcWhoIs);
    encode_whois(wi, {1, 10});
    CHECK(h.request(wi.buf).empty());
    Writer wi2;
    encode_unconfirmed_header(wi2, kSvcWhoIs);
    encode_whois(wi2, {1000, 2000});
    Bytes iam = h.request(wi2.buf);
    CHECK(iam.size() > 2 && iam[0] == 0x10 && iam[1] == kSvcIAm);
}

TEST(device_cov_subscription) {
    Harness h;
    Addr sub{0x7F000001, 50001};
    Writer s;
    encode_confirmed_header(s, 1, kSvcSubscribeCov);
    encode_subscribe_cov(s, {5, {kAnalogValue, 1}, false, 60u});
    h.request(s.buf, sub);
    CHECK(h.out.size() == 2);  // SimpleACK + initial notification
    CHECK(h.dev->subscription_count() == 1);
    // A change smaller than COV_Increment (0.1) is not reported; a larger one is.
    auto write = [&](float v) {
        Writer w;
        encode_confirmed_header(w, 2, kSvcWriteProperty);
        encode_write_property(w, {{kAnalogValue, 1}, {kPropPresentValue, std::nullopt}, {v}, std::nullopt});
        h.request(w.buf);
        return h.out.size();
    };
    CHECK(write(21.05f) == 1);  // ack only
    CHECK(write(21.5f) == 2);   // ack + notification
    const Bytes& f = h.out.back().second;
    CHECK(h.out.back().first == sub);
    Reader r(f.data() + 8, f.size() - 8);  // BVLC 4 + NPDU 2 + unconfirmed header 2
    CovNotification n;
    CHECK(decode_cov_notification(r, n) && n.process_id == 5 && std::get<float>(n.values[0].values[0]) == 21.5f);
    // cancellation: neither confirmed nor lifetime present
    Writer c;
    encode_confirmed_header(c, 3, kSvcSubscribeCov);
    encode_subscribe_cov(c, {5, {kAnalogValue, 1}, std::nullopt, std::nullopt});
    CHECK(h.request(c.buf, sub) == hex("200305"));
    CHECK(h.dev->subscription_count() == 0);
}

// ------------------------------------------------------------------ TSM

TEST(tsm_retries_then_times_out) {
    std::vector<Bytes> sent;
    Tsm tsm([&](const Addr&, const Bytes& a) { sent.push_back(a); }, 20, 2);
    Result got;
    bool done = false;
    tsm.request({1, 2}, kSvcReadProperty, {}, [&](Result r) {
        got = r;
        done = true;
    });
    for (int i = 0; i < 20 && !done; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        tsm.tick();
    }
    CHECK(done && got.kind == Result::kTimeout && got.attempts == 3);
    CHECK(sent.size() == 3 && sent[0] == sent[2]);  // retransmissions are byte-identical
    CHECK(tsm.outstanding() == 0);
}

TEST(tsm_matches_invoke_id_and_peer) {
    Tsm tsm([](const Addr&, const Bytes&) {}, 1000, 0);
    int acks = 0;
    tsm.request({1, 2}, kSvcWriteProperty, {}, [&](Result r) { acks += r.kind == Result::kSimpleAck; });
    Apdu a;
    a.type = kPduSimpleAck;
    a.invoke_id = 0;
    a.service = kSvcWriteProperty;
    CHECK(!tsm.on_response({9, 9}, a, nullptr, 0));  // right id, wrong peer
    a.service = kSvcReadProperty;
    CHECK(!tsm.on_response({1, 2}, a, nullptr, 0));  // right peer, wrong service
    a.service = kSvcWriteProperty;
    CHECK(tsm.on_response({1, 2}, a, nullptr, 0));
    CHECK(acks == 1 && tsm.outstanding() == 0);
    // 256 concurrent transactions is the limit
    for (int i = 0; i < 256; ++i) CHECK(tsm.request({1, 2}, kSvcReadProperty, {}, [](Result) {}));
    CHECK(!tsm.request({1, 2}, kSvcReadProperty, {}, [](Result) {}));
}

int main() {
    for (const auto& t : registry()) {
        int before = g_failures;
        t.fn();
        std::printf("%s %s\n", g_failures == before ? "ok  " : "FAIL", t.name);
    }
    std::printf("\n%zu tests, %d checks, %d failures\n", registry().size(), g_checks, g_failures);
    return g_failures ? 1 : 0;
}
