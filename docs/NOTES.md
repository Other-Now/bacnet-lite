# bacnet-lite study sheet

Everything you need to explain this project in an interview, in the order an
interviewer usually walks it: the protocol, the design, the bugs, the numbers.

## 1. BACnet in five minutes

BACnet (ASHRAE 135, ISO 16484-5) is the protocol HVAC, lighting and access
controllers use to talk to each other and to a building-management workstation.
Everything is an **object** (Analog Input, Binary Value, Device, ...) with
**properties** (Present_Value, Status_Flags, Units, ...). Clients read and write
properties and subscribe to changes.

The layers, bottom up, as this repo implements them:

| Layer | Clause | What it is | Where |
|---|---|---|---|
| BVLC | Annex J | 4-byte BACnet/IP header on UDP 47808 (`0xBAC0`): type `0x81`, function (Original-Unicast `0x0A`, Original-Broadcast `0x0B`, Forwarded-NPDU `0x04` + 6-byte originator), length | `protocol.cpp` `decode_bvlc` |
| NPDU | 6 | version 1, control byte (network message? DNET? SNET? expecting reply? priority); optional DNET/DADR, SNET/SADR, hop count | `decode_npdu` |
| APDU | 20.1 | PDU type in the high nibble: Confirmed-Request 0, Unconfirmed 1, SimpleACK 2, ComplexACK 3, SegmentACK 4, Error 5, Reject 6, Abort 7 | `decode_apdu` |
| Service data | 15, 16, 13 | tag-encoded parameters | `encode_*/decode_*` |

**Tag encoding (clause 20.2)** is the part to know cold. One initial octet:
`tag number (4 bits) | class (1 bit: 0 application, 1 context) | LVT (3 bits)`.
- LVT 0–4 = content length; 5 = extended length follows (1 byte; 254 → 2 more bytes; 255 → 4 more).
- Tag number 15 = extended tag number in the next octet.
- Context class with LVT 6/7 = **opening/closing tag** (constructed data, e.g. the value inside ReadProperty-ACK `[3]`).
- Application tags 0–12: Null, Boolean, Unsigned, Signed, Real, Double, Octet String, Character String, Bit String, Enumerated, Date, Time, ObjectIdentifier. An application Boolean carries its value *in the LVT*, with no content octet; a context-tagged Boolean has one content octet. In the code, `Value` is a `std::variant` whose index *is* the application tag number.
- Unsigned/Enumerated are minimal big-endian; Signed is minimal two's complement (`-129` → `32 FF 7F`). An ObjectIdentifier is 10-bit type << 22 | 22-bit instance, and instance 4194303 is the wildcard ("this device").

Worked example from Annex F, a ReadProperty of AI 5's Present_Value:
`00 02 01 0C | 0C 00000005 | 19 55`. Confirmed request, max-APDU code 2 (206 octets), invoke ID 1, service 12; then context [0] with 4 bytes (the object ID), and context [1] with 1 byte (property 85). `tests/unit_tests.cpp` checks this byte for byte, along with the I-Am, WriteProperty and COV-notification examples.

## 2. Services implemented

| Service | Type | Notes |
|---|---|---|
| Who-Is / I-Am | unconfirmed | optional instance range; device answers I-Am to `--bcast` if configured, else directly to the asker |
| ReadProperty | confirmed (12) | arrays: no index = whole array, `[0]` = length, `[n]` = element |
| ReadPropertyMultiple | confirmed (14) | ALL / REQUIRED / OPTIONAL expansion; per-property errors go in `[5]` inside the ACK, not as an Error PDU |
| WriteProperty | confirmed (15) | priority 1–16, NULL relinquishes |
| SubscribeCOV | confirmed (5) | confirmed or unconfirmed notifications, lifetime, cancellation |
| (Un)ConfirmedCOVNotification | 1 / unconf. 2 | sent by the device; the client ACKs confirmed ones |

Not implemented: segmentation (we Abort with `segmentation-not-supported`),
BBMD/foreign-device registration, routing, MS/TP, BACnet/SC, alarms/events,
schedules and trends, and the priority-6 minimum on/off rule.

## 3. The priority array (the BACnet-specific interview topic)

Commandable objects (AO, and AV/BV here) have `Priority_Array[16]` plus
`Relinquish_Default`. Each writer writes at a priority (1 = manual life safety
... 8 = manual operator ... 16 = lowest, the default). **Present_Value = the
highest-priority non-NULL slot, else Relinquish_Default.** Writing NULL at a
priority *relinquishes* that slot. So a fire-alarm override at priority 1 wins
over the scheduler at 16, and when the alarm relinquishes, control falls back
without anyone having to remember the old value. `ObjectDb::write_pv` and the
`priority_array_and_relinquish` test show it. An Analog *Input* rejects writes
(`write-access-denied`) unless Out_Of_Service is true, because its value
belongs to the field sensor.

## 4. COV (change of value)

A subscriber sends SubscribeCOV (process ID, object, confirmed?, lifetime).
The device ACKs, then **immediately sends an initial notification**, then
sends another whenever Present_Value moves by at least COV_Increment (analog)
or changes at all (binary), or Status_Flags change. Subscriptions are keyed by
(subscriber address, process ID, object), so renewing just refreshes the
lifetime. Expiry runs on the 50 ms timer thread. Lifetime 0 means indefinite.

## 5. Design

```
apps/bl-device ─┐                      ┌─ apps/bl-client, bl-bench
                Device (dispatch, COV) Client (who-is, rp, wp, rpm, cov)
                ObjectDb (mutex)          │
                └──────── Endpoint ───────┘
                  recv thread → bounded queue (4096) → N workers
                  timer thread (50 ms): TSM retries, COV expiry, simulation
                  Tsm: invoke IDs 0..255, APDU timeout, retries
                  UdpSocket (Winsock2 / BSD behind one class), PcapWriter
```

- **One socket, unconnected `sendto`/`recvfrom`.** B/IP is many-peer and uses
  broadcast, so nano-dtls's connected-per-peer UDP transport did not fit; I
  kept its two lessons: AF_INET only, and the SOCKET handle stored as `uintptr_t`.
- **TSM**: a transaction is (peer address, invoke ID); a reply from another
  peer with the same ID is ignored (tested). Retransmissions are byte-identical.
  At most 256 in flight; the 257th request is refused, not queued. Known gap:
  an ID can be reused right after a timeout, so a very late reply could match
  the new transaction. Real stacks keep a quarantine period.
- **Overload**: the receive queue is bounded (4096); beyond that, frames are
  dropped and counted (`rx_dropped`) instead of growing memory.
- **Too-large responses**: if the reply exceeds the requester's max-APDU, the
  device sends Abort(segmentation-not-supported). RPM ALL on the Device object
  with max-APDU 50 is the test.
- **Routing**: if a request arrived with SNET/SADR (through a router), the
  reply carries DNET/DADR so the router can deliver it back.

## 6. Cross-platform specifics (Windows vs Linux)

- `WSAStartup`; `closesocket` vs `close`; `WSAPoll` vs `poll`.
- **`SIO_UDP_CONNRESET`**: on Windows, an ICMP port-unreachable from an
  earlier `sendto` makes the *next* `recvfrom` on that UDP socket fail with
  `WSAECONNRESET`. Measured with `tools/connreset_experiment.py`: a subscriber
  exits, then 20 writes make the device send 20 notifications to the dead
  port. With the ioctl the device logs `rx_errors=0`; without it
  (`-DBL_KEEP_CONNRESET=ON`), `rx_errors=20`, one per notification. The device
  survives both because the receive loop never treats an error as fatal; a loop
  that exits or closes the socket on error would go deaf after the first write.
- `mstcpip.h` must come after `winsock2.h`, and some SDK setups don't expose
  `SIO_UDP_CONNRESET` (it's `_WSAIOW(IOC_VENDOR, 12)`).
- Clean shutdown in tests: SIGINT on Linux; on Windows, CTRL_BREAK to a
  process started with `CREATE_NEW_PROCESS_GROUP`, caught as `SIGBREAK`.
- Crash capture: Windows uses `SetUnhandledExceptionFilter` + `MiniDumpWriteDump`;
  Linux uses kernel core files (or `gcore`).

## 7. Interop notes (bacnet-stack 1.6.1 demo tools)

- bacnet-stack binds to an **interface** address, so `127.0.0.1` is
  unreachable from it. Tests use the host's primary IP.
- With `--mac` alone, `bacrp` sets DNET = 0xFFFF and the request never
  reached our device; adding `--dnet 0` fixed it. bacnet-stack sends
  broadcasts to its **own** port unless `BACNET_IP_BROADCAST_PORT` is set
  (`ports/linux/bip-init.c`, `bip_get_broadcast_port`), so on one host with two
  ports, broadcast discovery only works with that variable set. That's tested in
  `test_bacwi_broadcast_discovery`.
- `bacscov` has no `--mac`; it reads a static binding from an `address_cache`
  file in its working directory.

## 8. Things to say about testing

- Unit: Annex F encodings byte for byte, codec edge cases (extended
  length/tag, minimal signed), malformed-input rejection, priority-array
  semantics, and the device handler driven offline (no sockets).
- System (pytest): real UDP between processes, on Linux and Windows.
- Interop (pytest): bacrp/bacwp/bacwi/bacepics/bacscov against us; our client
  against bacserv, including COV.
- Wireshark: every frame of a scripted session decodes with 0 malformed and
  0 expert errors, checked by `tools/check_pcap.pl` (Perl).
- Sanitizers: unit + system suites under ASan+UBSan.
- Fuzzing: libFuzzer on the device's full receive path and on the client's ACK decoders.
