# bacnet-lite

A small, cross-platform **BACnet/IP** stack in C++17: a device server that
simulates building points and a client CLI. Both run on **Linux and Windows**,
interoperate with the standard open-source BACnet tools (Steve Karg's
`bacnet-stack`), produce traffic Wireshark decodes cleanly, and are covered by a
pytest system suite, sanitizers, libFuzzer and a WinDbg/GDB crash-dump write-up.

```
$ bl-device --instance 1234 &                                 # Linux or Windows
$ bl-client read 127.0.0.1 device:1234 object-list
device:1234 object-list = {device:1234, analog-input:1, analog-input:2, analog-output:1, analog-value:1, binary-value:1}
$ bl-client write 127.0.0.1 av:1 present-value 23.5 --priority 8
$ bl-client read 127.0.0.1 av:1 priority-array
analog-value:1 priority-array = {null, null, null, null, null, null, null, 23.5, null, null, null, null, null, null, null, null}
$ bacrp 1234 analog-input 1 present-value --mac 172.28.75.153:47808 --dnet 0   # bacnet-stack's tool, against us
21.500000
```

## What's implemented

| Layer | Scope |
|---|---|
| BVLC (Annex J) | Original-Unicast/Broadcast, Forwarded-NPDU (originator address used as source) on UDP 47808 |
| NPDU (clause 6) | local + routed requests (SNET/SADR in → DNET/DADR on the reply); network-layer messages ignored |
| APDU (clause 20) | Confirmed/Unconfirmed request, Simple/Complex ACK, Error, Reject, Abort; invoke IDs; APDU timeout + retries |
| Tags (20.2) | all 13 application types, context tags, opening/closing, extended length and tag numbers |
| Services | Who-Is/I-Am, ReadProperty, ReadPropertyMultiple (ALL/REQUIRED/OPTIONAL), WriteProperty, SubscribeCOV, confirmed + unconfirmed COV notifications |
| Objects | Device, Analog Input/Output/Value, Binary Value; **16-level priority array with relinquish** on AO/AV/BV |
| Threads | receive thread → bounded queue → worker pool; 50 ms timer for TSM retries, COV-subscription expiry and the point simulation |

Not implemented: segmentation (too-large replies get Abort
`segmentation-not-supported`), BBMD/foreign devices, routing, MS/TP, BACnet/SC,
alarms/schedules/trends, and the desktop GUI explorer (stretch goal, not built).

Layout: `src/` stack (`codec`, `protocol`, `net`, `objects`, `stack`, `device`,
`client`), `apps/` (`bl-device`, `bl-client`, `bl-bench`), `tests/` (unit +
pytest), `fuzz/`, `tools/` (Perl tshark checker, dump analysis), `docs/`.
The study sheet is [docs/NOTES.md](docs/NOTES.md).

## Build

```sh
# Linux (GCC or Clang): CMake, or the plain Makefile
cmake -S . -B build -G Ninja && cmake --build build && ./build/unit_tests
make && ./bin/unit_tests
# Windows (MSVC 2022), from a developer prompt
cmake -S . -B build -G "NMake Makefiles" && cmake --build build && build\unit_tests.exe
```

CI (`.github/workflows/ci.yml`) covers Linux GCC + Clang (CMake and Makefile),
ASan/UBSan + libFuzzer, and Windows MSVC.

## Results

All numbers are from this repo's scripts on one laptop (i5-9300H, 4 cores/8 threads).
"Linux" means WSL2 (4 vCPU), "Windows" means native Windows 11, both over loopback.
Raw outputs are in [`results/`](results).

**Correctness and interop**

| Check | Result |
|---|---|
| Unit tests (Annex F example encodings byte-for-byte, codec edge cases, priority array, offline device handler, TSM) | 19 tests / 407 checks, passing on GCC, Clang, MSVC and the Makefile build |
| pytest system suite, real UDP between processes | **23/23 on Linux** (13 device + 10 interop/Wireshark); **13/13 on Windows** (interop needs the Linux tools) |
| Same suite under ASan + UBSan | 23/23, no sanitizer reports |
| bacnet-stack 1.6.1 tools → our device | `bacrp`, `bacwp` (priority write + relinquish), `bacwi` (unicast **and** real broadcast), `bacepics` (full walk), `bacscov` (gets the initial + change notifications) |
| our client → bacnet-stack `bacserv` | reads an 80-entry object-list, RPM, WriteProperty, COV subscription + notification |
| Wireshark 4.2.2 (`tools/check_pcap.pl`, Perl) | scripted session of 33 frames (RP, RPM, WP, Error, Who-Is/I-Am, SubscribeCOV, confirmed and unconfirmed COV): **0 malformed, 0 expert errors** |

**Performance** (`scripts/bench.sh`, `tools/bench_windows.py`; median of 3 runs)

| ReadProperty | Linux | Windows |
|---|---|---|
| 1 outstanding: throughput / p50 / p99 | 6.3k req/s / 115 µs / 218 µs | 9.7k req/s / 84 µs / 144 µs |
| 32 outstanding, 2 workers | 81.9k req/s, p99 0.93 ms | 50.8k req/s, p99 0.31 ms |
| 64 outstanding, 1 / 2 / 4 workers | 39.6k / 84.7k / 87.8k req/s | 48.8k / 49.2k / 41.6k req/s |

On Windows the throughput ceiling is the **benchmark client**, not the device.
At 32 outstanding, Little's law gives a mean of 630 µs per request against a
p50 of 88 µs, so the single-threaded issuer is the bottleneck. On Linux, one
worker saturates near 43k req/s and a second worker doubles throughput. A
fourth adds little on 4 vCPUs shared with the client.

| COV fan-out (write → notifications to N subscriptions) | Linux | Windows |
|---|---|---|
| 10 / 100 / 1000 subs, all delivered (p50) | 0.61 / 0.83 / 6.2 ms | 0.23 / 1.4 / 15.0 ms |
| marginal cost per notification | ~6 µs | ~14 µs |
| rounds with a missing notification | 0 of 450 | 0 of 450 |

## Findings worth talking about

1. **Stale COV subscriptions cost real time.** The first benchmark draft never
   cancelled its subscriptions, and the 1,000-subscription row showed a 7.3 ms
   p50 for the *first* notification, against 0.28 ms on a fresh device. Controlled run (`results/stale-subscriptions-linux.txt`): leaving
   1,000 subscriptions behind per run pushed the live client's first
   notification from 244 µs to 5.5, 10.2 and 15.8 ms over three more runs. The
   device had 318k frames to send instead of 136k, most of them to dead ports.
   With cancellation it stays flat at ~216 µs. Subscription lifetimes exist for
   exactly this reason.
2. **Windows `WSAECONNRESET` on UDP.** A COV notification to a subscriber that
   has exited triggers an ICMP port-unreachable, and Windows reports it as an
   error on the socket's *next* `recvfrom`. Measured with
   `tools/connreset_experiment.py`: 20 notifications to a dead port gave
   `rx_errors=20` with default Winsock behavior, and 0 with
   `SIO_UDP_CONNRESET` disabled. The device stays up in both cases because the
   receive loop never treats an error as fatal.
3. **Interop addressing.** bacnet-stack binds to an interface address, so
   `127.0.0.1` can't reach it. With only `--mac`, `bacrp` addressed DNET 0xFFFF
   and nothing reached our device until `--dnet 0` was added. It also sends
   broadcasts to its *own* port unless `BACNET_IP_BROADCAST_PORT` is set.
   `bacscov` has no `--mac` at all and needs an `address_cache` file.
4. **Fuzzing: the corpus matters more than the hours.** Against the real code:
   1.5M device-path + 5.1M client-decoder executions, 0 crashes. Against a
   **planted** null dereference (`-DBL_PLANT_BUG=ON`, off by default): found in
   5/5 trials within 168–10.7k executions when the seed session contained one
   Boolean write, but only 2/3 trials, after more than 170k executions, without
   it. That needs a REAL→BOOLEAN length-changing mutation.
5. **One crash, both debuggers** ([docs/CRASH_ANALYSIS.md](docs/CRASH_ANALYSIS.md)):
   minidump via `MiniDumpWriteDump` → WinDbg `!analyze -v` →
   `INVALID_POINTER_WRITE` at `objects.cpp:233`, `obj` hidden in `rbp=0` by the
   optimizer, request fields recovered with `dx`. A Linux core in GDB shows
   `si_addr` 0x78 == `offsetof(Object, out_of_service)`. MSVC faults at 0x70
   for the same line because the standard libraries lay out `Object` differently.
6. Smaller bugs found while building: a benchmark livelock (a `cv.wait`
   predicate that was already true never released the mutex, starving the
   completion callbacks), `mstcpip.h` include order, and three test vectors I
   had remembered wrong from the standard.

## Honest limits

- No segmentation, BBMD, routing, MS/TP, BACnet/SC, or GUI.
- BACnet has no authentication, and neither does this. Any host can write
  points or fill the 4,096 subscription slots. There is no per-peer limit.
- The TSM can reuse an invoke ID immediately after a timeout, so a very late
  reply could be matched to a new request.
- Interop was tested on one host (different ports), not across a real
  building network. "Linux" numbers come from WSL2.
- The crash analyzed in WinDbg/GDB is a planted bug. The fuzzer found no
  crash in the real code.
