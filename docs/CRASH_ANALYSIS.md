# Crash-dump analysis: one crash, WinDbg and GDB

**Honesty first:** libFuzzer ran 1.5M executions of the device's receive
path and 5.1M of the client decoders against the real code and found **no
crash** (`results/fuzz.txt`). To practise the dump workflow on a real fuzzer
finding, I compiled in one **planted** bug (`-DBL_PLANT_BUG=ON`, off by
default), let the fuzzer find it on its own, and analyzed that crash on both
platforms. The input, transcripts and scripts are all in the repo.

## The planted bug

`src/objects.cpp`, `ObjectDb::write`: an Out_Of_Service "fast path" that runs
**before** the unknown-object check, so it dereferences the null `obj`:

```cpp
Object* obj = it == objects_.end() ? nullptr : &it->second;
#if defined(BL_PLANT_BUG)
if (p.property == kPropOutOfService && vals.size() == 1 && vals[0].index() == kTagBoolean) {
    obj->out_of_service = std::get<bool>(vals[0]);   // obj == nullptr for an unknown object
    return std::nullopt;
}
#endif
if (!obj) return kUnknownObject;
```

This is a realistic bug shape: a later "optimisation" is inserted above a
guard it depends on.

## 1. The fuzzer finds it, and the corpus decides how fast

`scripts/plant_trials.sh`, 300 s cap per trial:

| seed corpus | trials found | executions to find |
|---|---|---|
| B: recorded session **with** one `write ai:2 out-of-service false` | 5/5 | 168, 3,909, 5,278, 6,793, 10,686 (under 1 s each) |
| A: same session **without** it | 2/3 | >170k and >262k; third trial missed it after 3.64M execs / 301 s |

To reach the bug from corpus A, a mutation has to turn a REAL value
(`44 xx xx xx xx`, 5 octets) into a BOOLEAN (`10`, 1 octet). That's a
length-changing edit inside a constructed `[3]…[3]` value, and libFuzzer's
byte-level mutators rarely produce it. With one Boolean write in the seeds, a
**single bit flip** on the object instance is enough. Lesson: seed coverage of
every datatype path matters more than fuzzing hours. `scripts/fuzz.sh` now
records Boolean and Enumerated writes.

The crashing datagram (`docs/crash/crash-input.bin`, 20 bytes) decodes as:

```
81 0a 00 14             BVLC Original-Unicast, length 20
01 04                   NPDU v1, expecting reply
00 05 00 0f             Confirmed-REQ, max-APDU 1476, invoke 0, WriteProperty
0c 00 02 00 02          [0] object = analog-input:131074   <- the bit flip (was ai:2)
19 51                   [1] property 81 = out-of-service
3e 10 3f                [3] { BOOLEAN false }
```

Under ASan+UBSan the fuzzer reports
`objects.cpp:233:14: runtime error: member access within null pointer of type 'Object'`.
The fixed build answers the same datagram with an Error PDU (object, unknown-object).

## 2. Windows: minidump + WinDbg (cdb)

`bl-device` installs `SetUnhandledExceptionFilter` → `MiniDumpWriteDump`
(`MiniDumpWithDataSegs | WithThreadInfo | WithIndirectlyReferencedMemory`).
`--replay FILE` feeds a raw datagram to the request handler with no socket, so
a field crash can be reproduced from a captured packet.

```
> build-msvc-plant\bl-device.exe --dump-dir dumps --replay docs\crash\crash-input.bin
bl-device: crashed (0xc0000005), minidump written to dumps\bl-device-22248.dmp
> powershell -File tools\analyze_dump.ps1 -Dump dumps\bl-device-22248.dmp
```

What `!analyze -v` and friends showed (full text: `docs/crash/windbg.txt`):

- `FAILURE_BUCKET_ID: INVALID_POINTER_WRITE_c0000005_bl-device-plant.exe!bac::ObjectDb::write`
- `Attempt to write to address 0000000000000070`. A tiny address means a null
  base plus a field offset, i.e. `nullptr->member`, not a wild pointer.
- Faulting instruction: `mov byte ptr [rbp+70h],al` with **`rbp=0`**.
  In this optimized build `dv` doesn't even list `obj`. The disassembly shows
  the compiler keeps it in `rbp`, and that register is 0. Reading the
  instruction against the registers is how you find a variable the optimizer hid.
- `FAULTING_SOURCE_LINE_NUMBER: 233`, stack `ObjectDb::write` ←
  `Device::handle_write_property` (device.cpp:180) ← `Device::handle` ←
  `Endpoint::process_datagram` ← `replay` ← `main`.
- `.frame 1; dx req.oid` → `type 0x0, instance 0x20002` (131074), and
  `dx req.prop.property` → `0x51` (81, Out_Of_Service). So it's a write of
  Out_Of_Service to an object that doesn't exist.

## 3. Linux: core file + GDB

`scripts/crash_linux.sh docs/crash/crash-input.bin` runs the planted gcc build
under gdb to the SIGSEGV, writes a core (`generate-core-file`, because WSL pipes
kernel cores to `/wsl-capture-crash`; elsewhere `ulimit -c unlimited` gives the
same file), then opens the **core** offline (`docs/crash/gdb-core.txt`):

```
$1 = (void *) 0x78                              <- $_siginfo...si_addr: the faulting address
#0  bac::ObjectDb::write (...) at src/objects.cpp:233
233         obj->out_of_service = std::get<bool>(vals[0]);
obj = 0x0
$2 = (bool *) 0x78                              <- &((bac::Object*)0)->out_of_service
#1  bac::Device::handle_write_property (...) at src/device.cpp:180
$4 = {type = 0, instance = 131074}              <- req.oid
$5 = 81                                         <- req.prop.property
```

`si_addr` equals `offsetof(Object, out_of_service)` exactly, which proves the
null-plus-offset reading.

## 4. Cross-platform detail worth mentioning

The same source line faults at **0x70 under MSVC** and **0x78 under GCC**.
`Object` contains `std::string`s and a `std::variant`, and libstdc++ and the
MSVC STL lay those out at different sizes, so the member offset differs. An
address seen in one platform's dump can't be assumed for the other build.
Always compute the offset against the binary that crashed.

## 5. Fix and guard

The real code (`BL_PLANT_BUG` off) checks `obj` before any property handling.
Regression coverage: `device_object_and_errors` (unit) and `test_bacnet_errors` (system) write Out_Of_Service to `ai:131074` and expect unknown-object; the
fuzz targets run in CI.
