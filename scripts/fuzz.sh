#!/usr/bin/env bash
# bash scripts/fuzz.sh [seconds_per_target]
# Builds the libFuzzer targets (ASan+UBSan), seeds them from a recorded client
# session, and runs each target. Crashes land in $BUILD_ROOT/fuzz-run/<target>/.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
SECS=${1:-120}
bash scripts/build.sh gcc fuzz >/dev/null
RUN=$BUILD_ROOT/fuzz-run
mkdir -p "$RUN"

# record a session to seed the corpora
B=$BUILD_ROOT/gcc
PORT=47890
"$B/bl-device" --port $PORT --no-sim --pcap "$RUN/seed.pcap" >/dev/null &
DEV=$!
sleep 0.3
C="$B/bl-client --timeout 500"
A=127.0.0.1:$PORT
$C whois $A --wait 200 >/dev/null
$C whois $A --range 1 2000 --wait 200 >/dev/null
$C read $A ai:1 present-value >/dev/null
$C read $A av:1 priority-array >/dev/null
$C read $A device:1234 object-list[2] >/dev/null
$C rpm $A device:1234 all av:1 present-value,priority-array[3] >/dev/null
$C write $A av:1 present-value 22 --priority 9 >/dev/null
$C write $A av:1 present-value null --priority 9 >/dev/null
# Boolean / Enumerated writes: without these the fuzzer needs a length-changing
# edit (REAL -> BOOLEAN) to reach the Out_Of_Service path -- see docs/CRASH_ANALYSIS.md
$C write $A ai:2 out-of-service false >/dev/null
$C write $A bv:1 present-value active --priority 12 >/dev/null
$C read $A ai:7 present-value >/dev/null || true
$C subscribe $A av:1 --confirmed --lifetime 10 --duration 0.3 >/dev/null
$C subscribe $A av:1 --duration 0.3 >/dev/null
kill -INT $DEV; wait $DEV || true
python3 tools/pcap_to_corpus.py "$RUN/seed.pcap" "$RUN/corpus-device"
python3 tools/pcap_to_corpus.py "$RUN/seed.pcap" "$RUN/corpus-client" --client

for t in fuzz_device fuzz_client; do
  corpus=$RUN/corpus-${t#fuzz_}
  mkdir -p "$RUN/$t"
  echo "== $t for ${SECS}s"
  (cd "$RUN/$t" && "$BUILD_ROOT/fuzz/$t" -max_total_time="$SECS" -max_len=1500 -print_final_stats=1 \
      "$corpus" 2>&1 | grep -E "^#.*(DONE|pulse)|stat::|ERROR|SUMMARY|Test unit written" | tail -12)
done
