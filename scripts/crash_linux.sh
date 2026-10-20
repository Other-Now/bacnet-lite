#!/usr/bin/env bash
# Linux half of docs/CRASH_ANALYSIS.md: replay the fuzzer's crashing datagram into
# the planted-bug gcc build, write a core file, then analyse the core offline in gdb.
#   bash scripts/crash_linux.sh <crash-input> [outdir]
# The core is produced with gdb's generate-core-file because WSL pipes kernel cores
# to /wsl-capture-crash; on a normal Linux box `ulimit -c unlimited` gives the same file.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
INPUT=$(realpath "$1")
OUT=${2:-docs/crash}
BIN=$BUILD_ROOT/gcc-plant/bl-device
CORE=$BUILD_ROOT/crash-core
mkdir -p "$OUT"
rm -f "$CORE"

# 1) run until SIGSEGV, then dump a core of the stopped process
gdb -q -batch -ex run -ex "generate-core-file $CORE" --args "$BIN" --replay "$INPUT" >"$OUT/gdb-live.txt" 2>&1 || true
grep -E "SIGSEGV|Saved corefile" "$OUT/gdb-live.txt"

# 2) post-mortem on the core: what you do with a core file from the field
gdb -q -batch "$BIN" "$CORE" \
  -ex 'print $_siginfo._sifields._sigfault.si_addr' \
  -ex 'bt 8' -ex 'frame 0' -ex 'x/3i $pc' -ex 'info registers rax rip' \
  -ex 'info locals' -ex 'print &((bac::Object*)0)->out_of_service' -ex 'print p.property' \
  -ex 'frame 1' -ex 'print req.oid' -ex 'print req.prop.property' 2>&1 \
  | grep -vE "^\[New LWP|libthread_db|Using host libthread" | tee "$OUT/gdb-core.txt"
rm -f "$CORE"
