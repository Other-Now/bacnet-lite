#!/usr/bin/env bash
# Fuzzer time-to-find for the planted bug: N trials (different -seed) from a corpus.
#   bash scripts/plant_trials.sh <corpus-dir> <trials> <max-seconds> <out-file>
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
CORPUS=$1; N=$2; MAXT=$3; OUT=$4
R=$BUILD_ROOT/fuzz-run/plant-$(basename "$CORPUS"); rm -rf "$R"; mkdir -p "$R"
echo "corpus=$CORPUS ($(ls "$CORPUS" | wc -l) seeds) max=${MAXT}s" | tee "$OUT"
for t in $(seq 1 "$N"); do
  cp -r "$CORPUS" "$R/c$t"
  ( cd "$R" && "$BUILD_ROOT/fuzz-plant/fuzz_device" -seed=$t -max_len=1500 -max_total_time=$MAXT \
      -artifact_prefix="$R/crash$t-" "c$t" > "log$t.txt" 2>&1 )
  last=$(grep -oE "^#[0-9]+" "$R/log$t.txt" | tail -1)
  secs=$(grep -oE "Done [0-9]+ runs in [0-9]+ second" "$R/log$t.txt" | grep -oE "[0-9]+ second" | grep -oE "[0-9]+")
  if grep -qE "SEGV on unknown address|runtime error: member access within null" "$R/log$t.txt"; then
    tsec=$(grep -oE "^#[0-9]+.*exec/s: [0-9]+" "$R/log$t.txt" | tail -1)
    echo "trial $t: FOUND after ${last#\#} execs (last status: $tsec)" | tee -a "$OUT"
  else
    echo "trial $t: not found in ${secs:-$MAXT} s, ${last#\#} execs" | tee -a "$OUT"
  fi
done
ls "$R"/crash* 2>/dev/null | head -3
