#!/usr/bin/env bash
# bash scripts/bench.sh [bin-dir] [out.jsonl]
# ReadProperty throughput/latency (closed loop, 1..64 outstanding; device with 1, 2
# and 4 workers) and COV fan-out to 10/100/1000 subscriptions. 3 runs per config.
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
BIN=${1:-$BUILD_ROOT/gcc}
OUT=${2:-results/bench-linux.jsonl}
mkdir -p "$(dirname "$OUT")"
: > "$OUT"
{ echo "# $(date -u +%FT%TZ) $(uname -sr) $(nproc) cpus, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"; uptime; } > "${OUT%.jsonl}.env.txt"
PORT=47950
for workers in 1 2 4; do
  "$BIN/bl-device" --port $PORT --no-sim --workers $workers >/dev/null & DEV=$!
  sleep 0.3
  for conc in 1 8 32 64; do
    for run in 1 2 3; do
      line=$("$BIN/bl-bench" rp 127.0.0.1:$PORT --requests 50000 --concurrency $conc)
      echo "{\"workers\":$workers,\"run\":$run,${line#\{}" | tee -a "$OUT"
    done
  done
  kill -INT $DEV; wait $DEV 2>/dev/null
done
"$BIN/bl-device" --port $PORT --no-sim >/dev/null & DEV=$!
sleep 0.3
for subs in 10 100 1000; do
  for run in 1 2 3; do
    line=$("$BIN/bl-bench" cov 127.0.0.1:$PORT --subs $subs --rounds 50)
    echo "{\"run\":$run,${line#\{}" | tee -a "$OUT"
  done
done
kill -INT $DEV; wait $DEV 2>/dev/null
