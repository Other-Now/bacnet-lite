#!/usr/bin/env bash
# Fetch the interop peer (Steve Karg's bacnet-stack demo tools) and, when there
# is no root, unpack tshark + gdb from .debs into ~/bac-deps/root.
#   bash scripts/deps.sh            # bacnet-stack + (if missing) tshark/gdb debs
# CI installs tshark/gdb with apt instead and only needs the bacnet-stack part.
set -euo pipefail
DEPS=${BAC_DEPS:-$HOME/bac-deps}
TAG=bacnet-stack-1.6.1
mkdir -p "$DEPS"

# ---- bacnet-stack demo apps (BACnet/IP datalink) ----
if [ ! -x "$DEPS/bacnet-stack/bin/bacrp" ]; then
  rm -rf "$DEPS/bacnet-stack"
  git clone -q --depth 1 --branch "$TAG" https://github.com/bacnet-stack/bacnet-stack.git "$DEPS/bacnet-stack"
  make -s -C "$DEPS/bacnet-stack" BACDL=bip BUILD=release -j"$(nproc)" apps >"$DEPS/bacnet-stack-build.log" 2>&1 \
    || { tail -40 "$DEPS/bacnet-stack-build.log"; exit 1; }
fi
ls "$DEPS/bacnet-stack/bin" | tr '\n' ' '; echo

# ---- tshark + gdb without sudo (local WSL only) ----
need=()
command -v tshark >/dev/null || need+=(tshark)
command -v gdb >/dev/null || need+=(gdb)
if [ ${#need[@]} -gt 0 ] && [ ! -x "$DEPS/root/usr/bin/tshark" ]; then
  mkdir -p "$DEPS/debs" "$DEPS/root"
  cd "$DEPS/debs"
  pkgs=$(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
           --no-breaks --no-replaces --no-enhances "${need[@]}" | grep '^[a-z0-9]' | sort -u)
  for p in $pkgs; do
    dpkg -s "$p" >/dev/null 2>&1 && continue          # already on the system
    apt-get download "$p" >/dev/null 2>&1 || true      # virtual packages just fail
  done
  for d in *.deb; do dpkg -x "$d" "$DEPS/root"; done
fi
echo "deps ok"
