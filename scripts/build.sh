#!/usr/bin/env bash
# bash scripts/build.sh [gcc|clang|asan|fuzz]...   -> $BUILD_ROOT/<flavour>
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
for flavour in "${@:-gcc}"; do
  out=$BUILD_ROOT/$flavour
  case $flavour in
    gcc)   args=(-DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=RelWithDebInfo) ;;
    clang) args=(-DCMAKE_CXX_COMPILER=$CLANG_DIR/clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo) ;;
    asan)  args=(-DCMAKE_CXX_COMPILER=$CLANG_DIR/clang++ -DCMAKE_BUILD_TYPE=Debug -DBL_SANITIZE=ON) ;;
    fuzz)  args=(-DCMAKE_CXX_COMPILER=$CLANG_DIR/clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBL_FUZZ=ON -DBL_SANITIZE=ON) ;;
    # the planted null-deref (docs/CRASH_ANALYSIS.md): fuzzer time-to-find, and a gcc build for gdb
    fuzz-plant) args=(-DCMAKE_CXX_COMPILER=$CLANG_DIR/clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBL_FUZZ=ON -DBL_SANITIZE=ON -DBL_PLANT_BUG=ON) ;;
    gcc-plant)  args=(-DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBL_PLANT_BUG=ON) ;;
    *) echo "unknown flavour $flavour"; exit 2 ;;
  esac
  cmake -S . -B "$out" -G Ninja "${args[@]}" >/dev/null
  cmake --build "$out"
done
