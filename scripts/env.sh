# Source me: puts locally unpacked tools (tshark, gdb, clang 20) on PATH.
DEPS=${BAC_DEPS:-$HOME/bac-deps}
if [ -d "$DEPS/root/usr/bin" ]; then
  export PATH="$DEPS/root/usr/bin:$PATH"
  export LD_LIBRARY_PATH="$DEPS/root/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
  # unpacked wireshark looks for its dissector plugins under its own prefix
  export WIRESHARK_PLUGIN_DIR="$DEPS/root/usr/lib/x86_64-linux-gnu/wireshark/plugins"
fi
if [ -x "$HOME/llvm20/root/usr/lib/llvm-20/bin/clang++" ]; then
  export CLANG_DIR=$HOME/llvm20/root/usr/lib/llvm-20/bin
  export LD_LIBRARY_PATH=$HOME/llvm20/root/usr/lib/x86_64-linux-gnu:$HOME/llvm20/root/usr/lib/llvm-20/lib:${LD_LIBRARY_PATH:-}
else
  export CLANG_DIR=$(dirname "$(command -v clang++ || echo /usr/bin/clang++)")
fi
export BACNET_STACK_BIN="$DEPS/bacnet-stack/bin"
export BUILD_ROOT=${BUILD_ROOT:-$HOME/bac-build}
