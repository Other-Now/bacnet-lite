"""Windows UDP WSAECONNRESET experiment.

A subscriber registers for COV and exits; each subsequent write makes the device send
a notification to the now-closed port. Windows turns the ICMP port-unreachable into a
WSAECONNRESET error on the device socket's *next* recvfrom. Prints the device's
rx_errors with whatever build BL_BIN points at.

    python tools/connreset_experiment.py <bin-dir> [writes]
"""
import os
import re
import signal
import subprocess
import sys
import time

EXE = ".exe" if sys.platform == "win32" else ""
bindir, writes = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 20
dev_exe, cli = os.path.join(bindir, "bl-device" + EXE), os.path.join(bindir, "bl-client" + EXE)
port = "47877"
flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
dev = subprocess.Popen([dev_exe, "--port", port, "--no-sim"], stdout=subprocess.PIPE, text=True, creationflags=flags)
dev.stdout.readline()
a = "127.0.0.1:" + port
subprocess.run([cli, "subscribe", a, "av:1", "--lifetime", "300", "--duration", "0.1"], capture_output=True)
ok = 0
t0 = time.perf_counter()
for i in range(writes):
    r = subprocess.run([cli, "write", a, "av:1", "present-value", str(30 + i)], capture_output=True, text=True)
    ok += r.returncode == 0
elapsed = time.perf_counter() - t0
r = subprocess.run([cli, "read", a, "av:1", "present-value"], capture_output=True, text=True)
dev.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
out = dev.communicate(timeout=5)[0]
m = re.search(r"rx_errors=(\d+)", out)
print(f"writes ok {ok}/{writes}, final read: {r.stdout.strip()!r}, "
      f"device rx_errors={m.group(1) if m else 'n/a (no stats line)'}, {elapsed:.2f}s")
