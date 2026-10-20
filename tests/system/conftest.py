"""Fixtures for the system tests: start bl-device processes, run bl-client.

Environment:
  BL_BIN            directory holding bl-device / bl-client / bl-bench (required)
  BACNET_STACK_BIN  bacnet-stack demo apps (interop tests are skipped without it)
  BL_HOST_IP        address the interop peers use to reach each other
                    (default: this host's primary IPv4 -- bacnet-stack binds to
                    an interface address, so 127.0.0.1 is not reachable from it)
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time

import pytest

EXE = ".exe" if sys.platform == "win32" else ""
BIN = os.environ.get("BL_BIN", "")


def exe(name):
    path = os.path.join(BIN, name + EXE)
    if not os.path.exists(path):
        pytest.exit(f"{path} not found; set BL_BIN", 2)
    return path


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def host_ip():
    if os.environ.get("BL_HOST_IP"):
        return os.environ["BL_HOST_IP"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the outbound interface
        return s.getsockname()[0]
    finally:
        s.close()


class DeviceProc:
    def __init__(self, instance, port, extra=()):
        self.instance, self.port = instance, port
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.proc = subprocess.Popen(
            [exe("bl-device"), "--instance", str(instance), "--port", str(port), *extra],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=flags)
        line = self.proc.stdout.readline()
        if "ready" not in line:
            raise RuntimeError(f"bl-device did not start: {line!r}")
        self.addr = f"127.0.0.1:{port}"

    def stop(self):
        if self.proc.poll() is None:
            # clean shutdown + stats line: SIGINT, or CTRL_BREAK on Windows
            self.proc.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
        try:
            out, _ = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate()
        return out


@pytest.fixture
def device():
    d = DeviceProc(1234, free_port(), ["--no-sim"])
    yield d
    check_clean(d.stop())


def check_clean(output):
    # under ASan/UBSan builds a report in the device's output fails the test
    assert "Sanitizer" not in output and "runtime error" not in output, output


@pytest.fixture
def spawn_device():
    procs = []

    def spawn(instance=1234, port=None, extra=("--no-sim",)):
        d = DeviceProc(instance, port or free_port(), list(extra))
        procs.append(d)
        return d

    yield spawn
    for d in procs:
        check_clean(d.stop())


def client(*args, timeout_ms=1000, retries=1, check=True, wall=30):
    """Run bl-client --json; return (exit code, list of JSON lines)."""
    cmd = [exe("bl-client"), "--json", "--timeout", str(timeout_ms), "--retries", str(retries), *map(str, args)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=wall)
    lines = [json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")]
    if check and p.returncode != 0:
        raise AssertionError(f"{' '.join(cmd)} -> rc={p.returncode}\n{p.stdout}{p.stderr}")
    return p.returncode, lines


def wait_for(pred, timeout=5.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False
