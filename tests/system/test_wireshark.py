"""Every frame bl-device sends or receives must decode cleanly in Wireshark.

bl-device --pcap writes its own traffic (synthetic IPv4/UDP headers, LINKTYPE_RAW),
so this needs no capture privileges; CI additionally captures the interop runs
with a real dumpcap on the loopback interface.
"""
import os
import shutil
import subprocess

import pytest

from conftest import client, DeviceProc, free_port
from test_device import start_subscriber, collect

pytestmark = pytest.mark.skipif(not shutil.which("tshark") or not shutil.which("perl"),
                                reason="tshark and perl are needed")


def test_all_frames_decode(tmp_path):
    pcap = str(tmp_path / "session.pcap")
    port = free_port()
    d = DeviceProc(1234, port, ["--no-sim", "--pcap", pcap])
    a = d.addr
    try:
        client("whois", a, "--wait", "200")
        client("read", a, "ai:1", "present-value")
        client("read", a, "device:1234", "object-list")
        client("read", a, "av:1", "priority-array[8]")
        client("rpm", a, "device:1234", "all", "av:1", "all", "bv:1", "present-value")
        client("write", a, "av:1", "present-value", "23", "--priority", "8")
        client("write", a, "bv:1", "present-value", "active")
        client("read", a, "ai:9", "present-value", check=False)            # Error PDU
        client("write", a, "ai:1", "present-value", "1", check=False)      # Error PDU
        p, _ = start_subscriber(a, "av:1", "--confirmed", "--duration", "1")  # confirmed COV + acks
        client("write", a, "av:1", "present-value", "25", "--priority", "8")
        collect(p)
        p, _ = start_subscriber(a, "av:1", "--duration", "1")
        client("write", a, "av:1", "present-value", "null", "--priority", "8")
        collect(p)
    finally:
        d.stop()
    r = subprocess.run(["perl", "tools/check_pcap.pl", pcap, "1024-65535"], capture_output=True, text=True)
    os.makedirs("results", exist_ok=True)
    with open("results/tshark-session.txt", "w") as f:
        f.write(r.stdout + r.stderr)
    print(r.stdout)
    assert r.returncode == 0, r.stdout + r.stderr
    for kind in ("Confirmed-REQ readProperty", "Complex-ACK readPropertyMultiple", "Simple-ACK writeProperty",
                 "Unconfirmed-REQ i-Am", "Error writeProperty", "Confirmed-REQ confirmedCOVNotification",
                 "Unconfirmed-REQ unconfirmedCOVNotification"):
        assert kind in r.stdout, kind
