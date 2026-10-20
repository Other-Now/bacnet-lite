"""Interop with Steve Karg's bacnet-stack demo tools (Linux only).

Every bacnet-stack tool binds to an interface address and sends broadcasts to
its *own* BACNET_IP_PORT, so on one host the peers are bound statically:
--mac IP:PORT --dnet 0 for tools that accept it, an `address_cache` file for
those that do not (bacscov).
"""
import os
import subprocess
import sys
import time

import pytest

from conftest import client, exe, free_port, host_ip, wait_for, DeviceProc

STACK = os.environ.get("BACNET_STACK_BIN", "")
pytestmark = pytest.mark.skipif(sys.platform == "win32" or not os.path.exists(os.path.join(STACK, "bacrp")),
                                reason="bacnet-stack demo tools not available")
IP = host_ip()


def tool(name, *args, port=None, cwd=None, timeout=20):
    env = dict(os.environ, BACNET_IP_PORT=str(port or free_port()))
    p = subprocess.run([os.path.join(STACK, name), *map(str, args)], capture_output=True, text=True,
                       env=env, cwd=cwd, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


@pytest.fixture
def dev():
    d = DeviceProc(1234, free_port(), ["--no-sim"])
    d.peer = f"{IP}:{d.port}"
    yield d
    d.stop()


def static(d):
    return ["--mac", d.peer, "--dnet", "0"]


# --- their client -> our device -------------------------------------------------

def test_bacrp_reads_our_points(dev):
    rc, out = tool("bacrp", *static(dev), 1234, "analog-input", 1, "present-value")
    assert rc == 0 and out.strip() == "21.500000", out
    rc, out = tool("bacrp", *static(dev), 1234, "device", 1234, "object-list")
    assert "(analog-value, 1)" in out and "(binary-value, 1)" in out, out
    rc, out = tool("bacrp", *static(dev), 1234, "analog-value", 1, "units")
    assert "degrees-celsius" in out, out


def test_bacrp_sees_our_errors(dev):
    rc, out = tool("bacrp", *static(dev), 1234, "analog-input", 42, "present-value")
    assert "unknown-object" in out.lower(), out


def test_bacwp_priority_write_then_relinquish(dev):
    # bacwp DEVICE TYPE INSTANCE PROPERTY PRIORITY INDEX TAG VALUE  (tag 4 = REAL, 0 = NULL)
    rc, out = tool("bacwp", *static(dev), 1234, "analog-value", 1, "present-value", 10, -1, 4, 19.25)
    assert rc == 0 and "Acknowledged" in out, out
    _, r = client("read", dev.addr, "av:1", "priority-array[10]")
    assert r[0]["values"] == [{"type": "real", "value": 19.25}]
    rc, out = tool("bacwp", *static(dev), 1234, "analog-value", 1, "present-value", 10, -1, 0, 0)
    assert rc == 0, out
    _, r = client("read", dev.addr, "av:1", "present-value")
    assert r[0]["values"][0]["value"] == 21


def test_bacwi_discovers_us(dev):
    rc, out = tool("bacwi", "--mac", dev.peer, -1, timeout=15)
    assert "1234" in out and "Total Devices: 1" in out, out


def test_bacwi_broadcast_discovery(dev):
    # A real broadcast Who-Is. bacnet-stack sends broadcasts to its own port unless
    # BACNET_IP_BROADCAST_PORT says otherwise; our I-Am answers the asker directly.
    env = dict(os.environ, BACNET_IP_PORT=str(free_port()), BACNET_IP_BROADCAST_PORT=str(dev.port))
    p = subprocess.run([os.path.join(STACK, "bacwi"), "-1"], capture_output=True, text=True, env=env, timeout=20)
    assert "1234" in p.stdout and "Total Devices: 1" in p.stdout, p.stdout + p.stderr


def test_bacepics_walks_whole_device(dev, tmp_path):
    rc, out = tool("bacepics", "-t", dev.peer, 1234, timeout=60)
    (tmp_path / "epics.txt").write_text(out)
    os.makedirs("results", exist_ok=True)
    with open("results/bacepics-bl-device.txt", "w") as f:
        f.write(out)
    assert rc == 0, out[-2000:]
    for name in ("Zone Temp", "Outdoor Air Temp", "Damper Command", "Zone Setpoint", "Occupied"):
        assert name in out
    assert "SubscribeCOV" in out and "ReadPropertyMultiple" in out
    assert "unknown-property" not in out.lower() or "property-list" in out


def test_bacscov_subscribes_and_gets_notified(dev, tmp_path):
    (tmp_path / "address_cache").write_text(f"1234 {dev.peer} 0 0 1476\n")
    env = dict(os.environ, BACNET_IP_PORT=str(free_port()))
    p = subprocess.Popen([os.path.join(STACK, "bacscov"), "1234", "analog-value", "1", "7", "unconfirmed", "30"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=tmp_path)
    try:
        time.sleep(1.0)
        client("write", dev.addr, "av:1", "present-value", "24.5")
        time.sleep(1.0)
    finally:
        p.terminate()
        out, _ = p.communicate(timeout=5)
    # bacscov only logs receipt: expect the initial notification plus the one for the write
    assert out.count("UCOV: Received Notification!") == 2, out


# --- our client -> their device ---------------------------------------------------

@pytest.fixture
def bacserv(tmp_path):
    port = free_port()
    env = dict(os.environ, BACNET_IP_PORT=str(port))
    p = subprocess.Popen([os.path.join(STACK, "bacserv"), "4321"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, env=env, cwd=tmp_path)
    addr = f"{IP}:{port}"
    assert wait_for(lambda: client("read", addr, "device:4321", "object-name", check=False)[0] == 0, 5)
    yield addr
    p.terminate()
    p.wait(timeout=5)


def test_our_client_reads_and_writes_bacserv(bacserv):
    _, out = client("read", bacserv, "device:4321", "object-list")
    assert len(out[0]["values"]) > 20  # bacserv exposes ~80 objects, all in one unsegmented APDU
    _, out = client("rpm", bacserv, "device:4321", "object-name,vendor-identifier,protocol-revision",
                    "av:1", "present-value,cov-increment")
    props = {(o["object"], o["property"]) for o in out if "values" in o}
    assert ("device:4321", "protocol-revision") in props and ("analog-value:1", "present-value") in props
    client("write", bacserv, "av:1", "present-value", "42", "--priority", "8")
    _, out = client("read", bacserv, "av:1", "present-value")
    assert out[0]["values"][0]["value"] == 42


def test_our_client_cov_from_bacserv(bacserv):
    p = subprocess.Popen([exe("bl-client"), "--json", "subscribe", bacserv, "av:1", "--duration", "2"],
                         stdout=subprocess.PIPE, text=True)
    time.sleep(0.5)
    client("write", bacserv, "av:1", "present-value", "55", "--priority", "8")
    out, _ = p.communicate(timeout=10)
    assert '"value":55' in out, out
