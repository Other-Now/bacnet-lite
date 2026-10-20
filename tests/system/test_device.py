"""bl-client against bl-device over real UDP sockets (Linux and Windows)."""
import subprocess
import json
import time

from conftest import client, exe, free_port, wait_for

PV = "present-value"


def read(addr, obj, prop):
    _, out = client("read", addr, obj, prop)
    return out[0]["values"]


def test_whois_unicast_and_range(device):
    _, out = client("whois", device.addr, "--wait", "300")
    assert out == [{"device": 1234, "addr": device.addr, "max_apdu": 1476, "segmentation": 3, "vendor": 999}]
    rc, out = client("whois", device.addr, "--range", "1", "10", "--wait", "300", check=False)
    assert rc == 3 and out == []  # outside the range: the device stays silent
    _, out = client("whois", device.addr, "--range", "1000", "2000", "--wait", "300")
    assert out[0]["device"] == 1234


def test_read_device_and_points(device):
    assert read(device.addr, "ai:1", PV) == [{"type": "real", "value": 21.5}]
    assert read(device.addr, "ai:1", "units") == [{"type": "enumerated", "value": 62}]  # degrees-Celsius
    objs = [v["value"] for v in read(device.addr, "device:1234", "object-list")]
    assert objs == ["device:1234", "analog-input:1", "analog-input:2", "analog-output:1", "analog-value:1",
                    "binary-value:1"]
    assert read(device.addr, "device:1234", "object-list[0]") == [{"type": "unsigned", "value": 6}]
    # the wildcard instance 4194303 addresses "this device"
    assert read(device.addr, "device:4194303", "object-name") == [{"type": "character-string",
                                                                   "value": "bacnet-lite"}]


def test_priority_array_and_relinquish(device):
    a = device.addr
    client("write", a, "av:1", PV, "23.5", "--priority", "8")
    client("write", a, "av:1", PV, "22", "--priority", "16")
    assert read(a, "av:1", PV)[0]["value"] == 23.5         # priority 8 beats 16
    pa = read(a, "av:1", "priority-array")
    assert [v["type"] for v in pa].count("null") == 14 and pa[7]["value"] == 23.5 and pa[15]["value"] == 22
    client("write", a, "av:1", PV, "null", "--priority", "8")  # relinquish 8 -> 16 takes over
    assert read(a, "av:1", PV)[0]["value"] == 22
    client("write", a, "av:1", PV, "null", "--priority", "16")  # all NULL -> Relinquish_Default
    assert read(a, "av:1", PV)[0]["value"] == 21
    # binary value: enumerated active/inactive
    client("write", a, "bv:1", PV, "active", "--priority", "5")
    assert read(a, "bv:1", PV) == [{"type": "enumerated", "value": 1}]


def test_bacnet_errors(device):
    a = device.addr

    def err(*args):
        rc, out = client(*args, check=False)
        assert rc == 1
        return out[0]["kind"], out[0]["error_class"], out[0]["error_code"]

    assert err("read", a, "ai:99", PV) == ("error", 1, 31)                 # object / unknown-object
    # regression for the planted bug in docs/CRASH_ANALYSIS.md
    assert err("write", a, "ai:131074", "out-of-service", "false") == ("error", 1, 31)
    assert err("read", a, "ai:1", "priority-array") == ("error", 2, 32)    # property / unknown-property
    assert err("read", a, "ai:1", "present-value[1]") == ("error", 2, 50)  # property-is-not-an-array
    assert err("read", a, "av:1", "priority-array[17]") == ("error", 2, 42)
    assert err("write", a, "ai:1", PV, "30") == ("error", 2, 40)           # write-access-denied
    assert err("write", a, "av:1", PV, "1", "--priority", "17") == ("error", 2, 37)
    assert err("write", a, "av:1", PV, "1", "--type", "unsigned") == ("error", 2, 9)  # invalid-data-type
    # an input becomes writable once taken out of service
    client("write", a, "ai:1", "out-of-service", "true")
    client("write", a, "ai:1", PV, "30")
    assert read(a, "ai:1", PV)[0]["value"] == 30
    assert read(a, "ai:1", "status-flags")[0]["value"] == "0001"


def test_rpm_all_and_mixed_errors(device):
    _, out = client("rpm", device.addr, "av:1", "all", "ai:7", "present-value")
    av = [o for o in out if o["object"] == "analog-value:1"]
    props = {o["property"] for o in av}
    assert {"present-value", "priority-array", "relinquish-default", "cov-increment", "property-list"} <= props
    assert all("values" in o for o in av)
    missing = [o for o in out if o["object"] == "analog-input:7"]
    assert missing == [{"object": "analog-input:7", "property": "present-value", "error_class": 1,
                        "error_code": 31}]


def start_subscriber(addr, obj, *extra):
    p = subprocess.Popen([exe("bl-client"), "--json", "subscribe", addr, obj, *extra],
                         stdout=subprocess.PIPE, text=True)
    first = json.loads(p.stdout.readline())  # initial notification or the "subscribed" line
    return p, first


def collect(p):
    # Not communicate(timeout=...): that reads the raw pipe and silently drops lines the
    # readline() in start_subscriber already pulled into the TextIOWrapper's buffer
    # (seen in CI as a "missing" initial COV notification). The subscriber exits on its
    # own after --duration and its output fits in the pipe buffer.
    p.wait(timeout=30)
    out = p.stdout.read()
    return [json.loads(l) for l in out.splitlines() if l.startswith("{")]


def test_cov_on_write_respects_increment(device):
    p, first = start_subscriber(device.addr, "av:1", "--lifetime", "30", "--duration", "2")
    time.sleep(0.3)
    client("write", device.addr, "av:1", PV, "21.05")  # below COV_Increment 0.1
    client("write", device.addr, "av:1", PV, "24")     # above
    lines = [first] + collect(p)
    cov = [l for l in lines if l.get("cov")]
    values = [c["present_value"]["value"] for c in cov]
    assert values == [21, 24], values  # initial notification + one real change
    assert all(c["confirmed"] is False and 0 < c["time_remaining"] <= 30 for c in cov)


def test_confirmed_cov_is_acknowledged(device):
    p, _ = start_subscriber(device.addr, "av:1", "--confirmed", "--duration", "1.5")
    time.sleep(0.3)
    client("write", device.addr, "av:1", PV, "26")
    cov = [l for l in collect(p) if l.get("cov")]
    assert cov and all(c["confirmed"] for c in cov) and cov[-1]["present_value"]["value"] == 26


def test_cov_subscription_expires(device):
    p, _ = start_subscriber(device.addr, "av:1", "--lifetime", "1", "--duration", "2.5")
    time.sleep(1.6)  # lifetime is over; the device must have dropped the subscription
    client("write", device.addr, "av:1", PV, "27")
    cov = [l for l in collect(p) if l.get("cov")]
    assert all(c["present_value"]["value"] != 27 for c in cov)


def test_dead_subscriber_does_not_wedge_device(device):
    # Subscribe, let the subscriber exit, then trigger notifications to its now-closed
    # port. On Windows the resulting ICMP port-unreachable surfaces as WSAECONNRESET on
    # the device's next recvfrom unless SIO_UDP_CONNRESET is disabled.
    p, _ = start_subscriber(device.addr, "av:1", "--lifetime", "60", "--duration", "0.1")
    collect(p)
    for v in ("30", "31", "32"):
        client("write", device.addr, "av:1", PV, v)
    assert read(device.addr, "av:1", PV)[0]["value"] == 32


def test_timeout_and_retries():
    port = free_port()  # nothing listens here
    t0 = time.time()
    rc, out = client("read", f"127.0.0.1:{port}", "ai:1", PV, timeout_ms=300, retries=2, check=False)
    elapsed = time.time() - t0
    assert rc == 3 and out[0]["kind"] == "timeout" and out[0]["attempts"] == 3
    assert 0.85 < elapsed < 3.0, elapsed  # 3 attempts x 300 ms


def test_simulation_moves_zone_temp(spawn_device):
    d = spawn_device(extra=())
    v0 = read(d.addr, "ai:1", PV)[0]["value"]
    assert wait_for(lambda: read(d.addr, "ai:1", PV)[0]["value"] != v0, timeout=4)


def test_concurrent_load_no_failures(device):
    p = subprocess.run([exe("bl-bench"), "rp", device.addr, "--requests", "3000", "--concurrency", "32"],
                       capture_output=True, text=True, timeout=60)
    res = json.loads(p.stdout)
    assert p.returncode == 0 and res["ok"] == 3000 and res["failed"] == 0


def test_two_devices_independent(spawn_device):
    a, b = spawn_device(100), spawn_device(200)
    client("write", a.addr, "av:1", PV, "18")
    assert read(a.addr, "av:1", PV)[0]["value"] == 18
    assert read(b.addr, "av:1", PV)[0]["value"] == 21
    _, out = client("whois", b.addr, "--wait", "300")
    assert out[0]["device"] == 200
