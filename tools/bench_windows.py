"""Windows benchmark matrix (same configs as scripts/bench.sh): python tools/bench_windows.py [bin-dir]"""
import json, os, platform, signal, statistics as s, subprocess, sys

B = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build-msvc")
exe = lambda n: os.path.join(B, n + ".exe")
GROUP = subprocess.CREATE_NEW_PROCESS_GROUP


def device(port, workers=2):
    d = subprocess.Popen([exe("bl-device"), "--port", str(port), "--no-sim", "--workers", str(workers)],
                         stdout=subprocess.PIPE, text=True, creationflags=GROUP)
    d.stdout.readline()
    return d


def stop(d):
    d.send_signal(signal.CTRL_BREAK_EVENT)
    d.wait(timeout=5)
    return d.stdout.read().strip()


def bench(*args):
    return json.loads(subprocess.run([exe("bl-bench"), *map(str, args)], capture_output=True, text=True).stdout)


print(f"# Windows {platform.version()}, {os.cpu_count()} logical cpus, MSVC RelWithDebInfo, loopback")
for workers in (1, 2, 4):
    d = device(47970, workers)
    for c in (1, 8, 32, 64):
        rs = [bench("rp", "127.0.0.1:47970", "--requests", 50000, "--concurrency", c) for _ in range(3)]
        print("rp w=%d c=%-3d rps=%7.0f p50=%6.0fus p99=%7.0fus failed=%d" % (
            workers, c, s.median(r["rps"] for r in rs), s.median(r["p50_us"] for r in rs),
            s.median(r["p99_us"] for r in rs), sum(r["failed"] for r in rs)), flush=True)
    stop(d)
d = device(47971)
for n in (10, 100, 1000):
    rs = [bench("cov", "127.0.0.1:47971", "--subs", n, "--rounds", 50) for _ in range(3)]
    print("cov subs=%-5d ack_p50=%5.0fus first_p50=%6.0fus all_p50=%7.0fus all_p99=%7.0fus per_notif=%.2fus incomplete=%d" % (
        n, s.median(r["ack_p50_us"] for r in rs), s.median(r["first_p50_us"] for r in rs),
        s.median(r["all_p50_us"] for r in rs), s.median(r["all_p99_us"] for r in rs),
        s.median(r["per_notification_us"] for r in rs), sum(r["incomplete"] for r in rs)), flush=True)
print(stop(d))
