#!/usr/bin/env python3
"""P0/P1 benchmark orchestrator (docs/PERFORMANCE_PLAN.md).

Runs identical nettool workloads for variant A (no VPN) and B..F (same forwarding
engine, capture stages enabled per variant) on the attached phone. Only the shell
UID (com.android.shell, where nettool runs) is routed into the VPN (Include mode), so
other apps' traffic does not pollute measurements or leak into results.

Per workload it records: nettool JSON (rates, loss, RTT percentiles, client CPU),
tun0 packet/byte deltas from /proc/net/dev, app process + per-thread CPU deltas from
/proc/<pid>/{stat,task/*/stat}, system-wide CPU jiffies from /proc/stat, battery and
thermal state. Raw results: validation/perf/results/<device>/<date>/<variant>-<workload>-runN.json

Usage: bench.py --host 192.168.1.131 [--port 5201] [--repeats 3] [--variants A,B,C,D,E,F]
       [--stall]   (P1 V32: 1-5 s writer stall under load, variant D)
Requires: nettool server running on host, app installed (debug), VPN consent granted.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

PKG = "dev.minipcap"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "analyzer"))
import mpcanalyze  # noqa: E402


def pull(cid, ext, dest):
    """Copies files/captures/<cid>.<ext> from the app's private storage to dest."""
    data = subprocess.run(["adb", "exec-out", "run-as", PKG, "cat", "files/captures/%s.%s" % (cid, ext)],
                          capture_output=True).stdout
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def session_summary(meta_path):
    """Final counters from the binary .meta (SESSION_END), shaped for the benchmark summaries."""
    m = mpcanalyze.read_meta(meta_path, strict=False)
    end = next((r for r in m["records"] if r["type"] == "SESSION_END"), None)
    c = end["counters"] if end else {}
    stats = {"packets_recorded": c.get("records_written", 0),
             "capture_queue_drops": c.get("capture_queue_drops_ul", 0) + c.get("capture_queue_drops_dl", 0),
             "file_bytes": c.get("file_bytes", 0), "stop_finalize_ms": c.get("stop_finalize_ms"),
             "meta_records": len(m["records"]), "meta_records_dropped": c.get("meta_records_dropped", 0)}
    return {"native_counters": c, "stats": stats, "status": end["status"] if end else None}
NETTOOL = "/data/local/tmp/nettool"
CLK_TCK = 100


def adb(*args, check=True, timeout=180):
    r = subprocess.run(["adb", "shell", *args], capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError("adb %s failed: %s" % (args, r.stderr.strip()))
    return r.stdout


def app_cmd(*extras):
    adb("am", "start", "-n", PKG + "/.ui.MainActivity", *extras, check=False)


def pid():
    out = adb("pidof", PKG, check=False).strip()
    return int(out.split()[0]) if out else None


def proc_cpu(p):
    """(process utime+stime ticks, {thread_name: ticks})"""
    if p is None:
        return 0, {}
    # adb shell re-joins argv, so pass the whole remote command as one string.
    out = adb("cat /proc/%d/stat; for t in /proc/%d/task/*; do cat $t/stat 2>/dev/null; done" % (p, p), check=False)
    lines = [l for l in out.strip().split("\n") if l]
    def parse(l):
        m = re.match(r"^\d+ \((.*)\) (.*)$", l)
        if not m:
            return None, 0
        f = m.group(2).split()
        return m.group(1), int(f[11]) + int(f[12])
    total = parse(lines[0])[1] if lines else 0
    threads = {}
    for l in lines[1:]:
        n, v = parse(l)
        if n is not None:
            threads[n] = threads.get(n, 0) + v
    return total, threads


def sys_cpu():
    l = adb("head", "-1", "/proc/stat").split()
    vals = list(map(int, l[1:]))
    idle = vals[3] + vals[4]
    return sum(vals) - idle, sum(vals)


def netdev(iface):
    for line in adb("cat", "/proc/net/dev").split("\n"):
        if line.strip().startswith(iface + ":"):
            f = line.split(":")[1].split()
            return {"rx_bytes": int(f[0]), "rx_packets": int(f[1]), "tx_bytes": int(f[8]), "tx_packets": int(f[9])}
    return {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0}


def env():
    b = adb("dumpsys", "battery")
    t = adb("dumpsys", "thermalservice", check=False)
    g = lambda k: (re.search(k + r": (\S+)", b) or [None, None])[1]
    temps = dict(re.findall(r"mValue=([\d.]+), mType=\d+, mName=(\w+)", t)[:0])
    skin = re.findall(r"mValue=([\d.]+), mType=3, mName=(\w+)", t)
    return {"battery_level": g("level"), "battery_temp_dC": g("temperature"), "usb_powered": g("USB powered"),
            "thermal_status": (re.search(r"Thermal Status: (\d+)", t) or [None, None])[1],
            "skin_temps": skin[:3]}


def wait_vpn(up, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        c = adb("dumpsys", "connectivity", check=False).count("VPN CONNECTED")
        if (c > 0) == up:
            return True
        time.sleep(0.5)
    return False


def run_workload(host, port, w):
    kind = w["kind"]
    if kind == "udp":
        cmd = [NETTOOL, "udp", host, str(port), str(w["pps"]), str(w["size"]), str(w["seconds"])]
    elif kind in ("tcpup", "tcpdown"):
        cmd = [NETTOOL, kind, host, str(port), str(w["seconds"])]
    else:
        cmd = [NETTOOL, "churn", host, str(port), str(w["count"])]
    out = adb(*cmd, timeout=300)
    return json.loads(out.strip().split("\n")[-1])


WORKLOADS = [
    {"name": "udp_small_5kpps", "kind": "udp", "pps": 5000, "size": 100, "seconds": 15},
    {"name": "udp_large_2kpps", "kind": "udp", "pps": 2000, "size": 1200, "seconds": 15},
    {"name": "tcp_up", "kind": "tcpup", "seconds": 10},
    {"name": "tcp_down", "kind": "tcpdown", "seconds": 10},
    {"name": "tcp_churn_200", "kind": "churn", "count": 200},
]


def measure(host, port, variant, w, run, outdir):
    p = pid() if variant != "A" else None
    iface = "tun0" if variant != "A" else "wlan0"
    c0, t0 = proc_cpu(p)
    s0 = sys_cpu()
    n0 = netdev(iface)
    e0 = env()
    wall0 = time.time()
    res = run_workload(host, port, w)
    wall = time.time() - wall0
    c1, t1 = proc_cpu(p)
    s1 = sys_cpu()
    n1 = netdev(iface)
    dn = {k: n1[k] - n0[k] for k in n0}
    pkts = dn["rx_packets"] + dn["tx_packets"]
    app_ms = (c1 - c0) * 1000.0 / CLK_TCK
    rec = {
        "variant": variant, "workload": w, "run": run, "utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "wall_s": round(wall, 3), "nettool": res, "iface": iface, "iface_delta": dn,
        "iface_packets": pkts,
        "app_cpu_ms": app_ms,
        "app_threads_cpu_ms": {k: (t1.get(k, 0) - t0.get(k, 0)) * 1000.0 / CLK_TCK for k in t1 if t1.get(k, 0) - t0.get(k, 0) > 0},
        "app_cpu_ms_per_million_tun_packets": round(app_ms / pkts * 1e6, 1) if pkts and variant != "A" else None,
        "system_busy_ms": (s1[0] - s0[0]) * 1000.0 / CLK_TCK,
        "system_busy_ms_per_million_packets": round((s1[0] - s0[0]) * 1000.0 / CLK_TCK / pkts * 1e6, 1) if pkts else None,
        "env_before": e0, "env_after": env(),
    }
    with open(os.path.join(outdir, "%s-%s-run%d.json" % (variant, w["name"], run)), "w") as f:
        json.dump(rec, f, indent=1)
    return rec


def start_variant(v):
    if v == "A":
        return
    app_cmd("-S", "--es", "cmd", "start", "--es", "variant", v, "--ei", "snaplen", "256",
            "--es", "mode", "INCLUDE", "--es", "pkgs", "com.android.shell")
    if not wait_vpn(True):
        raise RuntimeError("VPN did not come up for variant " + v)
    time.sleep(2)


def stop_variant(v, outdir, run):
    if v == "A":
        return
    app_cmd("--es", "cmd", "stop")
    if not wait_vpn(False):
        raise RuntimeError("VPN did not stop for variant " + v)
    time.sleep(1.5)
    # Keep the variant's final counters as raw evidence; never keep packet captures.
    ids = [l.strip()[:-len(".state.json")] for l in adb("run-as", PKG, "ls", "files/captures").split() if l.endswith(".state.json")]
    newest = None
    for i in ids:
        st = adb("run-as", PKG, "cat", "files/captures/%s.state.json" % i, check=False)
        try:
            s = json.loads(st)
        except ValueError:
            continue
        if newest is None or s["seq"] > newest["seq"]:
            newest = s
    if newest:
        mp = pull(newest["capture_id"], "meta", os.path.join(outdir, "%s-run%d.meta" % (v, run)))
        with open(os.path.join(outdir, "%s-counters-run%d.json" % (v, run)), "w") as f:
            json.dump(session_summary(mp) if os.path.getsize(mp) else {}, f, indent=1)
        # Delete benchmark artifacts from the phone (keeps storage bounded).
        adb("run-as %s sh -c 'rm -f files/captures/%s.*'" % (PKG, newest["capture_id"]), check=False)


def stall_test(host, port, outdir):
    """V32: writer stalls of 1 s and 5 s under 5k pps UDP load (variant D)."""
    results = []
    for stall_ms in (1000, 5000):
        start_variant("D")
        w = {"name": "udp_small_5kpps_stall%d" % stall_ms, "kind": "udp", "pps": 5000, "size": 100, "seconds": 12}
        proc = subprocess.Popen(["adb", "shell", NETTOOL, "udp", host, str(port), "5000", "100", "12"],
                                stdout=subprocess.PIPE, text=True)
        time.sleep(3)
        app_cmd("--es", "cmd", "stall", "--ei", "ms", str(stall_ms))
        out, _ = proc.communicate(timeout=60)
        res = json.loads(out.strip().split("\n")[-1])
        stop_variant("D", outdir, 100 + stall_ms // 1000)
        with open(os.path.join(outdir, "D-counters-run%d.json" % (100 + stall_ms // 1000))) as f:
            meta = json.load(f)
        rec = {"stall_ms": stall_ms, "nettool": res, "native_counters": meta.get("native_counters"),
               "stats": meta.get("stats")}
        results.append(rec)
        with open(os.path.join(outdir, "D-%s.json" % w["name"]), "w") as f:
            json.dump(rec, f, indent=1)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5201)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--variants", default="A,B,C,D,E,F")
    ap.add_argument("--stall", action="store_true")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    model = adb("getprop", "ro.product.model").strip().replace(" ", "_")
    outdir = a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", model,
                                   datetime.date.today().isoformat())
    os.makedirs(outdir, exist_ok=True)
    meta = {"device": model, "android": adb("getprop", "ro.build.version.release").strip(),
            "sdk": adb("getprop", "ro.build.version.sdk").strip(), "build": adb("getprop", "ro.build.fingerprint").strip(),
            "soc": adb("getprop", "ro.soc.model").strip(),
            "commit": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
            "host": a.host, "workloads": WORKLOADS, "repeats": a.repeats, "env": env(),
            "note": "Include mode with com.android.shell only; snaplen 256; MTU 1500; Wi-Fi LAN path phone->host."}
    with open(os.path.join(outdir, "run_meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    variants = a.variants.split(",")
    for run in range(1, a.repeats + 1):
        order = variants[run - 1:] + variants[:run - 1]  # rotate order per repeat
        for v in order:
            print("run %d variant %s" % (run, v), flush=True)
            start_variant(v)
            run_workload(a.host, a.port, {"kind": "udp", "pps": 1000, "size": 100, "seconds": 3})  # warmup
            for w in WORKLOADS:
                r = measure(a.host, a.port, v, w, run, outdir)
                print("  %-16s pkts=%-7d app_ms=%-7.0f sys_ms=%-7.0f %s" % (
                    w["name"], r["iface_packets"], r["app_cpu_ms"], r["system_busy_ms"],
                    {k: r["nettool"][k] for k in ("achieved_pps", "loss_pct", "rtt_us_p50", "rtt_us_p99", "mbit_s",
                                                    "conn_rr_us_p50", "failed") if k in r["nettool"]}), flush=True)
            stop_variant(v, outdir, run)
    if a.stall:
        for r in stall_test(a.host, a.port, outdir):
            print("stall", r["stall_ms"], r["nettool"]["loss_pct"], r["stats"]["capture_queue_drops"], flush=True)
    print("results in", outdir)


if __name__ == "__main__":
    main()
