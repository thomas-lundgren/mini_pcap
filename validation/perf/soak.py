#!/usr/bin/env python3
"""Endurance soak (V18/V34): variant F, Include(com.android.shell), mixed load each
minute (UDP 2k pps x 200 B for 40 s, 10 s TCP download, 50 short TCP connections).
Samples every minute: app RSS / native heap / threads / fds, tun0 packets, battery and
thermal. At the end: stop, validate PCAP + metadata, report drops and memory trend.
Usage: soak.py --host <ip> --minutes 60 [--out dir]
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402

PKG = bench.PKG


def mem(pid):
    st = bench.adb("cat", "/proc/%d/status" % pid, check=False)
    g = lambda k: int((re.search(k + r":\s+(\d+)", st) or [0, 0])[1])
    mi = bench.adb("dumpsys", "meminfo", PKG, check=False)
    nh = re.search(r"Native Heap\s+(\d+)", mi)
    fds = bench.adb("ls /proc/%d/fd 2>/dev/null | wc -l" % pid, check=False).strip()
    return {"rss_kb": g("VmRSS"), "threads": g("Threads"), "native_heap_pss_kb": int(nh.group(1)) if nh else None,
            "fds": int(fds) if fds.isdigit() else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5201)
    ap.add_argument("--minutes", type=int, default=60)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "soak",
                                datetime.datetime.now().strftime("%Y-%m-%dT%H%M"))
    os.makedirs(out, exist_ok=True)
    bench.start_variant("F")
    pid = bench.pid()
    samples = []
    t_start = time.time()
    c_start, _ = bench.proc_cpu(pid)
    for minute in range(a.minutes):
        t0 = time.time()
        n0 = bench.netdev("tun0")
        u = bench.run_workload(a.host, a.port, {"kind": "udp", "pps": 2000, "size": 200, "seconds": 40})
        d = bench.run_workload(a.host, a.port, {"kind": "tcpdown", "seconds": 10})
        c = bench.run_workload(a.host, a.port, {"kind": "churn", "count": 50})
        n1 = bench.netdev("tun0")
        cpu, _ = bench.proc_cpu(pid)
        s = {"minute": minute, "t": round(time.time() - t_start, 1), **mem(pid),
             "tun_packets": (n1["rx_packets"] + n1["tx_packets"]) - (n0["rx_packets"] + n0["tx_packets"]),
             "app_cpu_s_total": (cpu - c_start) / bench.CLK_TCK, "udp_loss_pct": u["loss_pct"],
             "udp_rtt_p99_us": u["rtt_us_p99"], "tcp_mbit_s": d["mbit_s"], "churn_failed": c["failed"],
             "env": bench.env()}
        samples.append(s)
        print(json.dumps({k: s[k] for k in ("minute", "rss_kb", "native_heap_pss_kb", "threads", "fds", "tun_packets",
                                            "udp_loss_pct", "tcp_mbit_s", "churn_failed")}), flush=True)
        with open(os.path.join(out, "samples.jsonl"), "a") as f:
            f.write(json.dumps(s) + "\n")
        rest = 60 - (time.time() - t0)
        if rest > 0:
            time.sleep(rest)
    bench.app_cmd("--es", "cmd", "stop")
    bench.wait_vpn(False, 30)
    time.sleep(2)
    # Newest session: validated on the host, counters kept, capture files deleted.
    sess = []
    for name in bench.adb("run-as", PKG, "ls", "files/captures").split():
        if name.endswith(".state.json"):
            try:
                sess.append(json.loads(bench.adb("run-as", PKG, "cat", "files/captures/" + name)))
            except ValueError:
                pass
    last = max(sess, key=lambda s: s["seq"])
    cid = last["capture_id"]
    mp = bench.pull(cid, "meta", os.path.join(out, "%s.meta" % cid))
    pc = bench.pull(cid, "pcap", os.path.join(out, "%s.pcap" % cid))
    v = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(__file__), "..", "..", "analyzer", "mpcanalyze.py"),
                        "validate", pc, mp], capture_output=True, text=True).stdout
    m = bench.session_summary(mp)
    json.dump(m, open(os.path.join(out, "counters.json"), "w"), indent=1)
    rss = [s["rss_kb"] for s in samples]
    summary = {"minutes": a.minutes, "state": last["state"], "pcap_meta_valid": '"ok": true' in v,
               "records": m["stats"]["packets_recorded"], "capture_queue_drops": m["stats"]["capture_queue_drops"],
               "file_bytes": m["stats"]["file_bytes"], "rss_kb_first": rss[0], "rss_kb_max": max(rss), "rss_kb_last": rss[-1],
               "rss_kb_last10_spread": max(rss[-10:]) - min(rss[-10:]),
               "threads_max": max(s["threads"] for s in samples), "fds_max": max(s["fds"] or 0 for s in samples),
               "udp_loss_pct_max": max(s["udp_loss_pct"] for s in samples),
               "churn_failed_total": sum(s["churn_failed"] for s in samples),
               "app_cpu_s_total": samples[-1]["app_cpu_s_total"], "stop_finalize_ms": m["stats"].get("stop_finalize_ms"),
               "flows": m["native_counters"].get("flows_created"), "flows_expired": m["native_counters"].get("flows_expired")}
    json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=1)
    os.remove(pc)  # contains workload payload prefixes only, but keep repository/results small
    bench.adb("run-as %s sh -c 'rm -f files/captures/%s.*'" % (PKG, cid), check=False)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
