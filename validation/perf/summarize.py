#!/usr/bin/env python3
"""Summarize bench.py raw results into the three separately reported costs:
baseline (A), VPN-forwarding penalty (B vs A), incremental logging (C..F vs B).

Usage: summarize.py <results_dir> [--md out.md]
Medians across repeats with [min..max] spread. CPU is reported as ms per million
packets observed at the measured interface (tun0 for B..F, wlan0 for A) and as
absolute ms for the same workload, so different packet counts at TUN vs Wi-Fi
(TCP re-segmentation by the user-space stack) stay visible.
"""
import glob
import json
import os
import statistics
import sys

VARIANTS = ["A", "B", "C", "D", "E", "F"]
LABEL = {"A": "A no VPN", "B": "B fwd only", "C": "C copy+null", "D": "D writer", "E": "E +UID", "F": "F full"}


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def spread(xs, fmt="%.0f"):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    m = statistics.median(xs)
    return (fmt % m) + (" [" + fmt % min(xs) + ".." + fmt % max(xs) + "]" if len(xs) > 1 else "")


def load(d):
    runs = {}
    for f in glob.glob(os.path.join(d, "?-*-run*.json")):
        name = os.path.basename(f)
        if "sidecar" in name or "stall" in name:
            continue
        r = json.load(open(f))
        runs.setdefault((r["workload"]["name"], r["variant"]), []).append(r)
    return runs


def main():
    d = sys.argv[1]
    out = []
    p = out.append
    meta = json.load(open(os.path.join(d, "run_meta.json")))
    runs = load(d)
    workloads = [w["name"] for w in meta["workloads"]]
    p("# Benchmark summary — %s, Android %s (API %s), SoC %s" % (meta["device"], meta["android"], meta["sdk"], meta["soc"]))
    p("")
    p("Commit `%s`; repeats %d (variant order rotated per repeat); %s" % (meta["commit"][:12], meta["repeats"], meta["note"]))
    p("Environment at start: %s" % json.dumps(meta["env"]))
    p("")
    p("Values are medians [min..max] over repeats. `app CPU` = dev.minipcap process user+sys time; "
      "`sys busy` = all-core non-idle time on the phone during the workload (includes kernel TUN/Wi-Fi work, "
      "nettool itself and background noise). Packets counted on tun0 (B..F) or wlan0 (A).")
    p("")
    for w in workloads:
        p("## %s" % w)
        p("")
        p("| variant | pkts at iface | app CPU ms | app CPU ms / M pkts | sys busy ms | sys ms / M pkts | result |")
        p("|---|---|---|---|---|---|---|")
        for v in VARIANTS:
            rs = runs.get((w, v), [])
            if not rs:
                continue
            nt = [r["nettool"] for r in rs]
            if "achieved_pps" in nt[0]:
                res = "pps %s, loss %% %s, RTT p50 %s µs, p99 %s µs" % (
                    spread([n["achieved_pps"] for n in nt]), spread([n["loss_pct"] for n in nt], "%.3f"),
                    spread([n["rtt_us_p50"] for n in nt]), spread([n["rtt_us_p99"] for n in nt]))
            elif "mbit_s" in nt[0]:
                res = "%s Mbit/s" % spread([n["mbit_s"] for n in nt], "%.1f")
            else:
                res = "conn+RR p50 %s µs, p99 %s µs, failed %s" % (
                    spread([n["conn_rr_us_p50"] for n in nt]), spread([n["conn_rr_us_p99"] for n in nt]),
                    spread([n["failed"] for n in nt]))
            p("| %s | %s | %s | %s | %s | %s | %s |" % (
                LABEL[v], spread([r["iface_packets"] for r in rs]),
                spread([r["app_cpu_ms"] for r in rs]) if v != "A" else "n/a",
                spread([r["app_cpu_ms_per_million_tun_packets"] for r in rs]) if v != "A" else "n/a",
                spread([r["system_busy_ms"] for r in rs]),
                spread([r["system_busy_ms_per_million_packets"] for r in rs]), res))
        # Separate cost layers (median deltas).
        def m(v, k):
            return med([r[k] for r in runs.get((w, v), [])])
        b_app = m("B", "app_cpu_ms")
        rows = []
        if m("A", "system_busy_ms") is not None and m("B", "system_busy_ms") is not None:
            rows.append("VPN forwarding penalty (B−A): sys busy %+.0f ms" % (m("B", "system_busy_ms") - m("A", "system_busy_ms")))
        prev = "B"
        for v in ["C", "D", "E", "F"]:
            if m(v, "app_cpu_ms") is None or m(prev, "app_cpu_ms") is None:
                continue
            rows.append("%s−%s: app CPU %+.0f ms" % (v, prev, m(v, "app_cpu_ms") - m(prev, "app_cpu_ms")))
            prev = v
        if m("F", "app_cpu_ms") is not None and b_app:
            rows.append("total logging F−B: app CPU %+.0f ms (%+.0f%% of B app CPU)" % (
                m("F", "app_cpu_ms") - b_app, 100.0 * (m("F", "app_cpu_ms") - b_app) / b_app))
        if rows:
            p("")
            p("Deltas (medians): " + "; ".join(rows))
        p("")
    # Thread breakdown for the highest-rate UDP workload.
    w = "udp_small_5kpps"
    p("## Per-thread app CPU (%s, median ms)" % w)
    p("")
    names = sorted({n for v in VARIANTS for r in runs.get((w, v), []) for n in r["app_threads_cpu_ms"]})
    names = [n for n in names if max(med([r["app_threads_cpu_ms"].get(n, 0) for r in runs.get((w, v), [])]) or 0 for v in VARIANTS if runs.get((w, v))) >= 20]
    p("| variant | " + " | ".join(names) + " |")
    p("|---|" + "---|" * len(names))
    for v in VARIANTS[1:]:
        rs = runs.get((w, v), [])
        if rs:
            p("| %s | " % LABEL[v] + " | ".join("%.0f" % (med([r["app_threads_cpu_ms"].get(n, 0) for r in rs]) or 0) for n in names) + " |")
    p("")
    # Sidecar counters (drops/written) per variant.
    p("## Native counters per variant run (from sidecars)")
    p("")
    p("| file | pkts_ul | pkts_dl | records_written | queue drops | ring peak slots/slots | write syscalls | flows | uid requests | uid applied |")
    p("|---|---|---|---|---|---|---|---|---|---|")
    for f in sorted(glob.glob(os.path.join(d, "?-sidecar-run*.json"))):
        try:
            c = json.load(open(f)).get("native_counters", {})
        except ValueError:
            continue
        p("| %s | %s | %s | %s | %s | %s/%s | %s | %s | %s | %s |" % (
            os.path.basename(f), c.get("pkts_ul"), c.get("pkts_dl"), c.get("records_written"),
            (c.get("capture_queue_drops_ul") or 0) + (c.get("capture_queue_drops_dl") or 0),
            c.get("capture_ring_peak_slots"), c.get("capture_ring_slots"), c.get("write_syscalls"),
            c.get("flows_created"), c.get("uid_requests_queued"), c.get("uid_resolutions_applied")))
    stalls = sorted(glob.glob(os.path.join(d, "D-udp_small_5kpps_stall*.json")))
    if stalls:
        p("")
        p("## Writer stall under 5k pps UDP (variant D, V32)")
        p("")
        p("| stall | app loss % | RTT p99 µs | observed pkts | records written | capture drops | ring peak/slots |")
        p("|---|---|---|---|---|---|---|")
        for f in stalls:
            r = json.load(open(f))
            c = r["native_counters"]
            p("| %d ms | %.3f | %d | %d | %d | %d | %d/%d |" % (
                r["stall_ms"], r["nettool"]["loss_pct"], r["nettool"]["rtt_us_p99"], c["pkts_ul"] + c["pkts_dl"],
                c["records_written"], c["capture_queue_drops_ul"] + c["capture_queue_drops_dl"],
                c["capture_ring_peak_slots"], c["capture_ring_slots"]))
    text = "\n".join(out) + "\n"
    if "--md" in sys.argv:
        open(sys.argv[sys.argv.index("--md") + 1], "w").write(text)
    print(text)


if __name__ == "__main__":
    main()
