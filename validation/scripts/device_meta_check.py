#!/usr/bin/env python3
"""On-device functional check of the PCAP + metadata architecture (ADR-014 acceptance criteria).

Records a short session with every collector on, pulls both files and verifies:
  1. PCAP: linktype 113, both SLL directions present, every TCP/UDP record contains its transport header
  2. META: valid framing, SESSION_INFO first, one final SESSION_END(complete), session id = file stem
  3. sources: SENSOR_STATUS for location, accelerometer, radio, network; records of each enabled kind
  4. timestamps: record times inside the session span; motion samples at roughly the requested rate
  5. apps: FLOW_MAPPING for the workload flows, packets attributed through the analyzer
  6. analyzer: timeline + context-at a mid-session time succeed
  7. no metadata drops at the configured rates; capture drops reported
Usage: device_meta_check.py --host <workload-server-ip> [--seconds 30] [--motion-hz 50] [--keep DIR]
Prereq: debug build installed, VPN consent (appops) and runtime permissions granted, e.g.
  adb shell pm grant dev.minipcap android.permission.ACCESS_FINE_LOCATION
  adb shell pm grant dev.minipcap android.permission.READ_PHONE_STATE
"""
import argparse
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "perf"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "analyzer"))
import bench  # noqa: E402
import mpcanalyze as m  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, (" — " + str(detail)) if detail else ""))
    if not ok:
        FAILS.append(name)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5201)
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--motion-hz", type=int, default=50)
    ap.add_argument("--snaplen", type=int, default=128)
    ap.add_argument("--keep", default=None, help="directory to keep the pulled files in")
    a = ap.parse_args()

    before = set(bench.adb("run-as", bench.PKG, "ls", "files/captures", check=False).split())
    bench.app_cmd("--es", "cmd", "automove", "--ez", "on", "false")
    bench.app_cmd("--es", "cmd", "start", "--es", "variant", "F", "--ei", "snaplen", str(a.snaplen),
                  "--es", "mode", "INCLUDE", "--es", "pkgs", "com.android.shell",
                  "--ez", "gps", "true", "--ez", "radio", "true", "--ez", "motion", "true",
                  "--ei", "motion_hz", str(a.motion_hz), "--es", "motion_mode", "MAX_RATE")
    check("VPN up", bench.wait_vpn(True, 20))
    t0 = time.time()
    bench.run_workload(a.host, a.port, {"kind": "tcpdown", "seconds": min(10, a.seconds // 3)})
    bench.run_workload(a.host, a.port, {"kind": "udp", "pps": 200, "size": 200, "seconds": min(10, a.seconds // 3)})
    bench.run_workload(a.host, a.port, {"kind": "churn", "count": 30})
    rest = a.seconds - (time.time() - t0)
    if rest > 0:
        time.sleep(rest)
    bench.app_cmd("--es", "cmd", "stop")
    check("VPN down after Stop", bench.wait_vpn(False, 30))
    time.sleep(2)
    new = [n for n in bench.adb("run-as", bench.PKG, "ls", "files/captures").split() if n not in before and n.endswith(".pcap")]
    if not check("one new .pcap", len(new) == 1, new):
        return 1
    cid = new[0][:-5]
    d = a.keep or tempfile.mkdtemp(prefix="mpc-dev-")
    os.makedirs(d, exist_ok=True)
    pc = bench.pull(cid, "pcap", os.path.join(d, cid + ".pcap"))
    mp = bench.pull(cid, "meta", os.path.join(d, cid + ".meta"))
    pcap, meta = m.read_pcap(pc), m.read_meta(mp)

    # 1-2 structure
    errs, warns = m.validate(pcap, meta, pc)
    check("analyzer validate", not errs, errs or warns)
    dirs = {p["dir"] for p in pcap["packets"]}
    check("both directions in SLL", dirs == {"uplink", "downlink"}, dirs)
    check("session id matches file", meta["session_id"] == cid)
    end = meta["records"][-1] if meta["records"] else {}
    check("SESSION_END complete", end.get("type") == "SESSION_END" and end.get("status") == "complete", end.get("status"))

    # 3 sources
    s = m.Session(pcap, meta)
    status = {r["source"]: r["status"] for r in s.by.get("SENSOR_STATUS", [])}
    for src in ("location", "accelerometer", "radio", "network"):
        check("SENSOR_STATUS %s" % src, src in status, status.get(src))
    counts = {k: len(v) for k, v in s.by.items()}
    print("records:", counts)
    for kind in ("CLOCK_SYNC", "MOTION_SAMPLE", "RADIO_STATE", "NETWORK_STATE", "FLOW_MAPPING", "UID_MAPPING", "CAPTURE_STATS"):
        check("has %s" % kind, counts.get(kind, 0) > 0)
    for kind, src in (("LOCATION", "location"), ("CELL_MEASUREMENT", "cell_info"), ("SIGNAL_STRENGTH", "radio")):
        if status.get(src) == "active":
            check("has %s (source active)" % kind, counts.get(kind, 0) > 0,
                  "indoors without a fix is possible for LOCATION" if kind == "LOCATION" else "")
        else:
            print("SKIP %s: source %s is %s" % (kind, src, status.get(src)))

    # 4 timestamps
    span = (meta["start_boot_ns"] - 5 * 10 ** 9, end.get("ts_ns", 0) + 10 ** 9)
    bad = [r for r in meta["records"] if r["ts_source"] in ("logger", "sensor") and not span[0] <= r["ts_ns"] <= span[1]]
    check("logger/sensor timestamps inside session", not bad, len(bad))
    acc = s.motion.get("accelerometer")
    if acc and len(acc.ts) > 10:
        hz = (len(acc.ts) - 1) / ((acc.ts[-1] - acc.ts[0]) / 1e9)
        check("accelerometer rate ≈ requested", 0.5 * a.motion_hz <= hz <= 1.2 * a.motion_hz, "%.1f Hz" % hz)

    # 5-6 apps and analyzer
    rows = s.timeline()
    tcpudp = [r for r in rows if r["proto"] in ("tcp", "udp")]
    with_app = [r for r in tcpudp if r["uid"] != ""]
    check("packets attributed to an app", tcpudp and len(with_app) / len(tcpudp) > 0.95,
          "%d/%d" % (len(with_app), len(tcpudp)))
    mid = (pcap["packets"][0]["ts_ns"] + pcap["packets"][-1]["ts_ns"]) // 2 if pcap["packets"] else 0
    ctx = s.context_at(s.to_boot(mid))
    check("context-at mid-session", ctx["network"] is not None, ctx.get("location", {}).get("status"))

    # 7 losses
    c = end.get("counters", {})
    check("no metadata records dropped", c.get("meta_records_dropped", 0) == 0, c.get("meta_records_dropped"))
    print("capture drops:", c.get("capture_queue_drops_ul", 0) + c.get("capture_queue_drops_dl", 0),
          "records:", c.get("records_written"), "meta bytes:", os.path.getsize(mp))

    bench.adb("run-as %s sh -c 'rm -f files/captures/%s.*'" % (bench.PKG, cid), check=False)
    print("files kept in", d) if a.keep else None
    print("\n%s (%d failed)" % ("ALL PASSED" if not FAILS else "FAILED", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
