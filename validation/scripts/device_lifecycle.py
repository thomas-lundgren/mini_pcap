#!/usr/bin/env python3
"""Device lifecycle checks (debug build, VPN consent pre-granted):
  V07  Include(com.android.shell) routes shell traffic into the VPN; Exclude(com.android.shell)
       bypasses it while connectivity keeps working.
  V09  Stop logging while a TCP download is running -> exactly one finalization, valid files.
  V17  Rapid Start/Stop cycles -> no duplicate active sessions, every session finalized.
Usage: device_lifecycle.py --host <nettool server IP> [--port 5201] [--cycles 5]
"""
import argparse
import json
import subprocess
import sys
import tempfile
import time

PKG = "dev.minipcap"
NETTOOL = "/data/local/tmp/nettool"
TOOL = __file__.rsplit("/", 1)[0] + "/../../analyzer/mpcanalyze.py"
sys.path.insert(0, __file__.rsplit("/", 1)[0] + "/../perf")
import bench  # noqa: E402


def sh(*a, check=False, timeout=120):
    return subprocess.run(["adb", "shell", *a], capture_output=True, text=True, timeout=timeout, check=check).stdout


def cmd(*extras):
    sh("am", "start", "-n", PKG + "/.ui.MainActivity", *extras)


def vpn_up():
    return sh("dumpsys", "connectivity").count("VPN CONNECTED") > 0


def wait(pred, t=15):
    end = time.time() + t
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.3)
    return False


def tun_packets():
    for l in sh("cat", "/proc/net/dev").split("\n"):
        if l.strip().startswith("tun0:"):
            f = l.split(":")[1].split()
            return int(f[1]) + int(f[9])
    return None


def sessions():
    out = {}
    for name in sh("run-as", PKG, "ls", "files/captures").split():
        if name.endswith(".state.json"):
            try:
                s = json.loads(sh("run-as", PKG, "cat", "files/captures/" + name))
                out[s["capture_id"]] = s
            except ValueError:
                pass
    return out


def start(mode, pkgs="", variant="F"):
    cmd("-S", "--es", "cmd", "start", "--es", "variant", variant, "--es", "mode", mode, "--es", "pkgs", pkgs)
    return wait(vpn_up)


def stop():
    cmd("--es", "cmd", "stop")
    return wait(lambda: not vpn_up())


def check(name, ok, detail=""):
    print("%-5s %-60s %s" % ("PASS" if ok else "FAIL", name, detail))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", default="5201")
    ap.add_argument("--cycles", type=int, default=5)
    a = ap.parse_args()
    allok = True
    before = set(sessions())

    # V07 Include
    allok &= check("V07 include: VPN up", start("INCLUDE", "com.android.shell"))
    p0 = tun_packets()
    r = json.loads(sh(NETTOOL, "udp", a.host, a.port, "500", "100", "2").strip().split("\n")[-1])
    p1 = tun_packets()
    allok &= check("V07 include: shell traffic enters tun0", p1 - p0 >= 1500, "tun pkts +%d, loss %.2f%%" % (p1 - p0, r["loss_pct"]))
    allok &= check("V07 include: stop", stop())
    # V07 Exclude
    allok &= check("V07 exclude: VPN up", start("EXCLUDE", "com.android.shell"))
    p0 = tun_packets()
    r = json.loads(sh(NETTOOL, "udp", a.host, a.port, "500", "100", "2").strip().split("\n")[-1])
    t = json.loads(sh(NETTOOL, "tcpdown", a.host, a.port, "2").strip().split("\n")[-1])
    p1 = tun_packets()
    allok &= check("V07 exclude: shell bypasses VPN (tun0 unchanged by workload)", (p1 - p0) < 50, "tun pkts +%d" % (p1 - p0))
    allok &= check("V07 exclude: bypassed app keeps connectivity", r["loss_pct"] < 1 and t["bytes"] > 1_000_000,
                   "udp loss %.2f%%, tcp %.1f Mbit/s" % (r["loss_pct"], t["mbit_s"]))
    allok &= check("V07 exclude: stop", stop())

    # V09 Stop under load
    allok &= check("V09: VPN up", start("INCLUDE", "com.android.shell"))
    load = subprocess.Popen(["adb", "shell", NETTOOL, "tcpdown", a.host, a.port, "8"], stdout=subprocess.PIPE, text=True)
    time.sleep(3)
    cmd("--es", "cmd", "stop")
    cmd("--es", "cmd", "stop")  # duplicate Stop must be ignored
    allok &= check("V09: stopped under load", wait(lambda: not vpn_up()))
    load.communicate(timeout=60)
    time.sleep(1)
    new = {k: v for k, v in sessions().items() if k not in before}
    last = max(new.values(), key=lambda s: s["seq"]) if new else None
    ok = last is not None and last["state"] == "COMPLETE"
    allok &= check("V09: exactly one finalization, state COMPLETE", ok and last.get("finalize_seq") is not None,
                   last and last["state"])
    if ok:
        with tempfile.TemporaryDirectory() as d:
            cid = last["capture_id"]
            pc = bench.pull(cid, "pcap", "%s/%s.pcap" % (d, cid))
            mp = bench.pull(cid, "meta", "%s/%s.meta" % (d, cid))
            v = subprocess.run([sys.executable, "-I", TOOL, "validate", pc, mp], capture_output=True, text=True)
            meta = bench.session_summary(mp)
            allok &= check("V09: PCAP + meta valid", '"ok": true' in v.stdout,
                           "records %s, drops %s, finalize %s ms" % (meta["stats"]["packets_recorded"],
                                                                     meta["stats"]["capture_queue_drops"],
                                                                     meta["stats"].get("stop_finalize_ms")))
        sh("run-as %s sh -c 'rm -f files/captures/%s.*'" % (PKG, cid))
    before = set(sessions())

    # V17 rapid start/stop
    for i in range(a.cycles):
        start("INCLUDE", "com.android.shell", variant="F")
        time.sleep(0.5)
        stop()
    time.sleep(2)
    new = {k: v for k, v in sessions().items() if k not in before}
    states = sorted(s["state"] for s in new.values())
    allok &= check("V17: %d cycles -> %d sessions, none left active" % (a.cycles, len(new)),
                   len(new) == a.cycles and all(s in ("COMPLETE",) for s in states), str(states))
    allok &= check("V17: VPN down at end", not vpn_up())
    for cid in new:
        sh("run-as %s sh -c 'rm -f files/captures/%s.*'" % (PKG, cid))
    print("ALL PASS" if allok else "SOME CHECKS FAILED")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
