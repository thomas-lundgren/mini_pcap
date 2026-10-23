#!/usr/bin/env bash
# Phase 1 gate: build + run native host tests, then validate the generated PCAP (Linux SLL)
# fixtures with the independent Python reader (analyzer) AND tshark/capinfos.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="$ROOT/native/build-host"
cmake -S "$ROOT/native" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Debug >/dev/null
ninja -C "$B" >/tmp/mpc-ninja.log 2>&1 || { cat /tmp/mpc-ninja.log; exit 1; }
cd "$B"
for t in test_pcap test_packet test_flow test_ring; do echo "== $t"; ./"$t"; done
echo "== test_capture"; ./test_capture fixture
echo "== test_engine"; ./test_engine | tail -1

echo "== independent reader + tshark"
command -v tshark >/dev/null || { echo "tshark missing"; exit 1; }
python3 -I - "$ROOT/analyzer" "$B/fixture/fixture.pcap" "$B/fixture/fixture.expected.json" \
    "$B/fixture/stall.pcap" "$B/engine_out/engine.pcap" <<'PY'
import json, subprocess, sys
sys.path.insert(0, sys.argv[1])
import mpcanalyze as m
pcap_path, exp = sys.argv[2], json.load(open(sys.argv[3]))
p = m.read_pcap(pcap_path)
errs = []
if p["snaplen"] != exp["snaplen"]:
    errs.append("pcap snaplen %d (want %d: largest record incl. SLL)" % (p["snaplen"], exp["snaplen"]))
if not p["nano"]:
    errs.append("expected nanosecond pcap")
if len(p["packets"]) != len(exp["records"]):
    errs.append("count %d vs %d" % (len(p["packets"]), len(exp["records"])))
for i, (r, e) in enumerate(zip(p["packets"], exp["records"])):
    for k in ("dir", "orig_len", "cap_len", "ts_ns"):
        if r[k] != e[k]:
            errs.append("rec %d %s: %r != %r" % (i + 1, k, r[k], e[k]))
    if r["ts_ns"] - exp["anchor_real_ns"] + exp["anchor_boot_ns"] != e["boot_ns"]:
        errs.append("rec %d: monotonic time not recoverable from pcap time" % (i + 1))
print("reader: %d records, %s" % (len(p["packets"]), "OK" if not errs else errs))
out = subprocess.run(["tshark", "-r", pcap_path, "-T", "fields", "-E", "separator=|", "-e", "sll.pkttype",
                      "-e", "frame.len", "-e", "frame.cap_len", "-e", "frame.time_epoch", "-e", "sll.etype"],
                     capture_output=True, text=True, check=True).stdout.strip().split("\n")
for i, (line, e) in enumerate(zip(out, exp["records"])):
    pkttype, flen, clen, t, etype = line.split("|")
    want = "4" if e["dir"] == "uplink" else "0"
    if pkttype != want: errs.append("tshark rec %d sll.pkttype %s want %s" % (i + 1, pkttype, want))
    if int(flen) != e["orig_len"] + 16 or int(clen) != e["cap_len"] + 16: errs.append("tshark rec %d len" % (i + 1))
    if abs(float(t) * 1e9 - e["ts_ns"]) > 1000: errs.append("tshark rec %d ts %s" % (i + 1, t))
print("tshark: %d records, direction/lengths/time %s" % (len(out), "OK" if not errs else errs))
for extra in sys.argv[4:]:
    q = m.read_pcap(extra)
    print("%s: %d records, structurally valid" % (extra.rsplit("/", 1)[-1], len(q["packets"])))
sys.exit(1 if errs else 0)
PY
tshark -r "$B/fixture/fixture.pcap" -q -z io,phs | sed -n '1,16p'
capinfos -c -E -l "$B/fixture/fixture.pcap"
tshark -r "$B/engine_out/engine.pcap" -T fields -e tcp.analysis.flags -Y "tcp.analysis.flags" | wc -l | xargs echo "engine.pcap tcp analysis warnings:"
echo "ALL NATIVE CHECKS PASSED"
