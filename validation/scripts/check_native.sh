#!/usr/bin/env bash
# M2 gate: build + run native host tests, then validate the generated PCAPNG
# fixtures with the independent Python parser AND tshark/capinfos.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="$ROOT/native/build-host"
TOOL="$ROOT/validation/scripts/pcapng_tool.py"
cmake -S "$ROOT/native" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Debug >/dev/null
ninja -C "$B" >/dev/null
cd "$B"
for t in test_pcapng test_flow test_ring; do echo "== $t"; ./"$t"; done
echo "== test_capture"; ./test_capture fixture
echo "== test_engine"; ./test_engine | tail -1

echo "== python independent parser"
python3 -I "$TOOL" check-fixture fixture/fixture.pcapng fixture/fixture.expected.json
python3 -I "$TOOL" validate fixture/stall.pcapng >/dev/null && echo "stall.pcapng structurally valid"
python3 -I "$TOOL" validate fixture/late.pcapng >/dev/null && echo "late.pcapng structurally valid"
python3 -I "$TOOL" validate engine_out/engine.pcapng >/dev/null && echo "engine.pcapng structurally valid"

echo "== tshark cross-check"
command -v tshark >/dev/null || { echo "tshark missing"; exit 1; }
python3 -I - "$B/fixture/fixture.pcapng" "$B/fixture/fixture.expected.json" <<'EOF'
import json, subprocess, sys
pcap, exp = sys.argv[1], json.load(open(sys.argv[2]))
out = subprocess.run(["tshark", "-r", pcap, "-Y", "frame.interface_id == 0", "-T", "fields", "-E", "separator=|",
                      "-e", "frame.packet_flags_direction", "-e", "frame.len", "-e", "frame.cap_len",
                      "-e", "frame.comment", "-e", "frame.time_epoch", "-e", "ip.version", "-e", "ipv6.src"],
                     capture_output=True, text=True, check=True).stdout.strip().split("\n")
errs = []
if len(out) != len(exp["records"]):
    errs.append("count %d vs %d" % (len(out), len(exp["records"])))
for i, (line, e) in enumerate(zip(out, exp["records"])):
    d, flen, clen, comment, t, ipver, v6 = line.split("|")
    want_dir = "0x00000002" if e["dir"] == "uplink" else "0x00000001"
    if d != want_dir: errs.append("rec %d dir %s" % (i+1, d))
    if int(flen) != e["orig_len"] or int(clen) != e["cap_len"]: errs.append("rec %d len" % (i+1))
    parts = (["u=%d" % e["uid"]] if e["uid"] >= 0 else []) + (["f=%d" % e["flow_id"]] if e["flow_id"] else []) \
        + (["c=%d" % e["ctx"]] if e["ctx"] else [])
    want = ";".join(parts)
    if comment != want: errs.append("rec %d comment %r want %r" % (i+1, comment, want))
    if abs(float(t) * 1e6 - e["ts_us"]) > 1.5: errs.append("rec %d ts %s" % (i+1, t))
# Context records: Wireshark's own JSON dissector must decode them (no plugin).
ctx = subprocess.run(["tshark", "-r", pcap, "-Y", "frame.interface_id == 1 && json", "-T", "fields",
                      "-e", "_ws.col.Info", "-e", "json.member_with_value"],
                     capture_output=True, text=True, check=True).stdout.strip().split("\n")
if len(ctx) != len(exp["contexts"]):
    errs.append("tshark decoded %d context records as JSON, want %d" % (len(ctx), len(exp["contexts"])))
for line, e in zip(ctx, exp["contexts"]):
    if "seq:%d" % e["seq"] not in line or (e["info"] and not line.startswith(e["info"])):
        errs.append("context %d decoded as %r" % (e["seq"], line))
print("tshark: %d packets + %d JSON context records checked, %s" % (len(out), len(ctx), "OK" if not errs else errs))
sys.exit(1 if errs else 0)
EOF
tshark -r "$B/fixture/fixture.pcapng" -q -z io,phs | sed -n '1,20p'
capinfos -c -E -l "$B/fixture/fixture.pcapng"
tshark -r "$B/engine_out/engine.pcapng" -T fields -e tcp.analysis.flags -Y "tcp.analysis.flags" | wc -l | xargs echo "engine.pcapng tcp analysis warnings:"
echo "ALL NATIVE CHECKS PASSED"
