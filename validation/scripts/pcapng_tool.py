#!/usr/bin/env python3
"""LEGACY reader for captures made before ADR-014 (PCAPNG + JSON sidecar, app versions
<= 0.1.0). Current sessions (<id>.pcap + <id>.meta) are read by analyzer/mpcanalyze.py.

Independent PCAPNG v1 reader/validator and sidecar join tool (stdlib only).

Written separately from the native writer so it can serve as an independent
check of the binary format and of the comment grammar:

    comment := "f-" FLOW | "u-" UID ";f-" FLOW | "u-" UID
    (no comment => no flow ID, i.e. flow_id 0: non-TCP/UDP, fragment, malformed)

Commands:
    validate <file.pcapng>                       strict structural validation
    check-fixture <file.pcapng> <expected.json>   compare records with native test expectations
    validate-sidecar <file.meta.json>             sidecar contract checks
    join <file.pcapng> <file.meta.json> [--csv]   timestamp,src,dst,proto,...,uid,app,class
"""
import ipaddress
import json
import re
import struct
import sys

BT_SHB, BT_IDB, BT_EPB = 0x0A0D0D0A, 0x00000001, 0x00000006
COMMENT_RE = re.compile(r"^(?:u-(\d+)(?:;f-(\d+))?|f-(\d+))$")


class FormatError(Exception):
    pass


def parse_options(data, off, end, endian):
    opts = []
    terminated = False
    while off < end:
        if off + 4 > end:
            raise FormatError("truncated option header")
        code, length = struct.unpack_from(endian + "HH", data, off)
        off += 4
        if code == 0:
            if length != 0:
                raise FormatError("opt_endofopt with nonzero length")
            terminated = True
            break
        padded = (length + 3) & ~3
        if off + padded > end:
            raise FormatError("option overruns block")
        value = data[off:off + length]
        if any(data[off + length:off + padded]):
            raise FormatError("nonzero option padding")
        opts.append((code, value))
        off += padded
    if opts and not terminated:
        raise FormatError("options not terminated by opt_endofopt")
    if terminated and off != end:
        raise FormatError("bytes after opt_endofopt")
    return opts


def parse_comment(c):
    """Returns (uid or None, flow_id) per the v1 grammar; raises on bad syntax."""
    if c is None:
        return None, 0
    m = COMMENT_RE.match(c)
    if not m:
        raise FormatError("comment does not match v1 grammar: %r" % c)
    if m.group(3) is not None:
        return None, int(m.group(3))
    return int(m.group(1)), int(m.group(2) or 0)


def read_pcapng(path, strict=True):
    data = open(path, "rb").read()
    off = 0
    endian = "<"
    interfaces = []
    records = []
    shb = None
    while off < len(data):
        if off + 12 > len(data):
            raise FormatError("trailing %d bytes (truncated block header)" % (len(data) - off))
        btype = struct.unpack_from("<I", data, off)[0]
        if btype == BT_SHB:
            magic = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if magic == 0x1A2B3C4D else ">"
            if struct.unpack_from(endian + "I", data, off + 8)[0] != 0x1A2B3C4D:
                raise FormatError("bad byte-order magic")
        total = struct.unpack_from(endian + "I", data, off + 4)[0]
        if total < 12 or total % 4 or off + total > len(data):
            raise FormatError("bad block length %d at offset %d" % (total, off))
        trailer = struct.unpack_from(endian + "I", data, off + total - 4)[0]
        if trailer != total:
            raise FormatError("trailing length mismatch at offset %d" % off)
        body_end = off + total - 4
        if btype == BT_SHB:
            major, minor = struct.unpack_from(endian + "HH", data, off + 12)
            if (major, minor) != (1, 0):
                raise FormatError("unsupported version %d.%d" % (major, minor))
            opts = parse_options(data, off + 24, body_end, endian)
            shb = {c: v.decode("utf-8", "replace") for c, v in opts}
            interfaces = []
        elif btype == BT_IDB:
            linktype, _, snaplen = struct.unpack_from(endian + "HHI", data, off + 8)
            opts = parse_options(data, off + 16, body_end, endian)
            tsresol = 6
            name = None
            for c, v in opts:
                if c == 9:
                    tsresol = v[0]
                elif c == 2:
                    name = v.decode()
            if tsresol & 0x80:
                raise FormatError("binary tsresol not supported by this reader")
            interfaces.append({"linktype": linktype, "snaplen": snaplen, "tsresol": tsresol,
                               "name": name})
        elif btype == BT_EPB:
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(endian + "IIIII", data, off + 8)
            if if_id >= len(interfaces):
                raise FormatError("EPB references unknown interface %d" % if_id)
            iface = interfaces[if_id]
            if cap_len > orig_len:
                raise FormatError("captured length > original length")
            if strict and iface["snaplen"] and cap_len > iface["snaplen"]:
                raise FormatError("captured length > snaplen")
            pkt_off = off + 28
            padded = (cap_len + 3) & ~3
            if pkt_off + padded > body_end:
                raise FormatError("packet data overruns block")
            if any(data[pkt_off + cap_len:pkt_off + padded]):
                raise FormatError("nonzero packet padding")
            opts = parse_options(data, pkt_off + padded, body_end, endian)
            comment = None
            flags = None
            for c, v in opts:
                if c == 1:
                    if comment is not None:
                        raise FormatError("multiple comments in EPB")
                    comment = v.decode("utf-8")
                elif c == 2:
                    if len(v) != 4:
                        raise FormatError("epb_flags length != 4")
                    flags = struct.unpack(endian + "I", v)[0]
            uid, flow_id = parse_comment(comment)
            ts = (ts_hi << 32) | ts_lo
            direction = {1: "downlink", 2: "uplink"}.get((flags or 0) & 3, "unknown")
            records.append({"ts": ts, "ts_us": ts * 10 ** 6 // 10 ** iface["tsresol"],
                            "cap_len": cap_len, "orig_len": orig_len,
                            "data": data[pkt_off:pkt_off + cap_len], "comment": comment,
                            "flags": flags, "dir": direction, "uid": uid, "flow_id": flow_id})
        else:
            pass  # unknown block types are skipped per spec
        off += total
    if shb is None:
        raise FormatError("no Section Header Block")
    return {"shb": shb, "interfaces": interfaces, "records": records}


def decode_ip(data):
    """Best-effort header decode of a (possibly truncated) raw IP prefix."""
    out = {"src": "", "dst": "", "proto": "", "sport": "", "dport": ""}
    if not data:
        return out
    v = data[0] >> 4
    l4 = None
    proto = None
    if v == 4 and len(data) >= 20:
        ihl = (data[0] & 15) * 4
        out["src"] = str(ipaddress.IPv4Address(data[12:16]))
        out["dst"] = str(ipaddress.IPv4Address(data[16:20]))
        proto = data[9]
        frag = struct.unpack(">H", data[6:8])[0] & 0x1FFF
        if frag == 0:
            l4 = ihl
    elif v == 6 and len(data) >= 40:
        out["src"] = str(ipaddress.IPv6Address(data[8:24]))
        out["dst"] = str(ipaddress.IPv6Address(data[24:40]))
        proto = data[6]
        l4 = 40
        for _ in range(8):
            if proto in (0, 43, 60) and l4 + 8 <= len(data):
                proto, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
            elif proto == 44 and l4 + 8 <= len(data):
                fo = struct.unpack(">H", data[l4 + 2:l4 + 4])[0] & 0xFFF8
                proto, l4 = data[l4], (l4 + 8 if fo == 0 else None)
                if l4 is None:
                    break
            else:
                break
    if proto is not None:
        out["proto"] = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(proto, str(proto))
        if proto in (6, 17) and l4 is not None and l4 + 4 <= len(data):
            out["sport"], out["dport"] = struct.unpack(">HH", data[l4:l4 + 4])
    return out


def validate_sidecar(meta):
    errors = []
    for key in ("schema_version", "capture_id", "capture_file", "status", "uid_map",
                "flow_uid_map", "stats", "timestamp_unit", "capture_point"):
        if key not in meta:
            errors.append("missing key %s" % key)
    if meta.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if meta.get("capture_file") != "%s.pcapng" % meta.get("capture_id"):
        errors.append("capture_file does not match capture_id")
    if meta.get("status") not in ("complete", "recovered"):
        errors.append("status must be complete or recovered")
    for flow, entry in meta.get("flow_uid_map", {}).items():
        if not flow.isdigit() or int(flow) == 0:
            errors.append("bad flow id key %r" % flow)
        if entry.get("uid") is not None and not isinstance(entry.get("uid"), int):
            errors.append("flow %s: uid must be int or null" % flow)
    for uid, entry in meta.get("uid_map", {}).items():
        if not uid.lstrip("-").isdigit():
            errors.append("bad uid key %r" % uid)
        if not isinstance(entry.get("packages"), list):
            errors.append("uid %s: packages must be a list" % uid)
        if "class" not in entry:
            errors.append("uid %s: missing class" % uid)
    return errors


def join(pcap, meta):
    fmap = meta.get("flow_uid_map", {})
    umap = meta.get("uid_map", {})
    rows = []
    for r in pcap["records"]:
        uid, source = r["uid"], "comment"
        if uid is None and r["flow_id"]:
            entry = fmap.get(str(r["flow_id"]))
            if entry and entry.get("uid") is not None:
                uid, source = entry["uid"], "flow_uid_map"
        if uid is None:
            source = "unknown"
        app = umap.get(str(uid), {}) if uid is not None else {}
        row = {"timestamp_us": r["ts_us"], **decode_ip(r["data"]), "direction": r["dir"],
               "orig_len": r["orig_len"], "cap_len": r["cap_len"], "flow_id": r["flow_id"],
               "uid": "" if uid is None else uid, "uid_source": source,
               "packages": "|".join(app.get("packages", [])),
               "app_class": app.get("class", "unknown") if uid is not None else "unknown"}
        rows.append(row)
    return rows


def check_fixture(pcap_path, expected_path):
    exp = json.load(open(expected_path))
    p = read_pcapng(pcap_path)
    errs = []
    if len(p["interfaces"]) != 1:
        errs.append("expected one interface")
    iface = p["interfaces"][0]
    if iface["linktype"] != exp["linktype"] or iface["snaplen"] != exp["snaplen"]:
        errs.append("IDB mismatch %r" % iface)
    if len(p["records"]) != len(exp["records"]):
        errs.append("record count %d != %d" % (len(p["records"]), len(exp["records"])))
    for i, (r, e) in enumerate(zip(p["records"], exp["records"])):
        uid = e["uid"] if e["uid"] >= 0 else None
        for k, got, want in (("dir", r["dir"], e["dir"]), ("orig_len", r["orig_len"], e["orig_len"]),
                             ("cap_len", r["cap_len"], e["cap_len"]),
                             ("flow_id", r["flow_id"], e["flow_id"]), ("uid", r["uid"], uid),
                             ("ts_us", r["ts_us"], e["ts_us"])):
            if got != want:
                errs.append("record %d %s: got %r want %r" % (i + 1, k, got, want))
    # Retrospective join: early packets of flow 1 (before resolution) must resolve.
    meta = {"flow_uid_map": {k: {"uid": v} for k, v in exp["flow_uid_map"].items()},
            "uid_map": {"10234": {"packages": ["org.example.meet"], "class": "realtime_video"}}}
    rows = join(p, meta)
    for i, (row, e) in enumerate(zip(rows, exp["records"])):
        want = 10234 if e["flow_id"] == 1 else ""
        if row["uid"] != want:
            errs.append("join record %d uid %r want %r" % (i + 1, row["uid"], want))
        if e["flow_id"] == 1 and i < 2 and row["uid_source"] != "flow_uid_map":
            errs.append("record %d should resolve via flow_uid_map" % (i + 1))
    return errs


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    try:
        if cmd == "validate":
            p = read_pcapng(argv[2])
            print(json.dumps({"ok": True, "records": len(p["records"]), "interfaces": p["interfaces"],
                              "shb": p["shb"]}, default=str))
            return 0
        if cmd == "check-fixture":
            errs = check_fixture(argv[2], argv[3])
            for e in errs:
                print("FAIL:", e)
            print("OK" if not errs else "FAILED (%d)" % len(errs))
            return 1 if errs else 0
        if cmd == "validate-sidecar":
            errs = validate_sidecar(json.load(open(argv[2])))
            for e in errs:
                print("FAIL:", e)
            print("OK" if not errs else "FAILED (%d)" % len(errs))
            return 1 if errs else 0
        if cmd == "join":
            rows = join(read_pcapng(argv[2]), json.load(open(argv[3])))
            if "--csv" in argv:
                import csv
                if rows:
                    w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
                    w.writeheader()
                    w.writerows(rows)
            else:
                for r in rows:
                    print(json.dumps(r))
            return 0
    except FormatError as e:
        print("FORMAT ERROR:", e)
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
