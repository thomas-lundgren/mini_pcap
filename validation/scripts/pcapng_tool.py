#!/usr/bin/env python3
"""Independent PCAPNG reader/validator and packet/context/app join tool (stdlib only).

Written separately from the native writer so it can serve as an independent
check of the binary format and of the per-packet metadata grammar.

Interface 0 (tun0, LINKTYPE_RAW) holds packets. Their comment (v2) is
    comment := item (";" item)*      keys in this order, each at most once:
    item    := "u=" UID | "f=" FLOW | "c=" CONTEXT
(u = app UID when known, f = flow ID, c = seq of the context record in effect;
no f => no flow, e.g. ICMP/fragment). The v1 form "u-UID;f-FLOW" is also accepted.

Interface 1 (ctx0, LINKTYPE_WIRESHARK_UPPER_PDU) holds JSON records:
    {"type": "context", "seq": N, ...}  position / motion / network / cellular / wifi
    {"type": "app", "uid": U, ...}      app identity, written when a UID is first seen

Commands:
    validate <file.pcapng>                          strict structural validation
    check-fixture <file.pcapng> <expected.json>     compare records with native test expectations
    validate-sidecar <file.meta.json>               sidecar contract checks
    join <file.pcapng> [<file.meta.json>] [--csv]   one row per packet with app and context columns
    contexts <file.pcapng> [--csv]                  one row per context record
"""
import ipaddress
import json
import re
import struct
import sys

BT_SHB, BT_IDB, BT_EPB = 0x0A0D0D0A, 0x00000001, 0x00000006
LT_RAW, LT_UPPER_PDU = 101, 252
COMMENT_V1_RE = re.compile(r"^(?:u-(\d+)(?:;f-(\d+))?|f-(\d+))$")
COMMENT_V2_RE = re.compile(r"^(?:u=(\d+))?(?:(?:^|;)f=(\d+))?(?:(?:^|;)c=(\d+))?$")


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
    """Returns (uid or None, flow_id, ctx_seq or None); raises on bad syntax."""
    if c is None:
        return None, 0, None
    if "=" in c:
        m = COMMENT_V2_RE.match(c)
        if not m or not c or c.startswith(";"):
            raise FormatError("comment does not match v2 grammar: %r" % c)
        uid, flow, ctx = m.groups()
        return (int(uid) if uid else None), int(flow or 0), (int(ctx) if ctx else None)
    m = COMMENT_V1_RE.match(c)
    if not m:
        raise FormatError("comment does not match v1/v2 grammar: %r" % c)
    if m.group(3) is not None:
        return None, int(m.group(3)), None
    return int(m.group(1)), int(m.group(2) or 0), None


def parse_upper_pdu(data):
    """Wireshark exported-PDU tags (big endian, unpadded) -> (tags dict, payload)."""
    off, tags = 0, {}
    while True:
        if off + 4 > len(data):
            raise FormatError("truncated upper-PDU tag")
        tag, length = struct.unpack_from(">HH", data, off)
        off += 4
        if tag == 0:
            break
        if off + length > len(data):
            raise FormatError("upper-PDU tag overruns record")
        tags[tag] = data[off:off + length]
        off += length
    return tags, data[off:]


def read_pcapng(path, strict=True):
    data = open(path, "rb").read()
    off = 0
    endian = "<"
    interfaces = []
    records = []
    contexts = []
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
            ts = (ts_hi << 32) | ts_lo
            ts_us = ts * 10 ** 6 // 10 ** iface["tsresol"]
            payload = data[pkt_off:pkt_off + cap_len]
            if iface["linktype"] == LT_UPPER_PDU:
                tags, body = parse_upper_pdu(payload)
                if tags.get(12) != b"json":
                    raise FormatError("context record is not tagged for the json dissector")
                try:
                    obj = json.loads(body.decode("utf-8"))
                except ValueError as e:
                    raise FormatError("context record is not valid JSON: %s" % e)
                contexts.append({"ts_us": ts_us, "info": tags.get(36, b"").decode("utf-8", "replace"),
                                 "json": obj, "index": len(records) + len(contexts)})
                off += total
                continue
            uid, flow_id, ctx = parse_comment(comment)
            if strict and ctx is not None:
                known = [x["json"].get("seq") for x in contexts if x["json"].get("type") == "context"]
                if ctx not in known:
                    raise FormatError("packet references context %d before it was written" % ctx)
            direction = {1: "downlink", 2: "uplink"}.get((flags or 0) & 3, "unknown")
            records.append({"ts": ts, "ts_us": ts_us, "if_id": if_id,
                            "cap_len": cap_len, "orig_len": orig_len,
                            "data": payload, "comment": comment,
                            "flags": flags, "dir": direction, "uid": uid, "flow_id": flow_id,
                            "ctx": ctx})
        else:
            pass  # unknown block types are skipped per spec
        off += total
    if shb is None:
        raise FormatError("no Section Header Block")
    return {"shb": shb, "interfaces": interfaces, "records": records, "contexts": contexts}


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
    if meta.get("schema_version") not in (1, 2):
        errors.append("schema_version must be 1 or 2")
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


def _first(d, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) is not None:
            return d[k]
    return ""


def context_columns(ctx):
    """Flat, analysis-friendly subset of one context record (full JSON stays in the file)."""
    if ctx is None:
        return {k: "" for k in CONTEXT_COLUMNS}
    loc = ctx.get("location") or {}
    mot = ctx.get("motion") or {}
    net = ctx.get("network") or {}
    cel = ctx.get("cellular") or {}
    wifi = ctx.get("wifi") or {}
    serving = (cel.get("serving") or [{}])[0]
    return {
        "lat": _first(loc, "lat"), "lon": _first(loc, "lon"), "alt_m": _first(loc, "alt_m"),
        "h_acc_m": _first(loc, "h_acc_m"), "speed_mps": _first(loc, "speed_mps"),
        "bearing_deg": _first(loc, "bearing_deg"), "fix_age_ms": _first(loc, "fix_age_ms"),
        "lin_acc_mean_mps2": _first(mot, "lin_acc_mean_mps2"), "gyro_mean_rads": _first(mot, "gyro_mean_rads"),
        "transport": _first(net, "default_transport"),
        "data_rat": _first(cel, "data_rat"), "rat_override": _first(cel, "override"),
        "serving_rat": _first(serving, "rat"), "serving_pci": _first(serving, "pci", "psc", "bsic"),
        "serving_arfcn": _first(serving, "arfcn"),
        "serving_dbm": _first(serving, "rsrp", "ss_rsrp", "rscp", "rssi"),
        "serving_quality_db": _first(serving, "rsrq", "ss_rsrq", "ecno"),
        "serving_sinr_db": _first(serving, "rssnr", "ss_sinr"),
        "neighbor_cells": len(cel.get("neighbors") or []) if cel else "",
        "cell_info_age_ms": _first(cel, "info_age_ms"),
        "wifi_rssi_dbm": _first(wifi, "rssi_dbm"), "wifi_freq_mhz": _first(wifi, "freq_mhz"),
    }


CONTEXT_COLUMNS = list(context_columns({}).keys())


def join(pcap, meta=None):
    """One row per packet. App identity comes from the packet comment, then the sidecar's
    flow_uid_map; app names from the in-file app records, then the sidecar's uid_map."""
    meta = meta or {}
    fmap = meta.get("flow_uid_map", {})
    umap = dict(meta.get("uid_map", {}))
    ctx_by_seq = {}
    for c in pcap.get("contexts", []):
        j = c["json"]
        if j.get("type") == "app" and j.get("uid") is not None:
            umap[str(j["uid"])] = j
        elif j.get("type") == "context" and j.get("seq") is not None:
            ctx_by_seq[j["seq"]] = (c["ts_us"], j)
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
        ctx_ts, ctx = ctx_by_seq.get(r["ctx"], (None, None)) if r["ctx"] is not None else (None, None)
        row = {"timestamp_us": r["ts_us"], **decode_ip(r["data"]), "direction": r["dir"],
               "orig_len": r["orig_len"], "cap_len": r["cap_len"], "flow_id": r["flow_id"],
               "uid": "" if uid is None else uid, "uid_source": source,
               "packages": "|".join(app.get("packages", [])),
               "app_class": app.get("class", "unknown") if uid is not None else "unknown",
               "ctx_seq": "" if r["ctx"] is None else r["ctx"],
               "ctx_age_ms": "" if ctx_ts is None else (r["ts_us"] - ctx_ts) // 1000,
               **context_columns(ctx)}
        rows.append(row)
    return rows


def context_rows(pcap):
    rows = []
    for c in pcap.get("contexts", []):
        j = c["json"]
        rows.append({"timestamp_us": c["ts_us"], "type": j.get("type", ""), "seq": j.get("seq", ""),
                     "info": c["info"], **(context_columns(j) if j.get("type") == "context"
                                           else {k: "" for k in CONTEXT_COLUMNS})})
    return rows


def check_fixture(pcap_path, expected_path):
    exp = json.load(open(expected_path))
    p = read_pcapng(pcap_path)
    errs = []
    if [i["linktype"] for i in p["interfaces"]] != [exp["linktype"], LT_UPPER_PDU]:
        errs.append("expected interfaces tun0 (raw) + ctx0 (upper PDU): %r" % p["interfaces"])
    iface = p["interfaces"][0]
    if iface["linktype"] != exp["linktype"] or iface["snaplen"] != exp["snaplen"]:
        errs.append("IDB mismatch %r" % iface)
    if len(p["contexts"]) != len(exp["contexts"]):
        errs.append("context count %d != %d" % (len(p["contexts"]), len(exp["contexts"])))
    for i, (c, e) in enumerate(zip(p["contexts"], exp["contexts"])):
        if c["json"] != json.loads(e["json"]) or c["info"] != e["info"] or c["ts_us"] != e["ts_us"]:
            errs.append("context %d mismatch: %r" % (i + 1, c))
    # Each packet's c= must be the latest STATE context written before it in the file.
    order = sorted([(c["index"], "c", c) for c in p["contexts"]] +
                   [(i, "p", None) for i in range(len(p["records"]) + len(p["contexts"]))
                    if i not in {c["index"] for c in p["contexts"]}], key=lambda t: t[0])
    cur, pk = None, 0
    for _, kind, c in order:
        if kind == "c":
            if c["json"].get("type") == "context":
                cur = c["json"]["seq"]
        else:
            if pk < len(p["records"]) and p["records"][pk]["ctx"] != cur:
                errs.append("record %d c=%r but context in effect is %r" % (pk + 1, p["records"][pk]["ctx"], cur))
            pk += 1
    if len(p["records"]) != len(exp["records"]):
        errs.append("record count %d != %d" % (len(p["records"]), len(exp["records"])))
    for i, (r, e) in enumerate(zip(p["records"], exp["records"])):
        uid = e["uid"] if e["uid"] >= 0 else None
        for k, got, want in (("dir", r["dir"], e["dir"]), ("orig_len", r["orig_len"], e["orig_len"]),
                             ("cap_len", r["cap_len"], e["cap_len"]),
                             ("flow_id", r["flow_id"], e["flow_id"]), ("uid", r["uid"], uid),
                             ("ctx", r["ctx"], e["ctx"] or None), ("ts_us", r["ts_us"], e["ts_us"])):
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
            print(json.dumps({"ok": True, "records": len(p["records"]), "contexts": len(p["contexts"]),
                              "interfaces": p["interfaces"], "shb": p["shb"]}, default=str))
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
        if cmd in ("join", "contexts"):
            pcap = read_pcapng(argv[2])
            if cmd == "join":
                metas = [a for a in argv[3:] if not a.startswith("--")]
                rows = join(pcap, json.load(open(metas[0])) if metas else None)
            else:
                rows = context_rows(pcap)
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
