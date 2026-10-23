#!/usr/bin/env python3
"""MiniPcap post-processing analyzer (Python 3.8+, standard library only).

Reads a session's `<id>.pcap` (Linux SLL, nanosecond PCAP) and `<id>.meta` (binary
metadata, docs/META_FORMAT.md) and reconstructs the device context of every packet:
application, radio, position, motion and network state. The input files are never
modified.

Commands:
  validate   <pcap> <meta>                     structural checks of both files
  dump       <meta> [--type NAME]              decoded metadata records as JSON lines
  summary    <pcap> <meta>                     counts, time span, sources, drops
  timeline   <pcap> <meta> [--csv] [options]   one enriched row per packet
  context-at <pcap> <meta> <time>              device context at a time (epoch s, ISO 8601, or boot:NS)
  export-pcapng <pcap> <meta> <out.pcapng>     PCAPNG copy with direction flags and context comments

Timeline options:
  --max-location-gap S   interpolate position only between fixes at most S seconds apart (default 5)
  --motion-window MS     window for acceleration/gyro statistics before each packet (default 1000)
  --stale-after S        mark sample-based values older than S seconds as stale (default 10)
"""
import bisect
import datetime
import ipaddress
import json
import math
import struct
import sys
import uuid

# ---------------------------------------------------------------- PCAP

SLL_DIR = {0: "downlink", 4: "uplink"}  # MiniPcap convention: HOST = DL, OUTGOING = UL


class FormatError(Exception):
    pass


def read_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        raise FormatError("pcap: file shorter than global header")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xA1B23C4D:
        e, nano = "<", True
    elif magic == 0xA1B2C3D4:
        e, nano = "<", False
    elif magic in (0x4D3CB2A1, 0xD4C3B2A1):
        e, nano = ">", magic == 0x4D3CB2A1
    else:
        raise FormatError("pcap: bad magic 0x%08x" % magic)
    vmaj, vmin, _, _, snaplen, linktype = struct.unpack_from(e + "HHiIII", data, 4)
    if linktype != 113:
        raise FormatError("pcap: link type %d, expected LINKTYPE_LINUX_SLL (113)" % linktype)
    packets = []
    off = 24
    truncated = 0
    while off + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack_from(e + "IIII", data, off)
        if off + 16 + incl > len(data):
            truncated = len(data) - off
            break
        if incl < 16 or incl > orig or (snaplen and incl > snaplen):
            raise FormatError("pcap: bad record lengths at offset %d" % off)
        rec = data[off + 16:off + 16 + incl]
        pkttype, hatype, alen = struct.unpack_from(">HHH", rec, 0)
        proto = struct.unpack_from(">H", rec, 14)[0]
        if pkttype not in SLL_DIR:
            raise FormatError("pcap: SLL packet type %d is not HOST(0)/OUTGOING(4)" % pkttype)
        ts_ns = sec * 10 ** 9 + (frac if nano else frac * 1000)
        packets.append({"index": len(packets), "ts_ns": ts_ns, "dir": SLL_DIR[pkttype], "sll_proto": proto,
                        "cap_len": incl - 16, "orig_len": orig - 16, "ip": rec[16:]})
        off += 16 + incl
    if off != len(data) and not truncated:
        truncated = len(data) - off
    return {"snaplen": snaplen, "ip_snaplen": max(snaplen - 16, 0), "nano": nano, "packets": packets,
            "truncated_bytes": truncated}


def decode_ip(data):
    """Best-effort 5-tuple from a (possibly truncated) IP prefix."""
    out = {"ipver": 0, "src": "", "dst": "", "proto": None, "sport": None, "dport": None}
    if not data:
        return out
    v = data[0] >> 4
    l4 = None
    proto = None
    if v == 4 and len(data) >= 20:
        ihl = (data[0] & 15) * 4
        out.update(ipver=4, src=str(ipaddress.IPv4Address(data[12:16])), dst=str(ipaddress.IPv4Address(data[16:20])))
        proto = data[9]
        if struct.unpack(">H", data[6:8])[0] & 0x1FFF == 0:
            l4 = ihl
    elif v == 6 and len(data) >= 40:
        out.update(ipver=6, src=str(ipaddress.IPv6Address(data[8:24])), dst=str(ipaddress.IPv6Address(data[24:40])))
        proto, l4 = data[6], 40
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
    out["proto"] = proto
    if proto in (6, 17) and l4 is not None and l4 + 4 <= len(data):
        out["sport"], out["dport"] = struct.unpack(">HH", data[l4:l4 + 4])
    return out


# ---------------------------------------------------------------- META

TYPES = {
    0x0001: "SESSION_INFO", 0x0002: "CLOCK_SYNC", 0x0003: "SESSION_END", 0x0004: "CAPTURE_STATS",
    0x0005: "DROPPED_EVENTS", 0x0006: "SENSOR_STATUS", 0x0010: "LOCATION", 0x0011: "GNSS_STATUS",
    0x0020: "MOTION_SAMPLE", 0x0030: "RADIO_STATE", 0x0031: "CELL_IDENTITY", 0x0032: "CELL_MEASUREMENT",
    0x0033: "SIGNAL_STRENGTH", 0x0040: "NETWORK_STATE", 0x0041: "WIFI_STATE", 0x0050: "UID_MAPPING",
    0x0051: "FLOW_MAPPING",
}
TYPE_IDS = {v: k for k, v in TYPES.items()}
TS_SOURCES = {0: "logger", 1: "sensor", 2: "location", 3: "modem", 4: "packet"}
RATS = {1: "GSM", 2: "WCDMA", 3: "TDSCDMA", 4: "CDMA", 5: "LTE", 6: "NR"}
MEAS_NAMES = {
    "LTE": ["rsrp", "rsrq", "rssnr", "rssi", "cqi", "ta"],
    "NR": ["ss_rsrp", "ss_rsrq", "ss_sinr", "csi_rsrp", "csi_rsrq", "csi_sinr"],
    "WCDMA": ["rscp", "ecno", "rssi"],
    "GSM": ["rssi", "ber", "ta"],
    "TDSCDMA": ["rscp"],
    "CDMA": ["cdma_dbm", "cdma_ecio", "evdo_dbm", "evdo_snr"],
}
SENSORS = {1: "accelerometer", 2: "gyroscope", 3: "linear_acceleration", 4: "gravity", 5: "magnetometer",
           6: "rotation_vector", 7: "pressure"}
SOURCES = {1: "location", 2: "gnss", 3: "accelerometer", 4: "gyroscope", 5: "radio", 6: "cell_info",
           7: "network", 8: "wifi", 9: "apps"}
STATES = {0: "active", 1: "unavailable", 2: "permission_denied", 3: "disabled_by_user",
          4: "disabled_in_system", 5: "error", 6: "stopped"}
PROVIDERS = {0: "unknown", 1: "gps", 2: "network", 3: "fused", 4: "passive"}
RESOLUTIONS = {1: "resolved_first_lookup", 2: "resolved_after_retry", 3: "unresolved_invalid_uid",
               4: "unresolved_session_ended"}
NETWORK_TYPES = {0: "UNKNOWN", 1: "GPRS", 2: "EDGE", 3: "UMTS", 8: "HSDPA", 9: "HSUPA", 10: "HSPA",
                 13: "LTE", 15: "HSPAP", 16: "GSM", 17: "TD_SCDMA", 18: "IWLAN", 20: "NR"}
OVERRIDES = {0: "NONE", 1: "LTE_CA", 2: "LTE_ADVANCED_PRO", 3: "NR_NSA", 4: "NR_NSA_MMWAVE", 5: "NR_ADVANCED"}
TRANSPORTS = {0: "cellular", 1: "wifi", 2: "bluetooth", 3: "ethernet", 4: "vpn", 5: "wifi_aware",
              6: "lowpan", 8: "usb", 9: "thread", 10: "satellite"}


class Reader:
    def __init__(self, data, off=0):
        self.d, self.o = data, off

    def take(self, fmt):
        v = struct.unpack_from("<" + fmt, self.d, self.o)
        self.o += struct.calcsize("<" + fmt)
        return v if len(v) > 1 else v[0]

    def bytes(self, n):
        v = self.d[self.o:self.o + n]
        if len(v) < n:
            raise struct.error("short read")
        self.o += n
        return v

    def str(self):
        n = self.take("H")
        return self.bytes(n).decode("utf-8", "replace")

    def strs(self):
        return [self.str() for _ in range(self.take("H"))]

    def counters(self):
        out = {}
        for _ in range(self.take("H")):
            k = self.str()
            out[k] = self.take("Q")
        return out


def _bits(p, i):
    return bool(p >> i & 1)


def _cells(r, kind):
    count, _ = r.take("HH")
    cells = []
    for _ in range(count):
        start = r.o
        elen, rat, st, p, ts = r.take("HBBIq")
        c = {"rat": RATS.get(rat, "RAT_%d" % rat), "registered": bool(st & 1),
             "conn": {0: "none", 1: "primary", 2: "secondary", 3: "unknown"}[st >> 1 & 3],
             "ts_ns": ts if _bits(p, 0) else None}
        if kind == "identity":
            mcc, mnc, digits = r.take("HHB")
            r.bytes(3)
            cid, pci, arfcn, tac, bw = r.take("qiiii")
            bands = [r.take("i") for _ in range(r.take("H"))]
            for i, (k, v) in enumerate((("mcc", mcc), ("mnc", mnc), ("cid", cid), ("pci", pci),
                                        ("arfcn", arfcn), ("tac", tac), ("bandwidth_khz", bw))):
                c[k] = v if _bits(p, i + 1) else None
            c["mnc_digits"] = digits
            c["bands"] = bands if _bits(p, 8) else None
        else:
            pci, arfcn, level = r.take("iii")
            m = r.take("8i")
            c.update(pci=pci if _bits(p, 1) else None, arfcn=arfcn if _bits(p, 2) else None,
                     level=level if _bits(p, 3) else None)
            names = MEAS_NAMES.get(c["rat"], [])
            for i in range(8):
                if _bits(p, 4 + i):
                    c[names[i] if i < len(names) else "m%d" % i] = m[i]
        r.o = start + elen  # skip unknown trailing fields
        cells.append(c)
    return cells


def decode_payload(rtype, payload):
    r = Reader(payload)
    name = TYPES.get(rtype)
    if name == "SESSION_INFO":
        return {r.str(): r.str() for _ in range(r.take("H"))}
    if name == "CLOCK_SYNC":
        real, reason = r.take("qB")
        return {"realtime_ns": real, "reason": {0: "start", 1: "periodic", 2: "time_changed",
                                                3: "timezone_changed", 4: "stop"}.get(reason, reason)}
    if name == "SESSION_END":
        st = r.take("B")
        return {"status": {1: "complete", 2: "recovered"}.get(st, st), "reason": r.str(), "counters": r.counters()}
    if name == "CAPTURE_STATS":
        return {"counters": r.counters()}
    if name == "DROPPED_EVENTS":
        t, reason, n, total = r.take("HHIQ")
        return {"record_type": TYPES.get(t, t), "reason": {1: "queue_full", 2: "too_large", 3: "write_error"}.get(reason, reason),
                "dropped": n, "total": total}
    if name == "SENSOR_STATUS":
        src, st, _ = r.take("HBB")
        return {"source": SOURCES.get(src, src), "status": STATES.get(st, st), "detail": r.str()}
    if name == "LOCATION":
        p, recv, lat, lon, alt, msl = r.take("Iqdddd")
        hacc, vacc, spd, spdacc, brg, brgacc = r.take("6f")
        prov, sats, _ = r.take("BBH")
        out = {"recv_ns": recv, "lat": lat, "lon": lon, "provider": PROVIDERS.get(prov, prov)}
        for i, (k, v) in enumerate((("alt_m", alt), ("msl_alt_m", msl), ("h_acc_m", hacc), ("v_acc_m", vacc),
                                    ("speed_mps", spd), ("speed_acc_mps", spdacc), ("bearing_deg", brg),
                                    ("bearing_acc_deg", brgacc), ("satellites_used", sats))):
            out[k] = v if _bits(p, i + 1) else None
        return out
    if name == "GNSS_STATUS":
        vis, used, cn0, const = r.take("HHfI")
        return {"satellites_visible": vis, "satellites_used": used,
                "mean_cn0_dbhz": None if math.isnan(cn0) else cn0, "constellations": const}
    if name == "MOTION_SAMPLE":
        sensor, acc, n, _ = r.take("BBBB")
        return {"sensor": SENSORS.get(sensor, sensor), "accuracy": acc, "values": list(r.take("%df" % n)) if n > 1
                else [r.take("f")] if n == 1 else []}
    if name == "RADIO_STATE":
        p, nt, ov, ds, da, ss = r.take("I5i")
        roam = r.take("B")
        r.bytes(3)
        op, opname = r.str(), r.str()
        vals = [("data_network_type", NETWORK_TYPES.get(nt, nt)), ("override", OVERRIDES.get(ov, ov)),
                ("data_state", ds), ("data_activity", da), ("service_state", ss), ("roaming", bool(roam)),
                ("operator", op), ("operator_name", opname)]
        return {k: (v if _bits(p, i) else None) for i, (k, v) in enumerate(vals)}
    if name == "CELL_IDENTITY":
        return {"cells": _cells(r, "identity")}
    if name in ("CELL_MEASUREMENT", "SIGNAL_STRENGTH"):
        return {"cells": _cells(r, "measurement")}
    if name == "NETWORK_STATE":
        tr, val, met, lost, _, down, up, sig, _ = r.take("IBBBBiiii")
        return {"transports": [TRANSPORTS.get(i, i) for i in range(32) if tr >> i & 1], "validated": bool(val),
                "metered": bool(met), "lost": bool(lost), "down_kbps": down, "up_kbps": up,
                "signal_strength": None if sig == -2147483648 else sig}
    if name == "WIFI_STATE":
        p, rssi, freq, link, tx, rx, std = r.take("I6i")
        bssid = r.bytes(6)
        out = {"connected": _bits(p, 0)}
        for i, (k, v) in enumerate((("rssi_dbm", rssi), ("freq_mhz", freq), ("link_mbps", link),
                                    ("tx_mbps", tx), ("rx_mbps", rx), ("standard", std))):
            out[k] = v if _bits(p, i + 1) else None
        out["bssid"] = ":".join("%02x" % x for x in bssid) if _bits(p, 7) else None
        return out
    if name == "UID_MAPPING":
        uid, _ = r.take("iI")
        return {"uid": uid, "class": r.str(), "class_source": r.str(), "note": r.str() or None,
                "packages": r.strs(), "app_names": r.strs()}
    if name == "FLOW_MAPPING":
        fid, first, ipver, proto, lport, rport, _ = r.take("QqBBHHH")
        local, remote = r.bytes(16), r.bytes(16)
        uid, res, att, _, lat, _ = r.take("iBBHII")
        a = ipaddress.IPv4Address if ipver == 4 else ipaddress.IPv6Address
        n = 4 if ipver == 4 else 16
        return {"flow_id": fid, "first_seen_ns": first, "ipver": ipver, "proto": proto,
                "local": str(a(local[:n])), "lport": lport, "remote": str(a(remote[:n])), "rport": rport,
                "uid": None if uid < 0 else uid, "resolution": RESOLUTIONS.get(res, res), "attempts": att,
                "latency_ms": lat}
    return {"raw": payload.hex()}


def read_meta(path, strict=True):
    data = open(path, "rb").read()
    if len(data) < 64 or data[:8] != b"MPCMETA\0":
        raise FormatError("meta: bad magic")
    major, minor, hlen = struct.unpack_from("<HHI", data, 8)
    if major != 1:
        raise FormatError("meta: unsupported major version %d" % major)
    sid = str(uuid.UUID(bytes=data[16:32]))
    anchor_boot, anchor_real, start_boot = struct.unpack_from("<qqq", data, 32)
    recs = []
    off = hlen
    truncated = 0
    while off + 16 <= len(data):
        rtype, flags, length, ts = struct.unpack_from("<HHIq", data, off)
        if length < 16 or length % 8 or off + length > len(data):
            truncated = len(data) - off
            break
        payload = data[off + 16:off + length]
        try:
            body = decode_payload(rtype, payload)
        except (struct.error, KeyError, ValueError) as e:
            if strict:
                raise FormatError("meta: cannot decode %s at offset %d: %s" % (TYPES.get(rtype, rtype), off, e))
            body = {"decode_error": str(e)}
        recs.append({"type": TYPES.get(rtype, "TYPE_0x%04x" % rtype), "type_id": rtype, "ts_ns": ts,
                     "ts_source": TS_SOURCES.get(flags & 7, flags & 7), "refresh": bool(flags & 8), **body})
        off += length
    if off < len(data) and not truncated:
        truncated = len(data) - off
    return {"version": "%d.%d" % (major, minor), "session_id": sid, "anchor_boot_ns": anchor_boot,
            "anchor_real_ns": anchor_real, "start_boot_ns": start_boot, "records": recs,
            "truncated_bytes": truncated}


# ---------------------------------------------------------------- correlation

class Series:
    """Records of one kind sorted by monotonic time, with latest-before lookup."""

    def __init__(self, recs):
        self.recs = sorted(recs, key=lambda r: r["ts_ns"])
        self.ts = [r["ts_ns"] for r in self.recs]

    def latest(self, t):
        i = bisect.bisect_right(self.ts, t) - 1
        return self.recs[i] if i >= 0 else None

    def around(self, t):
        i = bisect.bisect_right(self.ts, t)
        return (self.recs[i - 1] if i > 0 else None), (self.recs[i] if i < len(self.recs) else None)

    def window(self, t0, t1):
        return self.recs[bisect.bisect_left(self.ts, t0):bisect.bisect_right(self.ts, t1)]


class Session:
    def __init__(self, pcap, meta, max_location_gap_s=5.0, motion_window_ms=1000, stale_after_s=10.0):
        self.pcap, self.meta = pcap, meta
        self.max_gap = int(max_location_gap_s * 1e9)
        self.motion_win = int(motion_window_ms * 1e6)
        self.stale = int(stale_after_s * 1e9)
        by = {}
        for r in meta["records"]:
            by.setdefault(r["type"], []).append(r)
        self.by = by
        self.series = {k: Series(v) for k, v in by.items()}
        self.motion = {}
        for r in by.get("MOTION_SAMPLE", []):
            self.motion.setdefault(r["sensor"], []).append(r)
        self.motion = {k: Series(v) for k, v in self.motion.items()}
        self.uids = {}
        for r in by.get("UID_MAPPING", []):
            self.uids[r["uid"]] = r
        self.flows = {}
        for r in by.get("FLOW_MAPPING", []):
            key = (r["ipver"], r["proto"], r["local"], r["lport"], r["remote"], r["rport"])
            self.flows.setdefault(key, []).append(r)
        for v in self.flows.values():
            v.sort(key=lambda r: r["first_seen_ns"])
        self.cell_identity = Series(by.get("CELL_IDENTITY", []))

    def boot_ns(self, pkt):
        """Exact inverse of the native PCAP timestamp conversion."""
        return pkt["ts_ns"] - self.meta["anchor_real_ns"] + self.meta["anchor_boot_ns"]

    def to_boot(self, epoch_ns):
        return epoch_ns - self.meta["anchor_real_ns"] + self.meta["anchor_boot_ns"]

    def to_epoch(self, boot_ns):
        return boot_ns - self.meta["anchor_boot_ns"] + self.meta["anchor_real_ns"]

    def flow_for(self, pkt, t):
        ip = decode_ip(pkt["ip"])
        if ip["proto"] not in (6, 17) or ip["sport"] is None:
            return ip, None
        if pkt["dir"] == "uplink":
            key = (ip["ipver"], ip["proto"], ip["src"], ip["sport"], ip["dst"], ip["dport"])
        else:
            key = (ip["ipver"], ip["proto"], ip["dst"], ip["dport"], ip["src"], ip["sport"])
        cands = self.flows.get(key)
        if not cands:
            return ip, None
        best = None
        for f in cands:  # latest generation that started at or before this packet
            if f["first_seen_ns"] <= t:
                best = f
            else:
                break
        return ip, best

    def _age_ms(self, rec, t, key="ts_ns"):
        return None if rec is None else round((t - rec[key]) / 1e6, 3)

    def location_at(self, t):
        s = self.series.get("LOCATION")
        if not s:
            return {"status": "no_data"}
        a, b = s.around(t)
        if a is not None and b is not None and b["ts_ns"] - a["ts_ns"] <= self.max_gap and b["ts_ns"] > a["ts_ns"]:
            f = (t - a["ts_ns"]) / (b["ts_ns"] - a["ts_ns"])
            lat = a["lat"] + (b["lat"] - a["lat"]) * f
            lon = a["lon"] + (b["lon"] - a["lon"]) * f
            alt = None if a["alt_m"] is None or b["alt_m"] is None else a["alt_m"] + (b["alt_m"] - a["alt_m"]) * f
            return {"status": "interpolated", "lat": lat, "lon": lon, "alt_m": alt,
                    "h_acc_m": max(x for x in (a["h_acc_m"], b["h_acc_m"]) if x is not None)
                    if a["h_acc_m"] is not None or b["h_acc_m"] is not None else None,
                    "speed_mps": a["speed_mps"], "bearing_deg": a["bearing_deg"],
                    "fix_age_ms": self._age_ms(a, t), "next_fix_in_ms": round((b["ts_ns"] - t) / 1e6, 3)}
        if a is None:
            return {"status": "before_first_fix"}
        age = t - a["ts_ns"]
        return {"status": "stale" if age > self.max_gap else "latest", "lat": a["lat"], "lon": a["lon"],
                "alt_m": a["alt_m"], "h_acc_m": a["h_acc_m"], "speed_mps": a["speed_mps"],
                "bearing_deg": a["bearing_deg"], "fix_age_ms": self._age_ms(a, t)}

    def motion_at(self, t):
        out = {}
        for sensor in ("accelerometer", "linear_acceleration", "gyroscope"):
            s = self.motion.get(sensor)
            if not s:
                continue
            w = s.window(t - self.motion_win, t)
            if not w:
                last = s.latest(t)
                out[sensor] = {"status": "no_samples_in_window",
                               "last_sample_age_ms": self._age_ms(last, t)}
                continue
            mags = [math.sqrt(sum(v * v for v in r["values"][:3])) for r in w]
            out[sensor] = {"samples": len(w), "mean_magnitude": sum(mags) / len(mags), "max_magnitude": max(mags),
                           "last": w[-1]["values"][:3]}
        return out

    def _sample(self, kind, t):
        s = self.series.get(kind)
        r = s.latest(t) if s else None
        if r is None:
            return None
        ts = r["ts_ns"]
        age = t - ts
        return r, round(age / 1e6, 3), age > self.stale

    def context_at(self, t):
        ctx = {"boot_ns": t, "time_utc": iso(self.to_epoch(t))}
        ci = self.cell_identity.latest(t)
        ctx["serving_cells"] = [c for c in ci["cells"] if c["registered"]] if ci else None
        ctx["cell_identity_age_ms"] = self._age_ms(ci, t)
        for kind, key in (("CELL_MEASUREMENT", "cell_measurement"), ("SIGNAL_STRENGTH", "signal_strength")):
            got = self._sample(kind, t)
            ctx[key] = None if got is None else {"cells": got[0]["cells"], "age_ms": got[1], "stale": got[2]}
        for kind, key in (("RADIO_STATE", "radio_state"), ("NETWORK_STATE", "network"), ("WIFI_STATE", "wifi"),
                          ("GNSS_STATUS", "gnss")):
            r = self.series[kind].latest(t) if kind in self.series else None
            if r is None:
                ctx[key] = None
            else:
                ctx[key] = {k: v for k, v in r.items() if k not in ("type", "type_id")}
                ctx[key]["age_ms"] = self._age_ms(r, t)
        ctx["location"] = self.location_at(t)
        ctx["motion"] = self.motion_at(t)
        return ctx

    def timeline(self):
        rows = []
        for p in self.pcap["packets"]:
            t = self.boot_ns(p)
            ip, flow = self.flow_for(p, t)
            uid = flow["uid"] if flow else None
            app = self.uids.get(uid) if uid is not None else None
            loc = self.location_at(t)
            ci = self.cell_identity.latest(t)
            serving = next((c for c in (ci["cells"] if ci else []) if c["registered"]), None)
            sig = self._sample("SIGNAL_STRENGTH", t)
            meas = self._sample("CELL_MEASUREMENT", t)
            srv_meas = None
            if meas:
                srv_meas = next((c for c in meas[0]["cells"] if c["registered"]), None)
            srv_sig = sig[0]["cells"][0] if sig and sig[0]["cells"] else None
            radio = self.series["RADIO_STATE"].latest(t) if "RADIO_STATE" in self.series else None
            net = self.series["NETWORK_STATE"].latest(t) if "NETWORK_STATE" in self.series else None
            wifi = self.series["WIFI_STATE"].latest(t) if "WIFI_STATE" in self.series else None
            mot = self.motion_at(t)
            acc = mot.get("linear_acceleration") or mot.get("accelerometer") or {}
            gyr = mot.get("gyroscope") or {}
            sigsrc = srv_sig or srv_meas or {}
            rows.append({
                "packet": p["index"] + 1, "time_utc": iso(p["ts_ns"]), "boot_ns": t, "direction": p["dir"],
                "orig_len": p["orig_len"], "cap_len": p["cap_len"],
                "src": ip["src"], "dst": ip["dst"], "proto": {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(ip["proto"], ip["proto"] or ""),
                "sport": ip["sport"] if ip["sport"] is not None else "", "dport": ip["dport"] if ip["dport"] is not None else "",
                "flow_id": flow["flow_id"] if flow else "", "uid": "" if uid is None else uid,
                "app_status": ("resolved" if uid is not None else flow["resolution"] if flow
                               else "no_flow_mapping" if ip["sport"] is not None else "not_tcp_udp"),
                "packages": "|".join(app["packages"]) if app else "", "app_class": app["class"] if app else "",
                "transport": "|".join(net["transports"]) if net else "",
                "data_rat": radio["data_network_type"] if radio and radio["data_network_type"] is not None else "",
                "rat_override": radio["override"] if radio and radio["override"] is not None else "",
                "serving_rat": serving["rat"] if serving else "", "serving_pci": serving["pci"] if serving and serving["pci"] is not None else "",
                "serving_arfcn": serving["arfcn"] if serving and serving["arfcn"] is not None else "",
                "serving_cid": serving["cid"] if serving and serving["cid"] is not None else "",
                "rsrp_dbm": _first(sigsrc, "rsrp", "ss_rsrp", "rscp", "rssi"),
                "rsrq_db": _first(sigsrc, "rsrq", "ss_rsrq", "ecno"),
                "sinr_db": _first(sigsrc, "rssnr", "ss_sinr"),
                "signal_age_ms": (sig or meas or (None, ""))[1] if (sig or meas) else "",
                "signal_stale": (sig or meas)[2] if (sig or meas) else "",
                "neighbor_cells": sum(1 for c in meas[0]["cells"] if not c["registered"]) if meas else "",
                "wifi_rssi_dbm": wifi["rssi_dbm"] if wifi and wifi["rssi_dbm"] is not None else "",
                "lat": loc.get("lat", ""), "lon": loc.get("lon", ""), "alt_m": _nz(loc.get("alt_m")),
                "h_acc_m": _nz(loc.get("h_acc_m")), "speed_mps": _nz(loc.get("speed_mps")),
                "location_status": loc["status"], "fix_age_ms": _nz(loc.get("fix_age_ms")),
                "acc_mean_mps2": _nz(acc.get("mean_magnitude")), "acc_max_mps2": _nz(acc.get("max_magnitude")),
                "gyro_mean_rads": _nz(gyr.get("mean_magnitude")),
            })
        return rows


def _first(d, *keys):
    for k in keys:
        if d.get(k) is not None:
            return d[k]
    return ""


def _nz(v):
    return "" if v is None else v


def iso(epoch_ns):
    dt = datetime.datetime.fromtimestamp(epoch_ns // 10 ** 9, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%09dZ" % (epoch_ns % 10 ** 9)


def parse_time(s, session):
    if s.startswith("boot:"):
        return int(s[5:])
    try:
        return session.to_boot(int(round(float(s) * 1e9)))
    except ValueError:
        pass
    dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return session.to_boot(int(round(dt.timestamp() * 1e9)))


# ---------------------------------------------------------------- validation / summary / export

def validate(pcap, meta, pcap_path=None):
    errs, warns = [], []
    recs = meta["records"]
    if pcap_path is not None:
        stem = pcap_path.rsplit("/", 1)[-1].split(".", 1)[0]
        if stem != meta["session_id"]:
            warns.append("pcap file name %r does not match session id %s" % (stem, meta["session_id"]))
    if not recs or recs[0]["type"] != "SESSION_INFO":
        errs.append("first record is not SESSION_INFO")
    ends = [r for r in recs if r["type"] == "SESSION_END"]
    if len(ends) != 1 or recs[-1]["type"] != "SESSION_END":
        errs.append("expected exactly one SESSION_END as the last record (found %d)" % len(ends))
    if meta["truncated_bytes"]:
        errs.append("meta has %d trailing bytes after the last complete record" % meta["truncated_bytes"])
    if pcap["truncated_bytes"]:
        errs.append("pcap has %d trailing bytes after the last complete record" % pcap["truncated_bytes"])
    prev = None
    for p in pcap["packets"]:
        if prev is not None and p["ts_ns"] < prev:
            warns.append("packet %d timestamp earlier than previous" % (p["index"] + 1))
            break
        prev = p["ts_ns"]
    seen = set()
    for r in recs:
        if r["type"] == "FLOW_MAPPING":
            if r["flow_id"] in seen:
                errs.append("duplicate FLOW_MAPPING for flow %d" % r["flow_id"])
            seen.add(r["flow_id"])
        if r["type"].startswith("TYPE_"):
            warns.append("unknown record type %s skipped" % r["type"])
    # Every TCP/UDP record must contain its complete transport header (the logger never
    # cuts inside headers, whatever the configured length).
    short = 0
    for p in pcap["packets"]:
        ip = decode_ip(p["ip"])
        if ip["proto"] in (6, 17) and ip["sport"] is not None:
            need = transport_end(p["ip"])
            if need is not None and p["cap_len"] < min(need, p["orig_len"]):
                short += 1
    if short:
        errs.append("%d TCP/UDP records end inside their transport header" % short)
    return errs, warns


def transport_end(data):
    """Offset just past the TCP/UDP header, or None if it cannot be determined."""
    v = data[0] >> 4 if data else 0
    if v == 4 and len(data) >= 20:
        l4, proto = (data[0] & 15) * 4, data[9]
    elif v == 6 and len(data) >= 40:
        l4, proto = 40, data[6]
        while proto in (0, 43, 60, 44) and l4 + 8 <= len(data):
            proto, l4 = data[l4], l4 + (8 if proto == 44 else (data[l4 + 1] + 1) * 8)
    else:
        return None
    if proto == 17:
        return l4 + 8
    if proto == 6 and l4 + 13 <= len(data):
        return l4 + max(20, (data[l4 + 12] >> 4) * 4)
    return None


def summary(pcap, meta):
    s = Session(pcap, meta)
    counts = {}
    for r in meta["records"]:
        counts[r["type"]] = counts.get(r["type"], 0) + 1
    rows = s.timeline()
    attributed = sum(1 for r in rows if r["uid"] != "")
    pk = pcap["packets"]
    end = next((r for r in meta["records"] if r["type"] == "SESSION_END"), None)
    status = {}
    for r in s.by.get("SENSOR_STATUS", []):
        status[r["source"]] = r["status"] + (" (%s)" % r["detail"] if r["detail"] else "")
    return {
        "session_id": meta["session_id"], "meta_version": meta["version"],
        "packets": len(pk), "uplink": sum(1 for p in pk if p["dir"] == "uplink"),
        "downlink": sum(1 for p in pk if p["dir"] == "downlink"),
        "first_packet_utc": iso(pk[0]["ts_ns"]) if pk else None, "last_packet_utc": iso(pk[-1]["ts_ns"]) if pk else None,
        "packets_with_app": attributed, "flows": len(s.by.get("FLOW_MAPPING", [])),
        "apps": {str(u): "|".join(r["packages"]) for u, r in sorted(s.uids.items())},
        "metadata_records": counts, "sources": status,
        "metadata_dropped": sum(r["dropped"] for r in s.by.get("DROPPED_EVENTS", [])),
        "end": None if end is None else {"status": end["status"], "reason": end["reason"]},
        "capture_queue_drops": None if end is None else
        end["counters"].get("capture_queue_drops_ul", 0) + end["counters"].get("capture_queue_drops_dl", 0),
    }


def export_pcapng(pcap, meta, out_path):
    """Enriched copy: raw IP packets, epb_flags direction, and a comment with app and radio context."""
    s = Session(pcap, meta)

    def opt(code, val):
        return struct.pack("<HH", code, len(val)) + val + b"\0" * (-len(val) % 4)

    def block(btype, body):
        return struct.pack("<II", btype, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))

    info = s.by.get("SESSION_INFO", [{}])[0]
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
                + opt(2, ("%s %s" % (info.get("device_manufacturer", ""), info.get("device_model", ""))).encode())
                + opt(3, ("Android %s" % info.get("android_release", "")).encode())
                + opt(4, ("mpcanalyze export of %s" % meta["session_id"]).encode()) + opt(0, b""))
    idb = block(1, struct.pack("<HHI", 101, 0, pcap["ip_snaplen"]) + opt(2, b"tun0") + opt(9, b"\x09") + opt(0, b""))
    with open(out_path, "wb") as f:
        f.write(shb + idb)
        for p, row in zip(pcap["packets"], s.timeline()):
            parts = []
            if row["uid"] != "":
                parts.append("app=%s" % (row["packages"] or row["uid"]))
            if row["serving_rat"]:
                parts.append("cell=%s/%s" % (row["serving_rat"], row["serving_pci"]))
            if row["rsrp_dbm"] != "":
                parts.append("rsrp=%s(%sms)" % (row["rsrp_dbm"], row["signal_age_ms"]))
            if row["lat"] != "":
                parts.append("pos=%.6f,%.6f" % (row["lat"], row["lon"]))
            comment = ";".join(parts).encode()
            ts = p["ts_ns"]
            data = p["ip"] + b"\0" * (-len(p["ip"]) % 4)
            opts = (opt(1, comment) if comment else b"") + opt(2, struct.pack("<I", 2 if p["dir"] == "uplink" else 1)) + opt(0, b"")
            f.write(block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, p["cap_len"], p["orig_len"]) + data + opts))
    return len(pcap["packets"])


# ---------------------------------------------------------------- CLI

def _opt(argv, name, default):
    if name in argv:
        return float(argv[argv.index(name) + 1])
    return default


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    try:
        if cmd == "dump":
            meta = read_meta(argv[2], strict=False)
            want = argv[argv.index("--type") + 1] if "--type" in argv else None
            hdr = {k: v for k, v in meta.items() if k != "records"}
            print(json.dumps({"header": hdr}))
            for r in meta["records"]:
                if want is None or r["type"] == want:
                    print(json.dumps(r, default=str))
            return 0
        pcap, meta = read_pcap(argv[2]), read_meta(argv[3])
        if cmd == "validate":
            errs, warns = validate(pcap, meta, argv[2])
            for w in warns:
                print("WARN:", w)
            for e in errs:
                print("FAIL:", e)
            print(json.dumps({"ok": not errs, "packets": len(pcap["packets"]), "records": len(meta["records"]),
                              "session_id": meta["session_id"]}))
            return 1 if errs else 0
        if cmd == "summary":
            print(json.dumps(summary(pcap, meta), indent=1))
            return 0
        s = Session(pcap, meta, _opt(argv, "--max-location-gap", 5.0), _opt(argv, "--motion-window", 1000),
                    _opt(argv, "--stale-after", 10.0))
        if cmd == "timeline":
            rows = s.timeline()
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
        if cmd == "context-at":
            print(json.dumps(s.context_at(parse_time(argv[4], s)), indent=1, default=str))
            return 0
        if cmd == "export-pcapng":
            n = export_pcapng(pcap, meta, argv[4])
            print("wrote %d packets to %s" % (n, argv[4]))
            return 0
    except FormatError as e:
        print("FORMAT ERROR:", e)
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
