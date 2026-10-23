#!/usr/bin/env python3
"""MiniPcap post-processing analyzer (Python 3.8+, standard library only).

Reads a session's `<id>.pcap` (Linux SLL, nanosecond PCAP) and `<id>.meta` (binary
metadata, docs/META_FORMAT.md) and reconstructs the device context of every packet:
application, radio, position, motion and network state. Inputs are never modified.
Packets are streamed (memory stays flat for multi-GB captures); metadata is loaded once.

Commands:
  validate      <pcap> <meta>                 structural and contract checks of both files
  dump          <meta> [--type NAME]          decoded metadata records as JSON lines
  summary       <pcap> <meta>                 counts, time span, apps, sources, losses
  timeline      <pcap> <meta> [--csv]         one enriched row per packet (streamed)
  context-at    <pcap> <meta> <time>          device context at a time (epoch s, ISO 8601, or boot:NS)
  export-pcapng <pcap> <meta> <out.pcapng>    PCAPNG copy with direction flags and context comments

Correlation options (timeline, context-at, export-pcapng, summary):
  --max-location-gap S   interpolate position only between fixes at most S seconds apart (default 5)
  --motion-window MS     window for acceleration/gyro statistics before each packet (default 1000)
  --stale-after S        mark sample-based radio values older than S seconds as stale (default 10)
"""
import argparse
import bisect
import collections
import datetime
import ipaddress
import json
import math
import mmap
import struct
import sys
import uuid

SLL_DIR = {0: "downlink", 4: "uplink"}  # MiniPcap convention: HOST = DL, OUTGOING = UL
PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}
UDP_IDLE_NS = 128 * 10 ** 9  # native UDP flow expiry (120 coarse units of ~1.07 s)


class FormatError(Exception):
    pass


# ---------------------------------------------------------------- PCAP (streamed)

class Pcap:
    """Streaming reader over a memory-mapped PCAP. Iterating yields
    (index, ts_ns, direction, cap_len, orig_len, ip_bytes) without copying the file.
    A record that is incomplete or implausible ends the stream (interrupted write);
    [truncated_bytes] and [bad_record] say why after a full pass."""

    def __init__(self, path):
        self.path = path
        self._f = open(path, "rb")
        size = self._f.seek(0, 2)
        if size < 24:
            self._f.close()
            raise FormatError("pcap: file shorter than global header")
        self._m = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        magic = struct.unpack_from("<I", self._m, 0)[0]
        if magic in (0xA1B23C4D, 0xA1B2C3D4):
            self.endian, self.nano = "<", magic == 0xA1B23C4D
        elif magic in (0x4D3CB2A1, 0xD4C3B2A1):
            self.endian, self.nano = ">", magic == 0x4D3CB2A1
        else:
            self.close()
            raise FormatError("pcap: bad magic 0x%08x" % magic)
        _, _, _, _, self.snaplen, linktype = struct.unpack_from(self.endian + "HHiIII", self._m, 4)
        if linktype != 113:
            self.close()
            raise FormatError("pcap: link type %d, expected LINKTYPE_LINUX_SLL (113)" % linktype)
        self.ip_snaplen = max(self.snaplen - 16, 0)
        self.size = size
        self.truncated_bytes = 0
        self.bad_record = None
        self.count = None

    def __iter__(self):
        m, size, e = self._m, self.size, self.endian
        hdr = struct.Struct(e + "IIII")
        mult = 1 if self.nano else 1000
        off, i = 24, 0
        mv = memoryview(m)
        while off + 16 <= size:
            sec, frac, incl, orig = hdr.unpack_from(m, off)
            if off + 16 + incl > size:
                break
            if incl < 16 or incl > orig or (self.snaplen and incl > self.snaplen):
                self.bad_record = "implausible record lengths at offset %d" % off
                break
            pkttype = m[off + 16] << 8 | m[off + 17]
            d = SLL_DIR.get(pkttype)
            if d is None:
                self.bad_record = "SLL packet type %d is not HOST(0)/OUTGOING(4) at offset %d" % (pkttype, off)
                break
            yield i, sec * 1_000_000_000 + frac * mult, d, incl - 16, orig - 16, mv[off + 32:off + 16 + incl]
            off += 16 + incl
            i += 1
        self.truncated_bytes = size - off
        self.count = i

    def close(self):
        try:
            self._m.close()
        except (AttributeError, BufferError, ValueError):
            pass
        self._f.close()


def read_pcap(path):
    """Small-file convenience (tests, scripts): all packets materialized as dicts."""
    p = Pcap(path)
    packets = [{"index": i, "ts_ns": ts, "dir": d, "cap_len": cl, "orig_len": ol, "ip": bytes(ip)}
               for i, ts, d, cl, ol, ip in p]
    out = {"snaplen": p.snaplen, "ip_snaplen": p.ip_snaplen, "nano": p.nano, "packets": packets,
           "truncated_bytes": p.truncated_bytes, "bad_record": p.bad_record}
    p.close()
    return out


def _ext_walk(data, proto, l4):
    """IPv6 extension headers (hop-by-hop, routing, destination, fragment, AH) -> (proto, l4 or None)."""
    for _ in range(8):
        if proto in (0, 43, 60) and l4 + 8 <= len(data):
            proto, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
        elif proto == 51 and l4 + 8 <= len(data):
            proto, l4 = data[l4], l4 + (data[l4 + 1] + 2) * 4
        elif proto == 44 and l4 + 8 <= len(data):
            fo = (data[l4 + 2] << 8 | data[l4 + 3]) & 0xFFF8
            proto, l4 = data[l4], (l4 + 8 if fo == 0 else None)
            if l4 is None:
                break
        else:
            break
    return proto, l4


def parse_ip(data):
    """(ipver, src_bytes, dst_bytes, proto, sport, dport, l4_offset) from a (possibly
    truncated) IP prefix; missing parts are None. No string formatting (hot loop)."""
    if not data:
        return 0, None, None, None, None, None, None
    v = data[0] >> 4
    if v == 4 and len(data) >= 20:
        src, dst, proto = bytes(data[12:16]), bytes(data[16:20]), data[9]
        l4 = (data[0] & 15) * 4 if ((data[6] << 8 | data[7]) & 0x1FFF) == 0 else None
    elif v == 6 and len(data) >= 40:
        src, dst = bytes(data[8:24]), bytes(data[24:40])
        proto, l4 = _ext_walk(data, data[6], 40)
    else:
        return v if v in (4, 6) else 0, None, None, None, None, None, None
    sport = dport = None
    if proto in (6, 17) and l4 is not None and l4 + 4 <= len(data):
        sport, dport = data[l4] << 8 | data[l4 + 1], data[l4 + 2] << 8 | data[l4 + 3]
    return v, src, dst, proto, sport, dport, l4


def client_syn(direction, ip, data):
    """Uplink TCP SYN without ACK: the start of a new connection (generation)."""
    l4 = ip[6]
    return (direction == "uplink" and ip[3] == 6 and l4 is not None and l4 + 14 <= len(data)
            and data[l4 + 13] & 0x12 == 0x02)


_ADDR_CACHE = {}


def addr(b):
    """Cached textual address (a capture has few distinct addresses)."""
    s = _ADDR_CACHE.get(b)
    if s is None:
        s = str(ipaddress.IPv4Address(b) if len(b) == 4 else ipaddress.IPv6Address(b))
        if len(_ADDR_CACHE) < 100_000:
            _ADDR_CACHE[b] = s
    return s


def decode_ip(data):
    """5-tuple with textual addresses (compatibility helper)."""
    v, src, dst, proto, sport, dport, _ = parse_ip(data)
    return {"ipver": v, "src": addr(src) if src else "", "dst": addr(dst) if dst else "", "proto": proto,
            "sport": sport, "dport": dport}


def transport_end(data):
    """Offset just past the TCP/UDP header, or None if it cannot be determined."""
    v, _, _, proto, _, _, l4 = parse_ip(data)
    if l4 is None:
        return None
    if proto == 17:
        return l4 + 8
    if proto == 6:
        # Without the data-offset byte the header is incomplete: it is at least 20 bytes.
        return l4 + (max(20, (data[l4 + 12] >> 4) * 4) if l4 + 13 <= len(data) else 20)
    return None


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
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 64 or data[:8] != b"MPCMETA\0":
        raise FormatError("meta: bad magic")
    major, minor, hlen = struct.unpack_from("<HHI", data, 8)
    if major != 1:
        raise FormatError("meta: unsupported major version %d" % major)
    if hlen < 64 or hlen > len(data):
        raise FormatError("meta: bad header length %d" % hlen)
    sid = str(uuid.UUID(bytes=data[16:32]))
    anchor_boot, anchor_real, start_boot = struct.unpack_from("<qqq", data, 32)
    recs = []
    off = hlen
    while off + 16 <= len(data):
        rtype, flags, length, ts = struct.unpack_from("<HHIq", data, off)
        if length < 16 or length % 8 or off + length > len(data):
            break
        payload = data[off + 16:off + length]
        try:
            body = decode_payload(rtype, payload)
        except (struct.error, KeyError, ValueError, IndexError) as e:
            if strict:
                raise FormatError("meta: cannot decode %s at offset %d: %s" % (TYPES.get(rtype, rtype), off, e))
            body = {"decode_error": str(e)}
        recs.append({"type": TYPES.get(rtype, "TYPE_0x%04x" % rtype), "type_id": rtype, "ts_ns": ts,
                     "ts_source": TS_SOURCES.get(flags & 7, flags & 7), "refresh": bool(flags & 8), **body})
        off += length
    return {"version": "%d.%d" % (major, minor), "session_id": sid, "anchor_boot_ns": anchor_boot,
            "anchor_real_ns": anchor_real, "start_boot_ns": start_boot, "records": recs,
            "truncated_bytes": len(data) - off}


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

    def __bool__(self):
        return bool(self.recs)


class MotionSeries:
    """|x,y,z| per sample with prefix sums: window mean in O(log n); window max via a
    monotonic deque for time-ordered queries (the timeline), a slice otherwise."""

    def __init__(self, recs):
        recs = sorted(recs, key=lambda r: r["ts_ns"])
        self.ts = [r["ts_ns"] for r in recs]
        self.last = [r["values"][:3] for r in recs]
        self.mag = [math.sqrt(sum(v * v for v in r["values"][:3])) for r in recs]
        self.prefix = [0.0]
        for x in self.mag:
            self.prefix.append(self.prefix[-1] + x)
        self._dq = collections.deque()
        self._hi = 0
        self._t = None

    def window(self, t0, t1):
        i, j = bisect.bisect_left(self.ts, t0), bisect.bisect_right(self.ts, t1)
        if i >= j:
            return None, i, j
        if self._t is not None and t1 >= self._t:  # sliding maximum, amortized O(1)
            while self._hi < j:
                while self._dq and self.mag[self._dq[-1]] <= self.mag[self._hi]:
                    self._dq.pop()
                self._dq.append(self._hi)
                self._hi += 1
            while self._dq and self._dq[0] < i:
                self._dq.popleft()
            mx = self.mag[self._dq[0]] if self._dq else max(self.mag[i:j])
        else:
            self._dq.clear()
            self._hi = i
            mx = max(self.mag[i:j])
        self._t = t1
        return {"samples": j - i, "mean_magnitude": (self.prefix[j] - self.prefix[i]) / (j - i),
                "max_magnitude": mx, "last": self.last[j - 1]}, i, j


def _lerp_lon(a, b, f):
    d = b - a
    if d > 180:
        d -= 360
    elif d < -180:
        d += 360
    x = a + d * f
    return (x + 180) % 360 - 180


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
        motion = {}
        for r in by.get("MOTION_SAMPLE", []):
            motion.setdefault(r["sensor"], []).append(r)
        self.motion = {k: MotionSeries(v) for k, v in motion.items()}
        self.uids = {r["uid"]: r for r in by.get("UID_MAPPING", [])}
        flows = {}
        for r in by.get("FLOW_MAPPING", []):
            key = (r["ipver"], r["proto"], ipaddress.ip_address(r["local"]).packed, r["lport"],
                   ipaddress.ip_address(r["remote"]).packed, r["rport"])
            flows.setdefault(key, []).append(r)
        self.flows = {}
        for k, v in flows.items():
            v.sort(key=lambda r: r["first_seen_ns"])
            self.flows[k] = ([r["first_seen_ns"] for r in v], v)
        self._unmapped = {}  # key -> start of a generation that has no FLOW_MAPPING
        self._last_seen = {}
        self.cell_identity = self.series.get("CELL_IDENTITY", Series([]))

    def packets(self):
        if isinstance(self.pcap, Pcap):
            return iter(self.pcap)
        return ((p["index"], p["ts_ns"], p["dir"], p["cap_len"], p["orig_len"], p["ip"]) for p in self.pcap["packets"])

    def boot_ns(self, pkt_ts):
        """Exact inverse of the native PCAP timestamp conversion."""
        ts = pkt_ts["ts_ns"] if isinstance(pkt_ts, dict) else pkt_ts
        return ts - self.meta["anchor_real_ns"] + self.meta["anchor_boot_ns"]

    def to_boot(self, epoch_ns):
        return epoch_ns - self.meta["anchor_real_ns"] + self.meta["anchor_boot_ns"]

    def to_epoch(self, boot_ns):
        return boot_ns - self.meta["anchor_boot_ns"] + self.meta["anchor_real_ns"]

    def reset_flow_state(self):
        self._unmapped.clear()
        self._last_seen.clear()

    def flow_for(self, direction, ip, t, syn=False):
        """FLOW_MAPPING for a packet: same 5-tuple, latest first_seen <= t. A new connection
        on a reused 5-tuple without its own mapping (client [syn], or UDP after the idle
        expiry) is reported unknown instead of inheriting the previous connection's app.
        Calls must come in capture order (after [reset_flow_state])."""
        v, src, dst, proto, sport, dport, l4 = ip
        if proto not in (6, 17) or sport is None:
            return None
        key = (v, proto, src, sport, dst, dport) if direction == "uplink" else (v, proto, dst, dport, src, sport)
        starts, maps = self.flows.get(key, ((), ()))
        i = bisect.bisect_right(starts, t) - 1
        best = maps[i] if i >= 0 else None
        prev = self._last_seen.get(key)
        self._last_seen[key] = t
        new_gen = prev is None
        if proto == 17 and prev is not None and t - prev > UDP_IDLE_NS:
            new_gen = True
        if syn:
            new_gen = True
        if new_gen and (best is None or best["first_seen_ns"] != t):
            self._unmapped[key] = t
        unmapped = self._unmapped.get(key)
        if unmapped is not None and (best is None or best["first_seen_ns"] < unmapped):
            return None
        return best

    def _age_ms(self, rec, t):
        return None if rec is None else round((t - rec["ts_ns"]) / 1e6, 3)

    def location_at(self, t):
        s = self.series.get("LOCATION")
        if not s:
            return {"status": "no_data"}
        a, b = s.around(t)
        if a is not None and b is not None and 0 < b["ts_ns"] - a["ts_ns"] <= self.max_gap:
            f = (t - a["ts_ns"]) / (b["ts_ns"] - a["ts_ns"])
            accs = [x for x in (a["h_acc_m"], b["h_acc_m"]) if x is not None]
            return {"status": "interpolated", "lat": a["lat"] + (b["lat"] - a["lat"]) * f,
                    "lon": _lerp_lon(a["lon"], b["lon"], f),
                    "alt_m": None if a["alt_m"] is None or b["alt_m"] is None else a["alt_m"] + (b["alt_m"] - a["alt_m"]) * f,
                    "h_acc_m": max(accs) if accs else None, "speed_mps": a["speed_mps"], "bearing_deg": a["bearing_deg"],
                    "fix_age_ms": self._age_ms(a, t), "next_fix_in_ms": round((b["ts_ns"] - t) / 1e6, 3)}
        if a is None:
            return {"status": "before_first_fix"}
        return {"status": "stale" if t - a["ts_ns"] > self.max_gap else "latest", "lat": a["lat"], "lon": a["lon"],
                "alt_m": a["alt_m"], "h_acc_m": a["h_acc_m"], "speed_mps": a["speed_mps"],
                "bearing_deg": a["bearing_deg"], "fix_age_ms": self._age_ms(a, t)}

    def motion_at(self, t):
        out = {}
        for sensor in ("accelerometer", "linear_acceleration", "gyroscope"):
            ms = self.motion.get(sensor)
            if ms is None:
                continue
            w, i, _ = ms.window(t - self.motion_win, t)
            if w is None:
                out[sensor] = {"status": "no_samples_in_window",
                               "last_sample_age_ms": round((t - ms.ts[i - 1]) / 1e6, 3) if i > 0 else None}
            else:
                out[sensor] = w
        return out

    def _sample(self, kind, t):
        s = self.series.get(kind)
        r = s.latest(t) if s else None
        if r is None:
            return None
        age = t - r["ts_ns"]
        return r, round(age / 1e6, 3), age > self.stale

    def _state(self, kind, t):
        s = self.series.get(kind)
        return s.latest(t) if s else None

    def serving_signal(self, t):
        """Serving-cell signal from the freshest of SIGNAL_STRENGTH and CELL_MEASUREMENT,
        with the age and stale flag of that same record."""
        best = None
        for kind in ("SIGNAL_STRENGTH", "CELL_MEASUREMENT"):
            got = self._sample(kind, t)
            if got is None:
                continue
            cell = next((c for c in got[0]["cells"] if c["registered"]), None)
            if cell is not None and (best is None or got[1] < best[1]):
                best = (cell, got[1], got[2], got[0])
        return best

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
            r = self._state(kind, t)
            if r is None:
                ctx[key] = None
            else:
                ctx[key] = {k: v for k, v in r.items() if k not in ("type", "type_id")}
                ctx[key]["age_ms"] = self._age_ms(r, t)
        ctx["location"] = self.location_at(t)
        ctx["motion"] = self.motion_at(t)
        return ctx

    # Record kinds whose "latest before t" value feeds a timeline row. Between two consecutive
    # timestamps of these kinds those values cannot change, so they are computed once per
    # interval; only ages, staleness, interpolation, motion windows and apps vary per packet.
    _STATE_KINDS = ("CELL_IDENTITY", "SIGNAL_STRENGTH", "CELL_MEASUREMENT", "RADIO_STATE", "NETWORK_STATE",
                    "WIFI_STATE", "LOCATION")

    def _static_columns(self, t):
        ci = self.cell_identity.latest(t)
        serving = next((c for c in (ci["cells"] if ci else ()) if c["registered"]), None)
        sig = self.serving_signal(t)
        meas = self._sample("CELL_MEASUREMENT", t)
        radio = self._state("RADIO_STATE", t)
        net = self._state("NETWORK_STATE", t)
        wifi = self._state("WIFI_STATE", t)
        cell = sig[0] if sig else {}
        cols = {
            "transport": "|".join(net["transports"]) if net else "",
            "data_rat": _nz(radio["data_network_type"]) if radio else "",
            "rat_override": _nz(radio["override"]) if radio else "",
            "serving_rat": serving["rat"] if serving else "",
            "serving_pci": _nz(serving["pci"]) if serving else "",
            "serving_arfcn": _nz(serving["arfcn"]) if serving else "",
            "serving_cid": _nz(serving["cid"]) if serving else "",
            "rsrp_dbm": _first(cell, "rsrp", "ss_rsrp", "rscp", "rssi"),
            "rsrq_db": _first(cell, "rsrq", "ss_rsrq", "ecno"),
            "sinr_db": _first(cell, "rssnr", "ss_sinr"),
            "neighbor_cells": sum(1 for c in meas[0]["cells"] if not c["registered"]) if meas else "",
            "wifi_rssi_dbm": _nz(wifi["rssi_dbm"]) if wifi else "",
        }
        return cols, (sig[3]["ts_ns"] if sig else None)

    def iter_timeline(self):
        """One row per packet, streamed in capture order."""
        self.reset_flow_state()
        bounds = sorted({ts for k in self._STATE_KINDS if k in self.series for ts in self.series[k].ts})
        lo = hi = None  # current interval [lo, hi) of constant static columns
        static, sig_ts = {}, None
        sec, sec_txt = None, ""
        for idx, ts, direction, cap_len, orig_len, data in self.packets():
            t = self.boot_ns(ts)
            if lo is None or not lo <= t < hi:
                i = bisect.bisect_right(bounds, t)
                lo = bounds[i - 1] if i > 0 else -(1 << 63)
                hi = bounds[i] if i < len(bounds) else 1 << 63
                static, sig_ts = self._static_columns(t)
            ip = parse_ip(data)
            v, src, dst, proto, sport, dport, l4 = ip
            flow = self.flow_for(direction, ip, t, client_syn(direction, ip, data))
            uid = flow["uid"] if flow else None
            app = self.uids.get(uid) if uid is not None else None
            loc = self.location_at(t)
            mot = self.motion_at(t) if self.motion else {}
            acc = mot.get("linear_acceleration") or mot.get("accelerometer") or {}
            gyr = mot.get("gyroscope") or {}
            if ts // 1_000_000_000 != sec:
                sec = ts // 1_000_000_000
                sec_txt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            row = {
                "packet": idx + 1, "time_utc": "%s.%09dZ" % (sec_txt, ts % 1_000_000_000), "boot_ns": t,
                "direction": direction, "orig_len": orig_len, "cap_len": cap_len,
                "src": addr(src) if src else "", "dst": addr(dst) if dst else "",
                "proto": PROTO_NAMES.get(proto, proto if proto is not None else ""),
                "sport": _nz(sport), "dport": _nz(dport),
                "flow_id": flow["flow_id"] if flow else "", "uid": _nz(uid),
                "app_status": ("resolved" if uid is not None else flow["resolution"] if flow
                               else "no_flow_mapping" if sport is not None else "not_tcp_udp"),
                "packages": "|".join(app["packages"]) if app else "", "app_class": app["class"] if app else "",
            }
            row.update(static)
            row["signal_age_ms"] = round((t - sig_ts) / 1e6, 3) if sig_ts is not None else ""
            row["signal_stale"] = (t - sig_ts > self.stale) if sig_ts is not None else ""
            row["lat"] = _nz(loc.get("lat"))
            row["lon"] = _nz(loc.get("lon"))
            row["alt_m"] = _nz(loc.get("alt_m"))
            row["h_acc_m"] = _nz(loc.get("h_acc_m"))
            row["speed_mps"] = _nz(loc.get("speed_mps"))
            row["location_status"] = loc["status"]
            row["fix_age_ms"] = _nz(loc.get("fix_age_ms"))
            row["acc_mean_mps2"] = _nz(acc.get("mean_magnitude"))
            row["acc_max_mps2"] = _nz(acc.get("max_magnitude"))
            row["gyro_mean_rads"] = _nz(gyr.get("mean_magnitude"))
            yield row

    def timeline(self):
        return list(self.iter_timeline())


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

def _packets_of(pcap):
    if isinstance(pcap, Pcap):
        return iter(pcap)
    return ((p["index"], p["ts_ns"], p["dir"], p["cap_len"], p["orig_len"], p["ip"]) for p in pcap["packets"])


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
    seen = set()
    for r in recs:
        if r["type"] == "FLOW_MAPPING":
            if r["flow_id"] in seen:
                errs.append("duplicate FLOW_MAPPING for flow %d" % r["flow_id"])
            seen.add(r["flow_id"])
        if r["type"].startswith("TYPE_"):
            warns.append("unknown record type %s skipped" % r["type"])
    # Every TCP/UDP record must contain its complete transport header (the logger never cuts
    # inside headers, whatever the configured length); timestamps must not go backwards much.
    short, n, prev, backwards = 0, 0, None, 0
    for _, ts, _, cap_len, orig_len, data in _packets_of(pcap):
        n += 1
        if prev is not None and ts < prev:
            backwards += 1
        prev = ts
        need = transport_end(data)
        if need is not None and cap_len < min(need, orig_len):
            short += 1
    tb = pcap.truncated_bytes if isinstance(pcap, Pcap) else pcap["truncated_bytes"]
    bad = pcap.bad_record if isinstance(pcap, Pcap) else pcap.get("bad_record")
    if bad:
        errs.append("pcap: " + bad)
    elif tb:
        errs.append("pcap has %d trailing bytes after the last complete record" % tb)
    if short:
        errs.append("%d TCP/UDP records end inside their transport header" % short)
    if backwards:
        warns.append("%d packet timestamps earlier than the previous packet" % backwards)
    return errs, warns, n


def summary(session):
    s, meta = session, session.meta
    counts = collections.Counter(r["type"] for r in meta["records"])
    n = up = attributed = 0
    first = last = None
    s.reset_flow_state()
    for idx, ts, direction, cap_len, orig_len, data in s.packets():
        n += 1
        up += direction == "uplink"
        first = ts if first is None else first
        last = ts
        ip = parse_ip(data)
        f = s.flow_for(direction, ip, s.boot_ns(ts), client_syn(direction, ip, data))
        attributed += bool(f and f["uid"] is not None)
    end = next((r for r in meta["records"] if r["type"] == "SESSION_END"), None)
    stats = s.by.get("CAPTURE_STATS", [])
    counters = end["counters"] if end and end["counters"] else (stats[-1]["counters"] if stats else None)
    drops = None if counters is None else counters.get("capture_queue_drops_ul", 0) + counters.get("capture_queue_drops_dl", 0)
    status = {}
    for r in s.by.get("SENSOR_STATUS", []):
        status[r["source"]] = r["status"] + (" (%s)" % r["detail"] if r["detail"] else "")
    return {
        "session_id": meta["session_id"], "meta_version": meta["version"],
        "packets": n, "uplink": up, "downlink": n - up,
        "first_packet_utc": iso(first) if first is not None else None, "last_packet_utc": iso(last) if last is not None else None,
        "packets_with_app": attributed, "flows": counts.get("FLOW_MAPPING", 0),
        "apps": {str(u): "|".join(r["packages"]) for u, r in sorted(s.uids.items())},
        "metadata_records": dict(counts), "sources": status,
        "metadata_dropped": sum(r["dropped"] for r in s.by.get("DROPPED_EVENTS", [])),
        "end": None if end is None else {"status": end["status"], "reason": end["reason"]},
        "capture_queue_drops": drops,
        "capture_queue_drops_source": None if counters is None else ("SESSION_END" if end and end["counters"] else "last CAPTURE_STATS"),
    }


def export_pcapng(session, out_path):
    """Enriched copy: raw IP packets, epb_flags direction, and a comment with app and radio context."""
    s = session

    def opt(code, val):
        return struct.pack("<HH", code, len(val)) + val + b"\0" * (-len(val) % 4)

    def block(btype, body):
        return struct.pack("<II", btype, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))

    info = s.by.get("SESSION_INFO", [{}])[0]
    ip_snaplen = s.pcap.ip_snaplen if isinstance(s.pcap, Pcap) else s.pcap["ip_snaplen"]
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
                + opt(2, ("%s %s" % (info.get("device_manufacturer", ""), info.get("device_model", ""))).encode())
                + opt(3, ("Android %s" % info.get("android_release", "")).encode())
                + opt(4, ("mpcanalyze export of %s" % s.meta["session_id"]).encode()) + opt(0, b""))
    idb = block(1, struct.pack("<HHI", 101, 0, ip_snaplen) + opt(2, b"tun0") + opt(9, b"\x09") + opt(0, b""))
    n = 0
    with open(out_path, "wb") as f:
        f.write(shb + idb)
        rows = s.iter_timeline()
        for (_, ts, direction, cap_len, orig_len, data), row in zip(s.packets(), rows):
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
            payload = bytes(data) + b"\0" * (-cap_len % 4)
            opts = (opt(1, comment) if comment else b"") + opt(2, struct.pack("<I", 2 if direction == "uplink" else 1)) + opt(0, b"")
            f.write(block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, cap_len, orig_len) + payload + opts))
            n += 1
    return n


# ---------------------------------------------------------------- CLI

def main(argv):
    ap = argparse.ArgumentParser(prog="mpcanalyze", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("command", choices=["validate", "dump", "summary", "timeline", "context-at", "export-pcapng"])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--type", default=None)
    ap.add_argument("--csv", action="store_true")
    ap.add_argument("--max-location-gap", type=float, default=5.0)
    ap.add_argument("--motion-window", type=float, default=1000)
    ap.add_argument("--stale-after", type=float, default=10.0)
    a = ap.parse_args(argv[1:])
    need = {"dump": 1, "validate": 2, "summary": 2, "timeline": 2, "context-at": 3, "export-pcapng": 3}[a.command]
    if len(a.files) != need:
        ap.error("%s takes %d file/argument(s)" % (a.command, need))
    try:
        if a.command == "dump":
            meta = read_meta(a.files[0], strict=False)
            print(json.dumps({"header": {k: v for k, v in meta.items() if k != "records"}}))
            for r in meta["records"]:
                if a.type is None or r["type"] == a.type:
                    print(json.dumps(r, default=str))
            return 0
        pcap, meta = Pcap(a.files[0]), read_meta(a.files[1])
        if a.command == "validate":
            errs, warns, n = validate(pcap, meta, a.files[0])
            for w in warns:
                print("WARN:", w)
            for e in errs:
                print("FAIL:", e)
            print(json.dumps({"ok": not errs, "packets": n, "records": len(meta["records"]), "session_id": meta["session_id"]}))
            return 1 if errs else 0
        s = Session(pcap, meta, a.max_location_gap, a.motion_window, a.stale_after)
        if a.command == "summary":
            print(json.dumps(summary(s), indent=1))
        elif a.command == "timeline":
            rows = s.iter_timeline()
            if a.csv:
                import csv
                first = next(rows, None)
                if first is not None:
                    w = csv.DictWriter(sys.stdout, fieldnames=list(first.keys()))
                    w.writeheader()
                    w.writerow(first)
                    for r in rows:
                        w.writerow(r)
            else:
                for r in rows:
                    sys.stdout.write(json.dumps(r) + "\n")
        elif a.command == "context-at":
            try:
                t = parse_time(a.files[2], s)
            except ValueError:
                ap.error("time must be epoch seconds, ISO 8601 or boot:<ns>")
            print(json.dumps(s.context_at(t), indent=1, default=str))
        elif a.command == "export-pcapng":
            print("wrote %d packets to %s" % (export_pcapng(s, a.files[2]), a.files[2]))
        return 0
    except FormatError as e:
        print("FORMAT ERROR:", e, file=sys.stderr)
        return 1
    except OSError as e:
        print("ERROR:", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
