#!/usr/bin/env python3
"""Unit tests for the analyzer with an independent, test-only encoder.
Run: python3 -I analyzer/test_mpcanalyze.py"""
import io
import json
import os
import struct
import sys
import tempfile
import time
import unittest
import uuid
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mpcanalyze as m  # noqa: E402

SID = "00000000-0000-4000-8000-0000000000aa"
BOOT0, REAL0 = 1_000_000_000_000, 1_792_000_000_000_000_000


def t(ms):
    return BOOT0 + int(ms * 1_000_000)


# ---------------------------------------------------------------- test encoder (independent of the app)

def rec(rtype, ts, body, flags=0):
    body += b"\0" * (-(16 + len(body)) % 8)
    return struct.pack("<HHIq", rtype, flags, 16 + len(body), ts) + body


def s(x):
    b = x.encode()
    return struct.pack("<H", len(b)) + b


def info(**kv):
    return rec(0x0001, t(0), struct.pack("<H", len(kv)) + b"".join(s(k) + s(str(v)) for k, v in kv.items()))


def end(status=1, counters=None):
    counters = counters or {}
    return rec(0x0003, t(99_000), bytes([status]) + s("user_stop") + struct.pack("<H", len(counters))
               + b"".join(s(k) + struct.pack("<Q", v) for k, v in counters.items()))


def location(ms, lat, lon, hacc=5.0):
    p = 1 | (1 << 3)
    return rec(0x0010, t(ms), struct.pack("<Iqdddd6fBBH", p, t(ms), lat, lon, 0, 0, hacc, 0, 0, 0, 0, 0, 3, 0, 0), 2)


def motion(ms, x, y, z, sensor=1):
    return rec(0x0020, t(ms), struct.pack("<BBBB3f", sensor, 3, 3, 0, x, y, z), 1)


def meas(ms, rat, registered, rsrp, pci=None):
    p = 1 | (1 << 4) | ((1 << 1) if pci is not None else 0)
    entry = struct.pack("<HBBIq", 0, rat, 1 | (1 << 1) if registered else 0, p, t(ms))
    entry += struct.pack("<iii8i", pci or 0, 0, 0, rsrp, 0, 0, 0, 0, 0, 0, 0)
    entry = struct.pack("<H", len(entry)) + entry[2:]
    return entry


def cells(rtype, ms, entries):
    return rec(rtype, t(ms), struct.pack("<HH", len(entries), 0) + b"".join(entries), 3)


def identity(ms, rat, pci, cid):
    p = 1 | (1 << 3) | (1 << 4)
    e = struct.pack("<HBBIq", 0, rat, 1 | (1 << 1), p, t(ms)) + struct.pack("<HHBBH", 0, 0, 0, 0, 0)
    e += struct.pack("<qiiii", cid, pci, 0, 0, 0) + struct.pack("<H", 0)
    e = struct.pack("<H", len(e)) + e[2:]
    return rec(0x0031, t(ms), struct.pack("<HH", 1, 0) + e)


def flow(ms_first, fid, proto, lport, rport, local, remote, uid, res=1):
    key = struct.pack("<BBHHH", 4, proto, lport, rport, 0) + bytes(local) + bytes(12) + bytes(remote) + bytes(12)
    return rec(0x0051, t(ms_first + 3), struct.pack("<Qq", fid, t(ms_first)) + key
               + struct.pack("<iBBHII", uid, res, 1, 0, 3, 0))


def uidmap(uid, pkg):
    return rec(0x0050, t(1), struct.pack("<iI", uid, 0) + s("web") + s("user_config") + s("")
               + struct.pack("<H", 1) + s(pkg) + struct.pack("<H", 1) + s(pkg))


def meta_file(path, records, sid=SID):
    hdr = b"MPCMETA\0" + struct.pack("<HHI", 1, 0, 64) + uuid.UUID(sid).bytes + struct.pack("<qqqII", BOOT0, REAL0, BOOT0, 0, 0)
    with open(path, "wb") as f:
        f.write(hdr + b"".join(records))


def ipv4(proto, src, dst, sport, dport, payload=b""):
    l4 = struct.pack(">HH", sport, dport) + (struct.pack(">IIBBHHH", 1, 0, 5 << 4, 0x18, 1000, 0, 0) if proto == 6
                                              else struct.pack(">HH", 8 + len(payload), 0)) + payload
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, bytes(src), bytes(dst)) + l4


def pcap_file(path, packets, snaplen=144):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, snaplen, 113))
        for ms, up, ip in packets:
            ts = REAL0 + (t(ms) - BOOT0)
            sll = struct.pack(">HHHQH", 4 if up else 0, 0xFFFE, 0, 0, 0x0800)
            f.write(struct.pack("<IIII", ts // 10 ** 9, ts % 10 ** 9, 16 + len(ip), 16 + len(ip)) + sll + ip)


APP, SRV = (10, 111, 0, 2), (93, 184, 216, 34)


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.pcap = os.path.join(self.d, SID + ".pcap")
        self.meta = os.path.join(self.d, SID + ".meta")

    def session(self, packets, records, **kw):
        pcap_file(self.pcap, packets)
        meta_file(self.meta, records)
        return m.Session(m.read_pcap(self.pcap), m.read_meta(self.meta), **kw)

    def test_interpolation_never_crosses_a_gap(self):
        s = self.session([], [info(), location(0, 59.0, 18.0), location(1000, 59.1, 18.1), location(20_000, 60.0, 19.0), end()])
        self.assertEqual(s.location_at(t(500))["status"], "interpolated")
        self.assertAlmostEqual(s.location_at(t(500))["lat"], 59.05)
        gap = s.location_at(t(10_000))  # fixes 19 s apart > 5 s
        self.assertEqual(gap["status"], "stale")
        self.assertAlmostEqual(gap["lat"], 59.1)
        self.assertEqual(s.location_at(t(-1))["status"], "before_first_fix")
        on_fix = s.location_at(t(1000))  # exactly on a fix that is followed by a gap
        self.assertEqual((on_fix["status"], on_fix["fix_age_ms"]), ("latest", 0.0))
        s2 = self.session([], [info(), end()])
        self.assertEqual(s2.location_at(t(5))["status"], "no_data")

    def test_out_of_order_records_are_sorted_by_timestamp(self):
        s = self.session([], [info(), location(2000, 2.0, 2.0), location(0, 0.0, 0.0), location(1000, 1.0, 1.0), end()])
        self.assertAlmostEqual(s.location_at(t(1500))["lat"], 1.5)

    def test_samples_report_age_and_staleness(self):
        s = self.session([], [info(), cells(0x0033, 100, [meas(100, 5, True, -90)]), end()], stale_after_s=2)
        r, age, stale = s._sample("SIGNAL_STRENGTH", t(600))
        self.assertEqual(age, 500.0)
        self.assertFalse(stale)
        self.assertTrue(s._sample("SIGNAL_STRENGTH", t(5000))[2])
        self.assertIsNone(s._sample("SIGNAL_STRENGTH", t(50)))  # nothing before the first report

    def test_flow_generations_and_directions(self):
        a = ipv4(6, APP, SRV, 40000, 443)
        b = ipv4(6, SRV, APP, 443, 40000)
        s = self.session([(10, True, a), (11, False, b), (500, True, a)],
                         [info(), flow(10, 1, 6, 40000, 443, APP, SRV, 1001), flow(500, 2, 6, 40000, 443, APP, SRV, 1002),
                          uidmap(1001, "org.one"), uidmap(1002, "org.two"), end()])
        rows = s.timeline()
        self.assertEqual([r["uid"] for r in rows], [1001, 1001, 1002])
        self.assertEqual([r["packages"] for r in rows], ["org.one", "org.one", "org.two"])
        self.assertEqual([r["direction"] for r in rows], ["uplink", "downlink", "uplink"])

    def test_packet_before_any_flow_mapping_is_unknown(self):
        a = ipv4(17, APP, SRV, 5000, 53, b"q")
        s = self.session([(10, True, a)], [info(), end()])
        self.assertEqual(s.timeline()[0]["app_status"], "no_flow_mapping")

    def test_motion_window(self):
        s = self.session([], [info(), motion(100, 0, 0, 10), motion(900, 0, 6, 8), motion(3000, 0, 0, 1), end()], motion_window_ms=1000)
        w = s.motion_at(t(1000))["accelerometer"]
        self.assertEqual(w["samples"], 2)
        self.assertAlmostEqual(w["mean_magnitude"], 10.0)
        self.assertEqual(s.motion_at(t(2500))["accelerometer"]["status"], "no_samples_in_window")

    def test_serving_cell_state_changes(self):
        s = self.session([], [info(), identity(100, 5, 123, 1), identity(5000, 6, 501, 2), end()])
        self.assertEqual(s.context_at(t(1000))["serving_cells"][0]["pci"], 123)
        self.assertEqual(s.context_at(t(6000))["serving_cells"][0]["rat"], "NR")
        self.assertIsNone(s.context_at(t(50))["serving_cells"])

    def test_truncated_meta_is_readable_but_invalid(self):
        pcap_file(self.pcap, [])
        meta_file(self.meta, [info(), location(0, 1, 1)])
        with open(self.meta, "ab") as f:
            f.write(rec(0x0010, t(5), b"x" * 40)[:20])
        meta = m.read_meta(self.meta)
        self.assertEqual(len(meta["records"]), 2)
        self.assertEqual(meta["truncated_bytes"], 20)
        errs, _, _ = m.validate(m.read_pcap(self.pcap), meta)
        self.assertTrue(any("SESSION_END" in e for e in errs))
        self.assertTrue(any("trailing bytes" in e for e in errs))

    def test_unknown_types_and_trailing_fields_are_skipped(self):
        loc = location(0, 1, 1)
        longer = loc[:4] + struct.pack("<I", len(loc) + 8) + loc[8:] + b"\x01" * 8  # future trailing field
        s = self.session([], [info(), rec(0x7777, t(1), b"future"), longer, end()])
        self.assertEqual(s.location_at(t(0))["lat"], 1.0)
        self.assertIn("TYPE_0x7777", s.by)

    def test_header_floor_validation(self):
        full = ipv4(6, APP, SRV, 40000, 443, b"x" * 100)
        pcap_file(self.pcap, [(1, True, full[:30])])  # cut inside the TCP header
        meta_file(self.meta, [info(), end()])
        # The test pcap writer stores orig_len = cap_len; record the real original length:
        with open(self.pcap, "r+b") as f:  # orig_len = full length
            f.seek(24 + 12)
            f.write(struct.pack("<I", 16 + len(full)))
        errs, _, _ = m.validate(m.read_pcap(self.pcap), m.read_meta(self.meta))
        self.assertTrue(any("transport header" in e for e in errs), errs)

    def test_bad_inputs_raise_format_errors(self):
        with open(self.pcap, "wb") as f:
            f.write(b"\0" * 24)
        with self.assertRaises(m.FormatError):
            m.read_pcap(self.pcap)
        with open(self.meta, "wb") as f:
            f.write(b"NOTMETA!" + bytes(56))
        with self.assertRaises(m.FormatError):
            m.read_meta(self.meta)

    def test_cli_context_at_accepts_time_formats(self):
        self.session([], [info(), location(1000, 59.0, 18.0), end()])
        for when in ("boot:%d" % t(1000), "%.9f" % ((REAL0 + 1_000_000_000) / 1e9),
                     m.iso(REAL0 + 1_000_000_000)):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(m.main(["x", "context-at", self.pcap, self.meta, when]), 0)
            self.assertIn(json.loads(out.getvalue())["location"]["status"], ("latest", "interpolated"))

    def test_export_pcapng_is_readable(self):
        a = ipv4(6, APP, SRV, 40000, 443)
        self.session([(10, True, a)], [info(), flow(10, 1, 6, 40000, 443, APP, SRV, 1001), uidmap(1001, "org.one"), end()])
        out = os.path.join(self.d, "e.pcapng")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(["x", "export-pcapng", self.pcap, self.meta, out]), 0)
        data = open(out, "rb").read()
        self.assertEqual(data[:4], b"\x0a\x0d\x0d\x0a")
        self.assertIn(b"app=org.one", data)


class AnalyzerPerformance(unittest.TestCase):
    """Scaling check: timeline over 200k packets and 50k metadata records stays well below O(n*m)."""

    def test_timeline_scales(self):
        d = tempfile.mkdtemp()
        pcap, meta = os.path.join(d, SID + ".pcap"), os.path.join(d, SID + ".meta")
        n = int(os.environ.get("MPC_PERF_PACKETS", "200000"))
        a = ipv4(6, APP, SRV, 40000, 443)
        pcap_file(pcap, [(i * 0.5, i % 2 == 0, a) for i in range(n)])
        recs = [info(), flow(0, 1, 6, 40000, 443, APP, SRV, 1001), uidmap(1001, "org.one")]
        recs += [location(i * 1000, 59 + i * 1e-5, 18) for i in range(n // 2000 + 1)]
        recs += [motion(i * 20, 0, 0, 9.8) for i in range(n // 40)]
        recs += [cells(0x0033, i * 1000, [meas(i * 1000, 5, True, -90)]) for i in range(n // 2000 + 1)]
        meta_file(meta, recs + [end()])
        t0 = time.perf_counter()
        s = m.Session(m.read_pcap(pcap), m.read_meta(meta))
        rows = s.timeline()
        dt = time.perf_counter() - t0
        self.assertEqual(len(rows), n)
        rate = n / dt
        print("\nanalyzer timeline: %d packets, %d meta records in %.2f s (%.0f packets/s)" % (n, len(recs) + 1, dt, rate))
        self.assertGreater(rate, 10_000, "timeline too slow: %.0f packets/s" % rate)


if __name__ == "__main__":
    unittest.main(verbosity=1)
