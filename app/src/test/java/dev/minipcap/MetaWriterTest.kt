package dev.minipcap

import dev.minipcap.meta.CellIdentity
import dev.minipcap.meta.CellMeasurement
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.UUID

class MetaWriterTest {
    private val dir = Files.createTempDirectory("meta").toFile()
    private val sid = UUID.fromString("00000000-0000-4000-8000-0000000000aa")
    private val boot0 = 1_000_000_000_000L
    private val real0 = 1_792_000_000_000_000_000L
    private fun t(ms: Long) = boot0 + ms * 1_000_000

    private fun writer(f: File, pool: Int = 512) = MetaWriter(f, sid, boot0, real0, boot0, poolSize = pool)

    @Test
    fun recordsAreFramedAndSessionEndIsLast() {
        val f = File(dir, "a.meta")
        val w = writer(f)
        assertTrue(MetaRecords.sessionInfo(w, t(0), mapOf("ip_snaplen" to "128", "gps" to "true")))
        assertTrue(MetaRecords.clockSync(w, t(0), real0, MetaFormat.CLOCK_START))
        assertTrue(MetaRecords.motion(w, t(5), MetaFormat.SENSOR_ACCEL, 3, floatArrayOf(0.1f, 9.8f, 0.2f), 3))
        assertTrue(MetaRecords.sessionEnd(w, t(9), MetaFormat.END_COMPLETE, "user_stop", mapOf("records_written" to 5L)))
        w.close()
        val s = MetaFormat.scan(f)
        assertEquals(sid, s.sessionId)
        assertEquals(4, s.records)
        assertEquals(MetaFormat.END_COMPLETE, s.endStatus)
        assertEquals(0, s.truncatedBytes)
        assertEquals(f.length(), s.validBytes)
        assertEquals(boot0, s.anchorBootNs)
        assertEquals(real0, s.anchorRealNs)
    }

    @Test
    fun recoveryTruncatesPartialRecordAndAppendsRecoveredEnd() {
        val f = File(dir, "b.meta")
        val w = writer(f)
        MetaRecords.sessionInfo(w, t(0), mapOf("k" to "v"))
        MetaRecords.clockSync(w, t(1), real0, MetaFormat.CLOCK_START)
        w.close()
        val good = f.length()
        RandomAccessFile(f, "rw").use { it.seek(good); it.write(ByteArray(13) { 7 }) } // half a record
        val before = MetaFormat.recover(f, t(100), "process_terminated_recovered")
        assertEquals(13, before.truncatedBytes)
        assertNull(before.endStatus)
        val after = MetaFormat.scan(f)
        assertEquals(3, after.records)
        assertEquals(MetaFormat.END_RECOVERED, after.endStatus)
        assertEquals(0, after.truncatedBytes)
        // Idempotent: a second recovery does not append another SESSION_END.
        MetaFormat.recover(f, t(200), "again")
        assertEquals(3, MetaFormat.scan(f).records)
    }

    @Test
    fun exhaustedPoolDropsAreCountedNeverBlock() {
        val f = File(dir, "c.meta")
        val w = writer(f, pool = 4)
        val values = floatArrayOf(1f, 2f, 3f)
        var ok = 0
        val t0 = System.nanoTime()
        repeat(20_000) { if (MetaRecords.motion(w, t(it.toLong()), MetaFormat.SENSOR_ACCEL, 3, values, 3)) ok++ }
        val producerMs = (System.nanoTime() - t0) / 1e6
        val dropped = w.droppedTotal
        assertTrue(MetaRecords.sessionEnd(w, t(30_000), MetaFormat.END_COMPLETE, "user_stop", emptyMap())) // critical: waits
        w.close()
        assertEquals(MetaFormat.END_COMPLETE, MetaFormat.scan(f).endStatus)
        assertEquals(20_000L, ok + dropped)
        assertTrue("expected drops with a 4-buffer pool", dropped > 0)
        assertTrue("producer must not block ($producerMs ms)", producerMs < 5_000)
        val s = MetaFormat.scan(f)
        // every accepted sample + SESSION_END + DROPPED_EVENTS reports
        assertTrue(s.records >= ok + 1)
        assertEquals(0, s.truncatedBytes)
    }

    @Test
    fun oversizedRecordIsDroppedNotCorrupting() {
        val f = File(dir, "d.meta")
        val w = writer(f)
        val huge = (0 until 2000).associate { "key_$it" to "value_$it" }
        assertTrue(!MetaRecords.sessionInfo(w, t(0), huge))
        MetaRecords.sessionEnd(w, t(1), MetaFormat.END_COMPLETE, "x", emptyMap())
        w.close()
        assertEquals(1L, w.droppedTotal)
        assertEquals(MetaFormat.END_COMPLETE, MetaFormat.scan(f).endStatus)
    }

    // ------------------------------------------------------------------ cross-check with the Python analyzer

    private val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "analyzer").isDirectory }

    private fun pcapRecord(out: java.io.OutputStream, bootNs: Long, uplink: Boolean, ip: ByteArray) {
        val ts = real0 + (bootNs - boot0)
        val b = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        b.putInt((ts / 1_000_000_000).toInt()).putInt((ts % 1_000_000_000).toInt()).putInt(16 + ip.size).putInt(16 + ip.size)
        b.order(ByteOrder.BIG_ENDIAN).putShort(if (uplink) 4 else 0).putShort(0xFFFE.toShort()).putShort(0).putLong(0)
            .putShort(if (ip[0].toInt() shr 4 == 4) 0x0800 else 0x86DD.toShort())
        out.write(b.array())
        out.write(ip)
    }

    private fun ipv4(proto: Int, src: ByteArray, dst: ByteArray, sport: Int, dport: Int): ByteArray {
        val b = ByteBuffer.allocate(40).order(ByteOrder.BIG_ENDIAN)
        b.put(0x45).put(0).putShort(40).putInt(0).put(64).put(proto.toByte()).putShort(0).put(src).put(dst)
        b.putShort(sport.toShort()).putShort(dport.toShort())
        return b.array()
    }

    private fun key(proto: Int, local: ByteArray, lport: Int, remote: ByteArray, rport: Int): ByteArray {
        val b = ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN)
        b.put(4).put(proto.toByte()).putShort(lport.toShort()).putShort(rport.toShort()).putShort(0)
        b.put(local).put(ByteArray(12)).put(remote).put(ByteArray(12))
        return b.array()
    }

    private fun python(vararg args: String): String {
        val p = ProcessBuilder(listOf("python3", "-I", File(root, "analyzer/mpcanalyze.py").path) + args)
            .redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        assertEquals(out, 0, p.waitFor())
        return out
    }

    @Test
    fun analyzerReconstructsContextFromKotlinWrittenFiles() {
        assumeTrue(runCatching { ProcessBuilder("python3", "--version").start().waitFor() == 0 }.getOrDefault(false))
        val app = byteArrayOf(10, 111, 0, 2)
        val srv = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)
        val dns = byteArrayOf(8, 8, 8, 8)
        val pcap = File(dir, "$sid.pcap")
        pcap.outputStream().use { o ->
            val g = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            g.putInt(0xA1B23C4D.toInt()).putShort(2).putShort(4).putInt(0).putInt(0).putInt(128 + 16).putInt(113)
            o.write(g.array())
            pcapRecord(o, t(1000), true, ipv4(6, app, srv, 40000, 443))       // 1: flow 1 (app 10234)
            pcapRecord(o, t(1100), false, ipv4(6, srv, app, 443, 40000))      // 2: same flow, downlink
            pcapRecord(o, t(2000), true, ipv4(1, app, dns, 0, 0).copyOf(28))  // 3: ICMP, no flow
            pcapRecord(o, t(5000), true, ipv4(17, app, dns, 5000, 53))        // 4: flow 2, unresolved
            pcapRecord(o, t(20000), true, ipv4(6, app, srv, 40000, 443))      // 5: same tuple, new flow 3
        }
        val meta = File(dir, "$sid.meta")
        val w = writer(meta)
        MetaRecords.sessionInfo(w, t(0), mapOf("ip_snaplen" to "128", "device_model" to "Test"))
        MetaRecords.clockSync(w, t(0), real0, MetaFormat.CLOCK_START)
        MetaRecords.sensorStatus(w, t(0), MetaFormat.SRC_LOCATION, MetaFormat.ST_ACTIVE, "fused")
        MetaRecords.cellIdentity(w, t(200), false, listOf(CellIdentity(MetaFormat.RAT_LTE, true, 1, t(150), 240, 1, 2,
            26138881L, 123, 6300, 4711, 20000, intArrayOf(20))))
        MetaRecords.location(w, t(500), t(510), 59.0, 18.0, 30.0, Double.NaN, 4f, Float.NaN, 1.0f, Float.NaN, 90f, Float.NaN, 3, 12)
        MetaRecords.signalStrength(w, t(900), true, listOf(CellMeasurement(MetaFormat.RAT_LTE, true, 1, t(900), null, null, 3,
            arrayOf(-95, -11, 12, null, 9, null, null, null))))
        MetaRecords.motion(w, t(950), MetaFormat.SENSOR_ACCEL, 3, floatArrayOf(0f, 0f, 9.81f), 3)
        MetaRecords.motion(w, t(990), MetaFormat.SENSOR_ACCEL, 3, floatArrayOf(0f, 3f, 4f), 3)
        // Written after packets they describe and out of time order: the analyzer sorts by timestamp.
        MetaRecords.flowMapping(w, t(1003), 1, t(1000), key(6, app, 40000, srv, 443), 10234, MetaFormat.RES_FIRST_LOOKUP, 1, 3)
        MetaRecords.location(w, t(1500), t(1520), 59.001, 18.001, 31.0, Double.NaN, 6f, Float.NaN, 1.0f, Float.NaN, 90f, Float.NaN, 3, 12)
        MetaRecords.uidMapping(w, t(1004), 10234, "web", "user_config", null, listOf("org.example.app"), listOf("Example"))
        w.emit(0x7777, 0, t(3000)) { it.putLong(42) } // unknown future type: must be skipped
        MetaRecords.signalStrength(w, t(4000), true, listOf(CellMeasurement(MetaFormat.RAT_LTE, true, 1, t(4000), null, null, 2,
            arrayOf(-100, -13, 5, null, null, null, null, null))))
        MetaRecords.flowMapping(w, t(7000), 2, t(5000), key(17, app, 5000, dns, 53), -1, MetaFormat.RES_UNRESOLVED_INVALID_UID, 5, 2000)
        MetaRecords.cellIdentity(w, t(10000), false, listOf(CellIdentity(MetaFormat.RAT_NR, true, 1, t(9990), 240, 1, 2,
            1234567L, 501, 632256, 4711, null, null)))
        MetaRecords.flowMapping(w, t(20002), 3, t(20000), key(6, app, 40000, srv, 443), 10500, MetaFormat.RES_FIRST_LOOKUP, 1, 2)
        MetaRecords.uidMapping(w, t(20003), 10500, "unknown", "default", null, listOf("org.other"), listOf("Other"))
        MetaRecords.sessionEnd(w, t(21000), MetaFormat.END_COMPLETE, "user_stop", mapOf("capture_queue_drops_ul" to 0L))
        w.close()

        val v = python("validate", pcap.path, meta.path)
        assertTrue(v, v.contains("\"ok\": true") && v.contains("WARN: unknown record type"))
        val rows = python("timeline", pcap.path, meta.path).trim().lines().map { JSONObject(it) }
        assertEquals(5, rows.size)
        val (p1, p2, p3, p4, p5) = rows
        assertEquals("uplink", p1.getString("direction"))
        assertEquals("downlink", p2.getString("direction"))
        assertEquals(10234, p1.getInt("uid"))
        assertEquals("org.example.app", p2.getString("packages"))
        assertEquals("interpolated", p1.getString("location_status"))
        assertEquals(59.0005, p1.getDouble("lat"), 1e-9)
        assertEquals(123, p1.getInt("serving_pci"))
        assertEquals(-95, p1.getInt("rsrp_dbm"))
        assertEquals(100.0, p1.getDouble("signal_age_ms"), 1e-6)
        assertEquals(7.405, p1.getDouble("acc_mean_mps2"), 1e-3) // |a| 9.81 and 5.0 within the 1 s window
        assertEquals("not_tcp_udp", p3.getString("app_status"))
        assertEquals("", p4.getString("uid"))
        assertEquals("unresolved_invalid_uid", p4.getString("app_status"))
        assertEquals(-100, p4.getInt("rsrp_dbm"))
        assertEquals(1000.0, p4.getDouble("signal_age_ms"), 1e-6)
        assertEquals("latest", p4.getString("location_status")) // last fix 3.5 s old, within the 5 s gap
        assertEquals(10500, p5.getInt("uid"))                    // same 5-tuple, later generation
        assertEquals("NR", p5.getString("serving_rat"))
        assertEquals(501, p5.getInt("serving_pci"))
        assertEquals("stale", p5.getString("location_status"))
        assertEquals(true, p5.getBoolean("signal_stale"))       // 16 s old > 10 s

        val ctx = JSONObject(python("context-at", pcap.path, meta.path, "boot:${t(1000)}"))
        assertEquals("interpolated", ctx.getJSONObject("location").getString("status"))
        assertEquals(2, ctx.getJSONObject("motion").getJSONObject("accelerometer").getInt("samples"))
        val sum = JSONObject(python("summary", pcap.path, meta.path))
        assertEquals(3, sum.getInt("packets_with_app"))
        assertEquals("complete", sum.getJSONObject("end").getString("status"))
    }
}
