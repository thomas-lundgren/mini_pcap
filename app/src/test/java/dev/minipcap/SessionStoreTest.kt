package dev.minipcap

import dev.minipcap.capture.PcapFormat
import dev.minipcap.meta.MetaFormat
import dev.minipcap.session.SessionFormat
import dev.minipcap.session.SessionState
import dev.minipcap.session.SessionStore
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class SessionStoreTest {
    private fun store() = SessionStore(Files.createTempDirectory("sessions").toFile())

    private fun completeSession(s: SessionStore, id: String, created: Long, finalizedAt: Long) {
        s.create(id, "F", created)
        s.pcapFinal(id).writeBytes(TestCapture.pcap(2))
        TestCapture.meta(s.metaFinal(id), id)
        s.markFinalized(id, SessionState.COMPLETE, finalizedAt, "user_stop")
    }

    @Test
    fun latestCompletedUsesFinalizationOrderNotCreationOrMtime() {
        val s = store()
        val a = "00000000-0000-4000-8000-00000000000a"
        val b = "00000000-0000-4000-8000-00000000000b"
        s.create(b, "F", 2000) // created later...
        s.create(a, "F", 1000)
        for (id in listOf(a, b)) {
            s.pcapFinal(id).writeBytes(TestCapture.pcap(1))
            s.metaFinal(id).writeText("{}")
        }
        s.markFinalized(b, SessionState.COMPLETE, 5000, null)
        s.markFinalized(a, SessionState.COMPLETE, 5000, null) // ...but finalized last
        s.pcapFinal(b).setLastModified(System.currentTimeMillis() + 100_000) // mtime must not matter
        assertEquals(a, s.latestCompleted()!!.id)
    }

    @Test
    fun latestCompletedSkipsActiveRecoveredAndUnpaired() {
        val s = store()
        val done = "00000000-0000-4000-8000-000000000001"
        completeSession(s, done, 1, 10)
        val rec = s.create("00000000-0000-4000-8000-000000000002", "F", 2)
        s.update(rec.id) { it.copy(state = SessionState.RECORDING) }
        s.pcapPartial(rec.id).writeBytes(TestCapture.pcap(1))
        val unpaired = "00000000-0000-4000-8000-000000000003"
        s.create(unpaired, "F", 3)
        s.pcapFinal(unpaired).writeBytes(TestCapture.pcap(1)) // metadata file missing
        s.markFinalized(unpaired, SessionState.COMPLETE, 30, null)
        assertEquals(done, s.latestCompleted()!!.id)
        s.delete(done)
        assertNull(s.latestCompleted())
    }

    @Test
    fun scanTruncatesPartialTrailingRecord() {
        val dir = Files.createTempDirectory("scan").toFile()
        val f = dir.resolve("x.pcap")
        val good = TestCapture.pcap(5)
        f.writeBytes(good + TestCapture.record(100).copyOf(30)) // killed mid-record
        val r = PcapFormat.truncateToValidPrefix(f)
        assertEquals(good.size.toLong(), r.validBytes)
        assertEquals(30L, r.truncatedBytes)
        assertEquals(5L, r.packets)
        assertEquals(good.size.toLong(), f.length())
        // Not a PCAP at all -> nothing valid.
        f.writeBytes(ByteArray(64) { 1 })
        assertEquals(0L, PcapFormat.scan(f).validBytes)
        // Header only (no packets yet) is a valid, empty capture.
        f.writeBytes(TestCapture.pcapHeader())
        assertEquals(24L, PcapFormat.scan(f).validBytes)
    }

    @Test
    fun recoversForceStoppedSessionFromPartialFiles() {
        val s = store()
        val id = "11111111-0000-4000-8000-000000000000"
        s.create(id, "F", 1000)
        s.update(id) { it.copy(state = SessionState.RECORDING) }
        s.pcapPartial(id).writeBytes(TestCapture.pcap(3) + byteArrayOf(1, 0, 0, 0, 99))
        TestCapture.meta(s.metaPartial(id), id, end = null)
        s.metaPartial(id).appendBytes(byteArrayOf(0x10, 0, 0, 0, 64)) // half-written record
        val out = s.recoverInterrupted(null, 9000, 123_000)
        assertEquals(1, out.size)
        assertEquals(SessionState.RECOVERED, out[0].state)
        assertFalse(s.pcapPartial(id).exists())
        assertFalse(s.metaPartial(id).exists())
        assertEquals("$id.pcap", s.pcapFinal(id).name)
        assertEquals(3L, PcapFormat.scan(s.pcapFinal(id)).packets)
        assertEquals(0L, PcapFormat.scan(s.pcapFinal(id)).truncatedBytes)
        val meta = MetaFormat.scan(s.metaFinal(id))
        assertEquals(MetaFormat.END_RECOVERED, meta.endStatus)
        assertEquals(0L, meta.truncatedBytes)
        assertEquals(3L, meta.records) // info, clock, appended SESSION_END
        // Recovered sessions are never "latest complete" (not uploadable as complete).
        assertNull(s.latestCompleted())
        // Idempotent: nothing more to recover.
        assertTrue(s.recoverInterrupted(null, 9500, 1L).isEmpty())
    }

    @Test
    fun recoveryRespectsActiveSessionAndFinishesInterruptedFinalize() {
        val s = store()
        val active = "22222222-0000-4000-8000-000000000000"
        s.create(active, "F", 1)
        s.update(active) { it.copy(state = SessionState.RECORDING) }
        val stopping = "33333333-0000-4000-8000-000000000000"
        s.create(stopping, "F", 2)
        s.update(stopping) { it.copy(state = SessionState.STOPPING) }
        // Killed after both files were finalized but before the COMPLETE state commit.
        s.pcapFinal(stopping).writeBytes(TestCapture.pcap(2))
        TestCapture.meta(s.metaFinal(stopping), stopping)
        val out = s.recoverInterrupted(active, 100, 1L)
        assertEquals(listOf(stopping), out.map { it.id })
        assertEquals(SessionState.COMPLETE, s.get(stopping)!!.state)
        assertEquals(SessionState.RECORDING, s.get(active)!!.state)
        assertEquals(stopping, s.latestCompleted()!!.id)
    }

    @Test
    fun noCaptureFileMeansFailedNotComplete() {
        val s = store()
        val id = "44444444-0000-4000-8000-000000000000"
        s.create(id, "B", 1) // forwarding-only benchmark: no capture file
        s.update(id) { it.copy(state = SessionState.RECORDING) }
        s.recoverInterrupted(null, 2, 1L)
        assertEquals(SessionState.FAILED, s.get(id)!!.state)
    }

    @Test
    fun legacySessionsKeepTheirFileNames() {
        val s = store()
        val id = "55555555-0000-4000-8000-000000000000"
        // A state file written before the format field existed.
        s.dir.resolve("$id.state.json").writeText(JSONObject().put("capture_id", id).put("seq", 1).put("state", "COMPLETE")
            .put("created_ms", 1).put("finalized_ms", 2).put("finalize_seq", 1).toString())
        assertEquals(SessionFormat.LEGACY, s.get(id)!!.format)
        assertEquals("$id.pcapng", s.pcapFinal(id).name)
        assertEquals("$id.meta.json", s.metaFinal(id).name)
        val fresh = s.create("66666666-0000-4000-8000-000000000000", "F", 3)
        assertEquals(SessionFormat.PCAP_META, fresh.format)
        assertEquals("${fresh.id}.meta", s.metaFinal(fresh.id).name)
    }
}
