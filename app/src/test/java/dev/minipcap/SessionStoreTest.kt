package dev.minipcap

import dev.minipcap.storage.PcapngRecovery
import dev.minipcap.storage.SessionState
import dev.minipcap.storage.SessionStore
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
        s.pcapFinal(id).writeBytes(TestPcapng.file(2))
        s.metaFinal(id).writeText(JSONObject().put("capture_id", id).put("status", "complete").toString())
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
            s.pcapFinal(id).writeBytes(TestPcapng.file(1))
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
        s.pcapPartial(rec.id).writeBytes(TestPcapng.file(1))
        val unpaired = "00000000-0000-4000-8000-000000000003"
        s.create(unpaired, "F", 3)
        s.pcapFinal(unpaired).writeBytes(TestPcapng.file(1)) // sidecar missing
        s.markFinalized(unpaired, SessionState.COMPLETE, 30, null)
        assertEquals(done, s.latestCompleted()!!.id)
        s.delete(done)
        assertNull(s.latestCompleted())
    }

    @Test
    fun scanTruncatesPartialTrailingBlock() {
        val dir = Files.createTempDirectory("scan").toFile()
        val f = dir.resolve("x.pcapng")
        val good = TestPcapng.file(5)
        f.writeBytes(good + TestPcapng.epb(100).copyOf(30)) // killed mid-block
        val r = PcapngRecovery.truncateToValidPrefix(f)
        assertEquals(good.size.toLong(), r.validBytes)
        assertEquals(30L, r.truncatedBytes)
        assertEquals(5L, r.packets)
        assertEquals(good.size.toLong(), f.length())
        // Corrupt trailing length -> block rejected.
        val bad = good.copyOf()
        bad[bad.size - 1] = 0x7f
        f.writeBytes(bad)
        assertEquals(4L, PcapngRecovery.scan(f).packets)
        // Not a PCAPNG at all -> nothing valid.
        f.writeBytes(ByteArray(64) { 1 })
        assertEquals(0L, PcapngRecovery.scan(f).validBytes)
    }

    @Test
    fun recoversForceStoppedSessionFromCheckpoint() {
        val s = store()
        val id = "11111111-0000-4000-8000-000000000000"
        s.create(id, "F", 1000)
        s.update(id) { it.copy(state = SessionState.RECORDING) }
        s.pcapPartial(id).writeBytes(TestPcapng.file(3) + byteArrayOf(6, 0, 0, 0, 99))
        s.metaCheckpoint(id).writeText(JSONObject()
            .put("schema_version", 1).put("capture_id", id).put("status", "recording")
            .put("uid_map", JSONObject().put("10234", JSONObject().put("packages", listOf("a.b"))))
            .put("flow_uid_map", JSONObject().put("1", JSONObject().put("uid", 10234)))
            .put("stats", JSONObject()).toString())
        val out = s.recoverInterrupted(null, 9000)
        assertEquals(1, out.size)
        assertEquals(SessionState.RECOVERED, out[0].state)
        assertFalse(s.pcapPartial(id).exists())
        assertFalse(s.metaCheckpoint(id).exists())
        assertEquals(3L, PcapngRecovery.scan(s.pcapFinal(id)).packets)
        assertEquals(0L, PcapngRecovery.scan(s.pcapFinal(id)).truncatedBytes)
        val meta = JSONObject(s.metaFinal(id).readText())
        assertEquals("recovered", meta.getString("status"))
        assertEquals("$id.pcapng", meta.getString("capture_file"))
        assertEquals(10234, meta.getJSONObject("flow_uid_map").getJSONObject("1").getInt("uid"))
        assertEquals(3, meta.getJSONObject("recovery").getInt("records_in_file"))
        // Recovered sessions are never "latest complete" (not uploadable as complete).
        assertNull(s.latestCompleted())
        // Idempotent: nothing more to recover.
        assertTrue(s.recoverInterrupted(null, 9500).isEmpty())
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
        // Killed after sidecar + rename but before the COMPLETE state commit.
        s.pcapFinal(stopping).writeBytes(TestPcapng.file(2))
        s.metaFinal(stopping).writeText(JSONObject().put("capture_id", stopping).put("status", "complete").toString())
        val out = s.recoverInterrupted(active, 100)
        assertEquals(listOf(stopping), out.map { it.id })
        assertEquals(SessionState.COMPLETE, s.get(stopping)!!.state)
        assertEquals(SessionState.RECORDING, s.get(active)!!.state)
        assertEquals(stopping, s.latestCompleted()!!.id)
    }

    @Test
    fun noCaptureFileMeansFailedNotComplete() {
        val s = store()
        val id = "44444444-0000-4000-8000-000000000000"
        s.create(id, "B", 1) // forwarding-only benchmark: no PCAPNG
        s.update(id) { it.copy(state = SessionState.RECORDING) }
        s.recoverInterrupted(null, 2)
        assertEquals(SessionState.FAILED, s.get(id)!!.state)
    }
}
