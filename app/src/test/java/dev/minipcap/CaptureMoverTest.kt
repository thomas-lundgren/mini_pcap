package dev.minipcap

import dev.minipcap.storage.CaptureMover
import dev.minipcap.storage.ExportDestination
import dev.minipcap.storage.ExportFile
import dev.minipcap.storage.ExportRecord
import dev.minipcap.storage.ExportStatus
import dev.minipcap.storage.ExportStore
import dev.minipcap.session.SessionState
import dev.minipcap.session.SessionStore
import dev.minipcap.storage.SyncedOutput
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files

/** In-memory stand-in for MediaStore Downloads. */
class FakeDownloads : ExportDestination {
    class Entry(var name: String, var pending: Boolean, var data: ByteArray = ByteArray(0))
    val entries = LinkedHashMap<String, Entry>()
    var space = Long.MAX_VALUE
    var corruptReads = false
    var renameOnCreate = false
    var syncs = 0
    private var next = 1
    override val location = "Download/Test"
    override fun usableSpace() = space
    override fun create(name: String, mime: String): String {
        val ref = "fake://${next++}"
        entries[ref] = Entry(if (renameOnCreate) "$name (1)" else name, true)
        return ref
    }
    override fun nameOf(ref: String) = entries[ref]?.name
    override fun openOutput(ref: String): SyncedOutput {
        val e = entries.getValue(ref)
        val buf = ByteArrayOutputStream()
        return object : SyncedOutput() {
            override fun write(b: Int) = buf.write(b)
            override fun write(b: ByteArray, off: Int, len: Int) = buf.write(b, off, len)
            override fun sync() { syncs++ }
            override fun close() { e.data = buf.toByteArray() }
        }
    }
    override fun openInput(ref: String): InputStream {
        val d = entries.getValue(ref).data.copyOf()
        if (corruptReads && d.isNotEmpty()) d[0] = (d[0].toInt() xor 1).toByte()
        return ByteArrayInputStream(d)
    }
    override fun size(ref: String) = entries[ref]?.data?.size?.toLong()
    override fun publish(ref: String) { entries.getValue(ref).pending = false }
    override fun delete(ref: String) = entries.remove(ref) != null
    override fun findOwn(name: String) = entries.filterValues { it.name == name }.keys.toList()
    fun visible() = entries.values.filter { !it.pending }.map { it.name }.sorted()
}

class CaptureMoverTest {
    private val dir = Files.createTempDirectory("move").toFile()
    private val sessions = SessionStore(dir)
    private val exports = ExportStore(dir)
    private val dest = FakeDownloads()
    private val mover = CaptureMover(sessions, exports, dest)

    private fun complete(id: String, packets: Int = 50, state: SessionState = SessionState.COMPLETE): Pair<ByteArray, ByteArray> {
        sessions.create(id, "F", 1)
        val p = TestCapture.pcap(packets)
        val m = JSONObject().put("capture_id", id).put("status", "complete").put("capture_file", "$id.pcap").toString().toByteArray()
        sessions.pcapFinal(id).writeBytes(p)
        sessions.metaFinal(id).writeBytes(m)
        sessions.markFinalized(id, state, 10, "user_stop")
        return p to m
    }

    private val id = "00000000-0000-4000-8000-0000000000aa"

    @Test
    fun moveCopiesVerifiesPublishesThenDeletesPrivate() {
        val (p, m) = complete(id)
        var last = 0L
        val r = mover.move(id) { done, total -> last = done; assertEquals((p.size + m.size).toLong(), total) }
        assertEquals(ExportStatus.EXPORTED, r.status)
        assertEquals((p.size + m.size).toLong(), last)
        assertEquals(listOf("$id.meta", "$id.pcap"), dest.visible())
        assertEquals(2, dest.syncs)
        assertFalse(sessions.pcapFinal(id).exists())
        assertFalse(sessions.metaFinal(id).exists())
        val pair = mover.pairFor(sessions.get(id)!!)!!
        assertTrue(pair.pcap is ExportFile)
        assertEquals("$id.pcap", pair.pcap.name)
        assertArrayEquals(p, pair.pcap.open().readBytes())
        assertArrayEquals(m, pair.meta.open().readBytes())
        assertEquals(CaptureMover.digest(ByteArrayInputStream(p)), r.pcapSha256)
        // Upload's "latest" selection still finds the moved pair.
        assertEquals(id, sessions.latestCompleted(mover::pairFor)!!.id)
        assertNull(sessions.latestCompleted()) // private-only lookup no longer sees it
    }

    @Test
    fun verificationFailureRollsBackAndKeepsPrivateCopy() {
        complete(id)
        dest.corruptReads = true
        val r = mover.move(id)
        assertEquals(ExportStatus.FAILED, r.status)
        assertTrue(r.lastError!!.contains("Verification failed"))
        assertTrue(dest.entries.isEmpty())
        assertTrue(sessions.pcapFinal(id).isFile && sessions.metaFinal(id).isFile)
        assertNotNull(mover.pairFor(sessions.get(id)!!))
    }

    @Test
    fun cancelRollsBackAndStaysPending() {
        complete(id, packets = 3000)
        var calls = 0
        val r = mover.move(id, cancelled = { ++calls > 1 })
        assertEquals(ExportStatus.NOT_EXPORTED, r.status)
        assertTrue(dest.entries.isEmpty())
        assertTrue(sessions.pcapFinal(id).isFile)
        exports.update(id) { it.copy(status = ExportStatus.QUEUED) }
        calls = 0
        assertEquals(ExportStatus.QUEUED, mover.move(id, cancelled = { ++calls > 1 }).status)
        assertEquals(ExportStatus.EXPORTED, mover.move(id).status)
    }

    @Test
    fun notEnoughSpaceAndNameConflictFailWithoutLosingData() {
        complete(id)
        dest.space = 1000
        assertTrue(mover.move(id).lastError!!.contains("Not enough free space"))
        dest.space = Long.MAX_VALUE
        dest.renameOnCreate = true
        assertTrue(mover.move(id).lastError!!.contains("Name conflict"))
        assertTrue(dest.entries.isEmpty())
        assertTrue(sessions.pcapFinal(id).isFile)
    }

    @Test
    fun onlyFinalizedPairsAreEligible() {
        sessions.create(id, "F", 1)
        sessions.update(id) { it.copy(state = SessionState.RECORDING) }
        sessions.pcapPartial(id).writeBytes(TestCapture.pcap(1))
        assertFalse(mover.eligible(sessions.get(id)!!))
        val unpaired = "00000000-0000-4000-8000-0000000000bb"
        sessions.create(unpaired, "F", 2)
        sessions.pcapFinal(unpaired).writeBytes(TestCapture.pcap(1))
        sessions.markFinalized(unpaired, SessionState.COMPLETE, 3, null)
        assertFalse(mover.eligible(sessions.get(unpaired)!!))
        val rec = "00000000-0000-4000-8000-0000000000cc"
        complete(rec, state = SessionState.RECOVERED)
        assertTrue(mover.eligible(sessions.get(rec)!!))
    }

    @Test
    fun reconcileRollsBackInterruptedMoveAndFinishesCommittedOne() {
        // Crash mid-copy: hidden entries recorded, private pair intact.
        complete(id)
        val ref = dest.create("$id.pcap", "application/octet-stream")
        exports.update(id) { ExportRecord(id, ExportStatus.EXPORTING, pcapRef = ref) }
        // Crash after commit, before deleting private copies.
        val b = "00000000-0000-4000-8000-0000000000bb"
        complete(b)
        mover.move(b)
        sessions.pcapFinal(b).writeBytes(TestCapture.pcap(1))
        sessions.metaFinal(b).writeText("{}")
        assertEquals(setOf(id, b), mover.reconcile().toSet())
        assertEquals(ExportStatus.QUEUED, exports.get(id).status)
        assertFalse(ref in dest.entries)
        assertTrue(sessions.pcapFinal(id).isFile)
        assertFalse(sessions.pcapFinal(b).exists() || sessions.metaFinal(b).exists())
        assertEquals(ExportStatus.EXPORTED, mover.move(id).status)
    }

    @Test
    fun staleHiddenEntriesFromAnUnrecordedCrashAreReplaced() {
        complete(id)
        dest.create("$id.pcap", "application/octet-stream") // ref never recorded
        assertEquals(ExportStatus.EXPORTED, mover.move(id).status)
        assertEquals(listOf("$id.meta", "$id.pcap"), dest.visible())
        assertEquals(2, dest.entries.size)
    }

    @Test
    fun sharedFilesDeletedOutsideTheAppAreReportedMissing() {
        complete(id)
        mover.move(id)
        dest.entries.entries.removeIf { it.value.name.endsWith(".pcap") }
        assertNull(mover.pairFor(sessions.get(id)!!))
        assertNull(sessions.latestCompleted(mover::pairFor))
        assertTrue(mover.deleteExported(id).not()) // the pcap is already gone
        sessions.delete(id)
        assertEquals(ExportStatus.NOT_EXPORTED, exports.get(id).status)
    }
}
