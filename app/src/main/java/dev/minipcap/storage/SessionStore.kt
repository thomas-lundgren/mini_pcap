package dev.minipcap.storage

import dev.minipcap.meta.MetaFormat
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile

enum class SessionState { PREPARING, RECORDING, STOPPING, COMPLETE, ERROR, RECOVERED, FAILED;
    val isActive get() = this == PREPARING || this == RECORDING || this == STOPPING
}

data class SessionRecord(
    val id: String,
    val seq: Long,
    val state: SessionState,
    val createdMs: Long,
    val finalizedMs: Long? = null,
    val finalizeSeq: Long? = null,
    val variant: String = "F",
    val stopReason: String? = null,
    val error: String? = null,
    /** File format: [FORMAT_PCAP_META] (pcap + binary meta) or [FORMAT_LEGACY] (pcapng + JSON sidecar). */
    val format: String = FORMAT_PCAP_META,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("capture_id", id).put("seq", seq).put("state", state.name).put("created_ms", createdMs)
        .put("finalized_ms", finalizedMs ?: JSONObject.NULL)
        .put("finalize_seq", finalizeSeq ?: JSONObject.NULL)
        .put("variant", variant)
        .put("stop_reason", stopReason ?: JSONObject.NULL)
        .put("error", error ?: JSONObject.NULL)
        .put("format", format)

    companion object {
        const val FORMAT_PCAP_META = "pcap+meta-1"
        const val FORMAT_LEGACY = "pcapng+json"

        fun fromJson(o: JSONObject) = SessionRecord(
            id = o.getString("capture_id"),
            seq = o.getLong("seq"),
            state = SessionState.valueOf(o.getString("state")),
            createdMs = o.getLong("created_ms"),
            finalizedMs = if (o.isNull("finalized_ms")) null else o.getLong("finalized_ms"),
            finalizeSeq = if (o.isNull("finalize_seq")) null else o.getLong("finalize_seq"),
            variant = o.optString("variant", "F"),
            stopReason = if (o.isNull("stop_reason")) null else o.optString("stop_reason"),
            error = if (o.isNull("error")) null else o.optString("error"),
            format = o.optString("format", FORMAT_LEGACY), // records from before the format field
        )
    }
}

/** An immutable, finalized capture + sidecar pair eligible for upload/export. */
data class CapturePair(val id: String, val pcap: CaptureFile, val meta: CaptureFile, val finalizedMs: Long, val finalizeSeq: Long)

/**
 * Persistent session registry in app-private storage. One `<id>.state.json` per
 * session plus the artifacts. Ordering uses persisted sequence numbers, never file
 * modification times.
 */
class SessionStore(val dir: File) {
    init {
        dir.mkdirs()
    }

    private val formats = java.util.concurrent.ConcurrentHashMap<String, String>()
    private fun format(id: String) = formats[id] ?: (get(id)?.format ?: SessionRecord.FORMAT_PCAP_META).also { formats[id] = it }

    fun pcapPartial(id: String) = File(dir, "$id.pcap.partial")
    fun metaPartial(id: String) = File(dir, "$id.meta.partial")
    fun pcapFinal(id: String) = File(dir, pcapName(id, format(id)))
    fun metaFinal(id: String) = File(dir, metaName(id, format(id)))
    private fun stateFile(id: String) = File(dir, "$id.state.json")

    @Synchronized
    private fun nextSeq(name: String): Long {
        val f = File(dir, "$name.counter")
        val v = (f.takeIf { it.exists() }?.readText()?.trim()?.toLongOrNull() ?: 0L) + 1
        writeAtomic(f, v.toString())
        return v
    }

    @Synchronized
    fun create(id: String, variant: String, nowMs: Long): SessionRecord {
        val r = SessionRecord(id, nextSeq("session"), SessionState.PREPARING, nowMs, variant = variant)
        save(r)
        return r
    }

    @Synchronized
    fun save(r: SessionRecord) = writeAtomic(stateFile(r.id), r.toJson().toString(2))

    @Synchronized
    fun get(id: String): SessionRecord? =
        stateFile(id).takeIf { it.exists() }?.let { runCatching { SessionRecord.fromJson(JSONObject(it.readText())) }.getOrNull() }

    @Synchronized
    fun update(id: String, f: (SessionRecord) -> SessionRecord): SessionRecord? = get(id)?.let { f(it).also(::save) }

    /** Commits COMPLETE with a new finalization sequence (the "latest" ordering key). */
    @Synchronized
    fun markFinalized(id: String, state: SessionState, nowMs: Long, reason: String?): SessionRecord? =
        update(id) { it.copy(state = state, finalizedMs = nowMs, finalizeSeq = nextSeq("finalize"), stopReason = reason) }

    @Synchronized
    fun list(): List<SessionRecord> =
        dir.listFiles { f -> f.name.endsWith(".state.json") }.orEmpty()
            .mapNotNull { runCatching { SessionRecord.fromJson(JSONObject(it.readText())) }.getOrNull() }
            .sortedByDescending { it.seq }

    /**
     * Newest COMPLETE session by finalization sequence whose two artifacts both exist.
     * [pairOf] locates the pair (private by default; CaptureMover also finds moved pairs).
     */
    @Synchronized
    fun latestCompleted(pairOf: (SessionRecord) -> CapturePair? = ::pairFor): CapturePair? = list()
        .filter { it.state == SessionState.COMPLETE && it.finalizeSeq != null }
        .sortedWith(compareByDescending<SessionRecord> { it.finalizeSeq }.thenByDescending { it.id })
        .firstNotNullOfOrNull { pairOf(it) }

    @Synchronized
    fun pairFor(r: SessionRecord): CapturePair? {
        val p = pcapFinal(r.id)
        val m = metaFinal(r.id)
        if (r.state != SessionState.COMPLETE || !p.isFile || !m.isFile) return null
        return CapturePair(r.id, PrivateFile(p), PrivateFile(m), r.finalizedMs ?: 0, r.finalizeSeq ?: 0)
    }

    @Synchronized
    fun delete(id: String) {
        listOf(pcapPartial(id), metaPartial(id), pcapFinal(id), metaFinal(id), stateFile(id),
            File(dir, "$id.upload.json"), File(dir, "$id.export.json")).forEach { it.delete() }
        formats.remove(id)
    }

    /**
     * Next-launch recovery for sessions left active by process death (e.g. Android
     * Task Manager "Stop", which delivers no callbacks). Never marks such a session
     * COMPLETE unless finalization had already produced both final artifacts.
     */
    @Synchronized
    fun recoverInterrupted(activeId: String?, nowMs: Long, nowBootNs: Long = System.nanoTime()): List<SessionRecord> {
        val out = ArrayList<SessionRecord>()
        for (r in list()) {
            // Active sessions were interrupted; ERROR sessions may still hold .partial files.
            val interrupted = r.state.isActive ||
                (r.state == SessionState.ERROR && (pcapPartial(r.id).exists() || metaPartial(r.id).exists()))
            if (!interrupted || r.id == activeId) continue
            out += if (r.format == SessionRecord.FORMAT_PCAP_META) recoverOne(r, nowMs, nowBootNs)
                else markFinalized(r.id, SessionState.FAILED, nowMs, "legacy_session_interrupted")!!
        }
        return out
    }

    private fun recoverOne(r: SessionRecord, nowMs: Long, nowBootNs: Long): SessionRecord {
        val pcap = pcapFinal(r.id)
        val meta = metaFinal(r.id)
        for ((partial, final) in listOf(pcapPartial(r.id) to pcap, metaPartial(r.id) to meta))
            if (partial.exists() && !partial.renameTo(final))
                return markFinalized(r.id, SessionState.FAILED, nowMs, "recovery_rename_failed")!!
        if (!pcap.exists() || PcapRecovery.truncateToValidPrefix(pcap).validBytes == 0L) {
            pcap.delete()
            meta.delete()
            return markFinalized(r.id, SessionState.FAILED, nowMs, "process_terminated_no_capture_file")!!
        }
        if (!meta.exists())
            return markFinalized(r.id, SessionState.FAILED, nowMs, "process_terminated_no_metadata_file")!!
        val scan = MetaFormat.recover(meta, nowBootNs, "process_terminated_recovered")
        if (!scan.headerOk)
            return markFinalized(r.id, SessionState.FAILED, nowMs, "process_terminated_metadata_unreadable")!!
        // Finalization had fully written both files: only the state commit was lost.
        if (scan.endStatus == MetaFormat.END_COMPLETE && r.state == SessionState.STOPPING)
            return markFinalized(r.id, SessionState.COMPLETE, nowMs, "recovered_after_finalize")!!
        return markFinalized(r.id, SessionState.RECOVERED, nowMs, "process_terminated_recovered")!!
    }

    companion object {
        fun pcapName(id: String, format: String) = if (format == SessionRecord.FORMAT_LEGACY) "$id.pcapng" else "$id.pcap"
        fun metaName(id: String, format: String) = if (format == SessionRecord.FORMAT_LEGACY) "$id.meta.json" else "$id.meta"

        fun writeAtomic(target: File, text: String) {
            val tmp = File(target.parentFile, target.name + ".tmp")
            FileOutputStream(tmp).use { out ->
                out.write(text.toByteArray(Charsets.UTF_8))
                out.fd.sync()
            }
            if (!tmp.renameTo(target)) {
                tmp.delete()
                throw java.io.IOException("rename failed: ${target.name}")
            }
        }
    }
}

/** Cuts a crash-interrupted classic PCAP file back to its last complete record. */
object PcapRecovery {
    data class Result(val validBytes: Long, val truncatedBytes: Long, val packets: Long)

    fun truncateToValidPrefix(f: File): Result = RandomAccessFile(f, "rw").use { raf ->
        val r = scan(raf)
        if (r.truncatedBytes > 0) {
            raf.setLength(r.validBytes)
            raf.fd.sync()
        }
        r
    }

    fun scan(f: File): Result = RandomAccessFile(f, "r").use { scan(it) }

    private fun scan(raf: RandomAccessFile): Result {
        val size = raf.length()
        if (size < 24) return Result(0, size, 0)
        val hdr = ByteArray(16)
        raf.seek(0)
        raf.readFully(hdr, 0, 4)
        val magic = java.nio.ByteBuffer.wrap(hdr, 0, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).int
        if (magic != 0xA1B23C4D.toInt() && magic != 0xA1B2C3D4.toInt()) return Result(0, size, 0)
        var off = 24L
        var packets = 0L
        while (off + 16 <= size) {
            raf.seek(off)
            raf.readFully(hdr)
            val incl = java.nio.ByteBuffer.wrap(hdr, 8, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xffffffffL
            if (off + 16 + incl > size) break
            off += 16 + incl
            packets++
        }
        return Result(off, size - off, packets)
    }
}
