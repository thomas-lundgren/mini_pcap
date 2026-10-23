package dev.minipcap.storage

import dev.minipcap.capture.Sidecar
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
) {
    fun toJson(): JSONObject = JSONObject()
        .put("capture_id", id).put("seq", seq).put("state", state.name).put("created_ms", createdMs)
        .put("finalized_ms", finalizedMs ?: JSONObject.NULL)
        .put("finalize_seq", finalizeSeq ?: JSONObject.NULL)
        .put("variant", variant)
        .put("stop_reason", stopReason ?: JSONObject.NULL)
        .put("error", error ?: JSONObject.NULL)

    companion object {
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

    fun pcapPartial(id: String) = File(dir, "$id.pcapng.partial")
    fun pcapFinal(id: String) = File(dir, "$id.pcapng")
    fun metaCheckpoint(id: String) = File(dir, "$id.meta.partial.json")
    fun metaFinal(id: String) = File(dir, "$id.meta.json")
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
        listOf(pcapPartial(id), pcapFinal(id), metaCheckpoint(id), metaFinal(id), stateFile(id),
            File(dir, "$id.upload.json"), File(dir, "$id.export.json")).forEach { it.delete() }
    }

    /**
     * Next-launch recovery for sessions left active by process death (e.g. Android
     * Task Manager "Stop", which delivers no callbacks). Never marks such a session
     * COMPLETE unless finalization had already produced both final artifacts.
     */
    @Synchronized
    fun recoverInterrupted(activeId: String?, nowMs: Long): List<SessionRecord> {
        val out = ArrayList<SessionRecord>()
        for (r in list()) {
            // Active sessions were interrupted; ERROR sessions may still hold a .partial capture.
            val interrupted = r.state.isActive || (r.state == SessionState.ERROR && pcapPartial(r.id).exists())
            if (!interrupted || r.id == activeId) continue
            out += recoverOne(r, nowMs)
        }
        return out
    }

    private fun recoverOne(r: SessionRecord, nowMs: Long): SessionRecord {
        val partial = pcapPartial(r.id)
        val final = pcapFinal(r.id)
        var scan: PcapngRecovery.Result? = null
        if (partial.exists()) {
            scan = PcapngRecovery.truncateToValidPrefix(partial)
            if (scan.validBytes == 0L) {
                partial.delete()
            } else if (!partial.renameTo(final)) {
                return markFinalized(r.id, SessionState.FAILED, nowMs, "recovery_rename_failed")!!
            }
        } else if (final.exists()) {
            scan = PcapngRecovery.truncateToValidPrefix(final)
        }
        // Finalization had fully written the sidecar: only the state commit was lost.
        val existing = metaFinal(r.id).takeIf { it.exists() }?.let { runCatching { JSONObject(it.readText()) }.getOrNull() }
        if (existing != null && existing.optString("status") == "complete" && final.exists() && r.state == SessionState.STOPPING) {
            metaCheckpoint(r.id).delete()
            return markFinalized(r.id, SessionState.COMPLETE, nowMs, existing.optString("stop_reason", "recovered_after_finalize"))!!
        }
        if (scan == null || !final.exists()) {
            metaCheckpoint(r.id).delete()
            return markFinalized(r.id, SessionState.FAILED, nowMs, "process_terminated_no_capture_file")!!
        }
        val base = metaCheckpoint(r.id).takeIf { it.exists() }?.let { runCatching { JSONObject(it.readText()) }.getOrNull() }
            ?: JSONObject()
                .put("schema_version", Sidecar.SCHEMA_VERSION)
                .put("capture_id", r.id)
                .put("capture_point", "android_vpn_tun")
                .put("timestamp_unit", "microseconds_since_unix_epoch")
                .put("started_utc", Sidecar.iso(r.createdMs))
                .put("uid_map", JSONObject())
                .put("flow_uid_map", JSONObject())
                .put("stats", JSONObject())
        base.put("capture_file", "${r.id}.pcapng")
        base.put("status", "recovered")
        base.put("stop_reason", "process_terminated_recovered_on_next_launch")
        base.put("ended_utc", JSONObject.NULL)
        base.put("recovery", JSONObject()
            .put("recovered_utc", Sidecar.iso(nowMs))
            .put("valid_bytes", scan.validBytes)
            .put("truncated_bytes", scan.truncatedBytes)
            .put("records_in_file", scan.packets)
            .put("sidecar_source", if (metaCheckpoint(r.id).exists()) "last_checkpoint" else "minimal")
            .put("note", "uid_map/flow_uid_map/stats reflect the last checkpoint, not the end of capture"))
        writeAtomic(metaFinal(r.id), base.toString(2))
        metaCheckpoint(r.id).delete()
        return markFinalized(r.id, SessionState.RECOVERED, nowMs, "process_terminated_recovered")!!
    }

    companion object {
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

/** Walks PCAPNG blocks and truncates a crash-interrupted file to its last complete block. */
object PcapngRecovery {
    data class Result(val validBytes: Long, val truncatedBytes: Long, val packets: Long)

    fun scan(f: File): Result = RandomAccessFile(f, "r").use { scan(it) }

    fun truncateToValidPrefix(f: File): Result = RandomAccessFile(f, "rw").use { raf ->
        val r = scan(raf)
        if (r.truncatedBytes > 0) {
            raf.setLength(r.validBytes)
            raf.fd.sync()
        }
        r
    }

    private fun le32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xff) or ((b[o + 1].toLong() and 0xff) shl 8) or
            ((b[o + 2].toLong() and 0xff) shl 16) or ((b[o + 3].toLong() and 0xff) shl 24))

    private fun scan(raf: RandomAccessFile): Result {
        val size = raf.length()
        var off = 0L
        var packets = 0L
        val hdr = ByteArray(12)
        val tail = ByteArray(4)
        var first = true
        while (off + 12 <= size) {
            raf.seek(off)
            raf.readFully(hdr)
            val type = le32(hdr, 0)
            val len = le32(hdr, 4)
            if (first && (type != 0x0A0D0D0AL || le32(hdr, 8) != 0x1A2B3C4DL)) break
            if (len < 12 || len % 4 != 0L || off + len > size) break
            raf.seek(off + len - 4)
            raf.readFully(tail)
            if (le32(tail, 0) != len) break
            if (type == 6L) packets++
            off += len
            first = false
        }
        return Result(off, size - off, packets)
    }
}
