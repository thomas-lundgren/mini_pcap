package dev.minipcap.session

import dev.minipcap.capture.PcapFormat
import dev.minipcap.core.AtomicFiles
import dev.minipcap.core.CaptureFile
import dev.minipcap.core.PrivateFile
import dev.minipcap.meta.MetaFormat
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ConcurrentHashMap

enum class SessionState {
    PREPARING, RECORDING, STOPPING, COMPLETE, ERROR, RECOVERED, FAILED;

    val isActive get() = this == PREPARING || this == RECORDING || this == STOPPING
}

/** File layout of a session's pair; [LEGACY] sessions predate ADR-014 and are kept readable only. */
enum class SessionFormat(val id: String, val pcapExt: String, val metaExt: String) {
    PCAP_META("pcap+meta-1", "pcap", "meta"),
    LEGACY("pcapng+json", "pcapng", "meta.json");

    companion object {
        fun of(id: String?) = entries.firstOrNull { it.id == id } ?: LEGACY // records without the field are legacy
    }
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
    val format: SessionFormat = SessionFormat.PCAP_META,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("capture_id", id).put("seq", seq).put("state", state.name).put("created_ms", createdMs)
        .put("finalized_ms", finalizedMs ?: JSONObject.NULL)
        .put("finalize_seq", finalizeSeq ?: JSONObject.NULL)
        .put("variant", variant)
        .put("stop_reason", stopReason ?: JSONObject.NULL)
        .put("error", error ?: JSONObject.NULL)
        .put("format", format.id)

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
            format = SessionFormat.of(if (o.has("format")) o.getString("format") else null),
        )
    }
}

/** A finalized packet + metadata pair, wherever it is stored. */
data class CapturePair(val id: String, val pcap: CaptureFile, val meta: CaptureFile, val finalizedMs: Long, val finalizeSeq: Long)

/**
 * Persistent session registry in app-private storage: one `<id>.state.json` per session
 * next to its files. Ordering uses persisted sequence numbers, never modification times.
 * Use one instance per directory (see [Sessions]): all mutations synchronize on it.
 */
class SessionStore(val dir: File) {
    init {
        dir.mkdirs()
    }

    private val formats = ConcurrentHashMap<String, SessionFormat>()
    private fun format(id: String) = formats.getOrPut(id) { get(id)?.format ?: SessionFormat.PCAP_META }

    fun pcapPartial(id: String) = File(dir, "$id.pcap.partial")
    fun metaPartial(id: String) = File(dir, "$id.meta.partial")
    fun pcapFinal(id: String) = File(dir, "$id.${format(id).pcapExt}")
    fun metaFinal(id: String) = File(dir, "$id.${format(id).metaExt}")
    private fun stateFile(id: String) = File(dir, "$id.state.json")

    @Synchronized
    private fun nextSeq(name: String): Long {
        val f = File(dir, "$name.counter")
        val v = (f.takeIf { it.exists() }?.readText()?.trim()?.toLongOrNull() ?: 0L) + 1
        AtomicFiles.write(f, v.toString())
        return v
    }

    @Synchronized
    fun create(id: String, variant: String, nowMs: Long): SessionRecord {
        val r = SessionRecord(id, nextSeq("session"), SessionState.PREPARING, nowMs, variant = variant)
        save(r)
        return r
    }

    @Synchronized
    fun save(r: SessionRecord) {
        AtomicFiles.write(stateFile(r.id), r.toJson().toString(2))
        formats[r.id] = r.format
    }

    @Synchronized
    fun get(id: String): SessionRecord? =
        stateFile(id).takeIf { it.exists() }?.let { runCatching { SessionRecord.fromJson(JSONObject(it.readText())) }.getOrNull() }

    @Synchronized
    fun update(id: String, f: (SessionRecord) -> SessionRecord): SessionRecord? = get(id)?.let { f(it).also(::save) }

    /** Commits a final state with a new finalization sequence (the "latest" ordering key). */
    @Synchronized
    fun markFinalized(id: String, state: SessionState, nowMs: Long, reason: String?): SessionRecord? =
        update(id) { it.copy(state = state, finalizedMs = nowMs, finalizeSeq = nextSeq("finalize"), stopReason = reason) }

    @Synchronized
    fun list(): List<SessionRecord> =
        dir.listFiles { f -> f.name.endsWith(".state.json") }.orEmpty()
            .mapNotNull { runCatching { SessionRecord.fromJson(JSONObject(it.readText())) }.getOrNull() }
            .sortedByDescending { it.seq }

    /**
     * Newest COMPLETE session by finalization sequence whose two files exist.
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
     * Next-launch recovery for sessions left unfinished by process death (e.g. Android Task
     * Manager "Stop", which delivers no callbacks) or a failed finalization. Runs off the
     * main thread: it scans both files. [nowBootNs] must be CLOCK_BOOTTIME
     * (SystemClock.elapsedRealtimeNanos) since it is written into SESSION_END.
     */
    @Synchronized
    fun recoverInterrupted(activeId: String?, nowMs: Long, nowBootNs: Long): List<SessionRecord> {
        val out = ArrayList<SessionRecord>()
        for (r in list()) {
            val interrupted = r.state.isActive ||
                (r.state == SessionState.ERROR && (pcapPartial(r.id).exists() || metaPartial(r.id).exists()))
            if (!interrupted || r.id == activeId) continue
            out += if (r.format == SessionFormat.PCAP_META) recoverOne(r, nowMs, nowBootNs)
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
        if (!pcap.exists() || PcapFormat.truncateToValidPrefix(pcap).validBytes == 0L) {
            pcap.delete()
            meta.delete()
            return markFinalized(r.id, SessionState.FAILED, nowMs, "process_terminated_no_capture_file")!!
        }
        if (!meta.exists())
            return markFinalized(r.id, SessionState.FAILED, nowMs, "process_terminated_no_metadata_file")!!
        val scan = MetaFormat.recover(meta, nowBootNs, "process_terminated_recovered")
        if (!scan.headerOk)
            return markFinalized(r.id, SessionState.FAILED, nowMs, "process_terminated_metadata_unreadable")!!
        // Both files were completely written (SESSION_END complete); only the final state commit
        // or a rename was lost.
        if (scan.endStatus == MetaFormat.END_COMPLETE)
            return markFinalized(r.id, SessionState.COMPLETE, nowMs, "recovered_after_finalize")!!
        return markFinalized(r.id, SessionState.RECOVERED, nowMs, "process_terminated_recovered")!!
    }
}
