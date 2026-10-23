package dev.minipcap.storage

import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/** One artifact of a finalized pair, either in app-private storage or moved to shared storage. */
interface CaptureFile {
    val name: String
    fun length(): Long
    fun open(): InputStream
}

class PrivateFile(val file: File) : CaptureFile {
    override val name: String get() = file.name
    override fun length() = file.length()
    override fun open(): InputStream = FileInputStream(file)
}

/**
 * Shared-storage target (MediaStore Downloads on Android). Entries are created
 * hidden ("pending") and only become visible to other apps/USB after [publish].
 */
interface ExportDestination {
    /** Human-readable folder, e.g. "Download/MiniPcap". */
    val location: String
    fun usableSpace(): Long
    /** Creates a hidden entry and returns its id (a content URI string on Android). */
    fun create(name: String, mime: String): String
    /** Display name actually assigned, or null if the entry no longer exists. */
    fun nameOf(ref: String): String?
    fun openOutput(ref: String): SyncedOutput
    fun openInput(ref: String): InputStream
    fun size(ref: String): Long?
    fun publish(ref: String)
    fun delete(ref: String): Boolean
    /** This app's entries (hidden or not) in the folder with exactly this name. */
    fun findOwn(name: String): List<String>
}

/** Output that is flushed to stable storage by [sync] before close. */
abstract class SyncedOutput : OutputStream() {
    abstract fun sync()
}

class ExportFile(private val dest: ExportDestination, val ref: String, override val name: String, private val size: Long) : CaptureFile {
    override fun length() = dest.size(ref) ?: size
    override fun open(): InputStream = dest.openInput(ref)
}

/** QUEUED = requested by the user; NOT_EXPORTED pairs move only when auto-move is on. */
enum class ExportStatus { NOT_EXPORTED, QUEUED, EXPORTING, EXPORTED, FAILED }

data class ExportRecord(
    val captureId: String,
    val status: ExportStatus = ExportStatus.NOT_EXPORTED,
    val pcapRef: String? = null,
    val metaRef: String? = null,
    val pcapSize: Long = 0,
    val metaSize: Long = 0,
    val pcapSha256: String? = null,
    val metaSha256: String? = null,
    val location: String? = null,
    val lastError: String? = null,
    val updatedMs: Long = 0,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("capture_id", captureId).put("status", status.name)
        .put("pcap_ref", pcapRef ?: JSONObject.NULL).put("meta_ref", metaRef ?: JSONObject.NULL)
        .put("pcap_size", pcapSize).put("meta_size", metaSize)
        .put("pcap_sha256", pcapSha256 ?: JSONObject.NULL).put("meta_sha256", metaSha256 ?: JSONObject.NULL)
        .put("location", location ?: JSONObject.NULL)
        .put("last_error", lastError ?: JSONObject.NULL)
        .put("updated_ms", updatedMs)

    companion object {
        private fun JSONObject.str(k: String) = if (isNull(k)) null else optString(k)
        fun fromJson(o: JSONObject) = ExportRecord(
            captureId = o.getString("capture_id"),
            status = ExportStatus.valueOf(o.getString("status")),
            pcapRef = o.str("pcap_ref"), metaRef = o.str("meta_ref"),
            pcapSize = o.optLong("pcap_size"), metaSize = o.optLong("meta_size"),
            pcapSha256 = o.str("pcap_sha256"), metaSha256 = o.str("meta_sha256"),
            location = o.str("location"), lastError = o.str("last_error"),
            updatedMs = o.optLong("updated_ms"),
        )
    }
}

/** Export state per capture, stored next to the session record in app-private storage. */
class ExportStore(private val dir: File) {
    private fun file(id: String) = File(dir, "$id.export.json")

    @Synchronized
    fun get(id: String): ExportRecord =
        file(id).takeIf { it.exists() }?.let { runCatching { ExportRecord.fromJson(JSONObject(it.readText())) }.getOrNull() }
            ?: ExportRecord(id)

    @Synchronized
    fun update(id: String, f: (ExportRecord) -> ExportRecord): ExportRecord {
        val r = f(get(id)).copy(updatedMs = System.currentTimeMillis())
        SessionStore.writeAtomic(file(id), r.toJson().toString(2))
        return r
    }
}

/**
 * Moves a finalized pair out of app-private storage (docs/DECISIONS.md ADR-012):
 * copy both files into hidden entries, fsync, read back and compare SHA-256 with
 * the source, publish, commit EXPORTED, and only then delete the private copies.
 * A crash at any point leaves at least one complete, verified copy; [reconcile]
 * finishes or rolls back an interrupted move on the next launch.
 */
class CaptureMover(
    private val sessions: SessionStore,
    private val exports: ExportStore,
    private val dest: ExportDestination,
) {
    class MoveException(message: String) : Exception(message)
    class MoveCancelled : Exception("canceled")

    /** Sessions whose finalized files may be moved: never active, never `.partial`. */
    fun eligible(r: SessionRecord): Boolean =
        (r.state == SessionState.COMPLETE || r.state == SessionState.RECOVERED) &&
            sessions.pcapFinal(r.id).isFile && sessions.metaFinal(r.id).isFile

    /**
     * The pair for upload/share: the moved copy when exported, else the private one.
     * Returns null for a moved pair whose shared files were deleted outside the app.
     */
    fun pairFor(r: SessionRecord): CapturePair? {
        if (r.state != SessionState.COMPLETE && r.state != SessionState.RECOVERED) return null
        val e = exports.get(r.id)
        if (e.status != ExportStatus.EXPORTED) {
            if (!sessions.pcapFinal(r.id).isFile || !sessions.metaFinal(r.id).isFile) return null
            return CapturePair(r.id, PrivateFile(sessions.pcapFinal(r.id)), PrivateFile(sessions.metaFinal(r.id)),
                r.finalizedMs ?: 0, r.finalizeSeq ?: 0)
        }
        val pn = sessions.pcapFinal(r.id).name
        val mn = sessions.metaFinal(r.id).name
        val p = e.pcapRef?.takeIf { dest.nameOf(it) == pn } ?: return null
        val m = e.metaRef?.takeIf { dest.nameOf(it) == mn } ?: return null
        return CapturePair(r.id, ExportFile(dest, p, pn, e.pcapSize), ExportFile(dest, m, mn, e.metaSize),
            r.finalizedMs ?: 0, r.finalizeSeq ?: 0)
    }

    fun move(id: String, cancelled: () -> Boolean = { false }, onProgress: (done: Long, total: Long) -> Unit = { _, _ -> }): ExportRecord {
        val r = sessions.get(id) ?: throw MoveException("Unknown capture")
        val before = exports.get(id).status
        if (before == ExportStatus.EXPORTED) return exports.get(id)
        if (!eligible(r)) throw MoveException("Capture is not finalized (no PCAPNG + sidecar pair)")
        val pcap = sessions.pcapFinal(id)
        val meta = sessions.metaFinal(id)
        val total = pcap.length() + meta.length()
        if (dest.usableSpace() < total + SPACE_MARGIN)
            return fail(id, "Not enough free space to move (needs ${(total + SPACE_MARGIN) shr 20} MB free) — kept in app storage")
        removeStale(id)
        exports.update(id) { ExportRecord(id, ExportStatus.EXPORTING, location = dest.location) }
        try {
            var done = 0L
            val progress = { n: Long ->
                if (cancelled()) throw MoveCancelled()
                done += n
                onProgress(done, total)
            }
            // octet-stream keeps the file extension (a pcap MIME type would make MediaStore rename it).
            val pRef = dest.create(pcap.name, "application/octet-stream")
            exports.update(id) { it.copy(pcapRef = pRef) }
            val mRef = dest.create(meta.name, if (meta.name.endsWith(".json")) "application/json" else "application/octet-stream")
            exports.update(id) { it.copy(metaRef = mRef) }
            for ((ref, want) in listOf(pRef to pcap.name, mRef to meta.name))
                if (dest.nameOf(ref) != want) throw MoveException("Name conflict in ${dest.location} (got ${dest.nameOf(ref)})")
            val pSha = copy(pcap, pRef, progress)
            val mSha = copy(meta, mRef, progress)
            if (digest(dest.openInput(pRef)) != pSha || digest(dest.openInput(mRef)) != mSha)
                throw MoveException("Verification failed: copy in ${dest.location} differs from the original")
            dest.publish(mRef)
            dest.publish(pRef)
            exports.update(id) {
                it.copy(status = ExportStatus.EXPORTED, pcapSize = pcap.length(), metaSize = meta.length(),
                    pcapSha256 = pSha, metaSha256 = mSha, lastError = null)
            }
        } catch (e: MoveCancelled) {
            rollback(id)
            val again = if (before == ExportStatus.QUEUED) ExportStatus.QUEUED else ExportStatus.NOT_EXPORTED
            return exports.update(id) { it.copy(status = again, lastError = "Move paused by the system — will retry") }
        } catch (e: Exception) {
            rollback(id)
            return fail(id, "Move failed: ${e.message ?: e.javaClass.simpleName} — kept in app storage")
        }
        deletePrivate(id)
        return exports.get(id)
    }

    /**
     * Next launch: an interrupted move (EXPORTING) is rolled back while the private
     * pair is intact; a committed move whose private copies survived is completed.
     */
    fun reconcile(): List<String> {
        val touched = ArrayList<String>()
        for (r in sessions.list()) {
            val e = exports.get(r.id)
            when (e.status) {
                ExportStatus.EXPORTING -> {
                    if (sessions.pcapFinal(r.id).isFile && sessions.metaFinal(r.id).isFile) {
                        rollback(r.id)
                        // The interrupted move was already started (auto or by the user): retry it.
                        exports.update(r.id) {
                            it.copy(status = ExportStatus.QUEUED, lastError = "Previous move was interrupted — kept in app storage")
                        }
                    } else {
                        fail(r.id, "Move was interrupted and the app copy is incomplete — check ${dest.location}")
                    }
                    touched += r.id
                }
                ExportStatus.EXPORTED -> if (sessions.pcapFinal(r.id).exists() || sessions.metaFinal(r.id).exists()) {
                    deletePrivate(r.id)
                    touched += r.id
                }
                else -> {}
            }
        }
        return touched
    }

    /** Deletes the shared copies this app created for the capture (private ones via SessionStore). */
    fun deleteExported(id: String): Boolean {
        val e = exports.get(id)
        return listOfNotNull(e.pcapRef, e.metaRef).map { runCatching { dest.delete(it) }.getOrDefault(false) }.all { it }
    }

    private fun copy(src: File, ref: String, progress: (Long) -> Unit): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(1 shl 20)
        val out = dest.openOutput(ref)
        try {
            FileInputStream(src).use { inp ->
                while (true) {
                    val n = inp.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                    out.write(buf, 0, n)
                    progress(n.toLong())
                }
            }
            out.sync()
        } finally {
            out.close()
        }
        if (dest.size(ref)?.let { it != src.length() } == true) throw IOException("size mismatch after copy")
        return hex(md.digest())
    }

    private fun rollback(id: String) {
        val e = exports.get(id)
        listOfNotNull(e.pcapRef, e.metaRef).forEach { runCatching { dest.delete(it) } }
        exports.update(id) { it.copy(pcapRef = null, metaRef = null) }
    }

    /** Leftover hidden entries from a move that crashed before its refs were recorded. */
    private fun removeStale(id: String) {
        for (n in listOf(sessions.pcapFinal(id).name, sessions.metaFinal(id).name))
            dest.findOwn(n).forEach { runCatching { dest.delete(it) } }
    }

    private fun deletePrivate(id: String) {
        sessions.pcapFinal(id).delete()
        sessions.metaFinal(id).delete()
    }

    private fun fail(id: String, msg: String) =
        exports.update(id) { it.copy(status = ExportStatus.FAILED, lastError = msg) }

    companion object {
        /** Extra free space kept when moving, so the copy itself cannot fill the device. */
        const val SPACE_MARGIN = 64L shl 20

        fun digest(inp: InputStream): String = inp.use {
            val md = MessageDigest.getInstance("SHA-256")
            val buf = ByteArray(1 shl 20)
            while (true) {
                val n = it.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
            hex(md.digest())
        }

        private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }
}
