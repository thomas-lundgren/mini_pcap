package dev.minipcap.storage

import android.content.ContentResolver
import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import android.util.Log
import dev.minipcap.upload.UploadStatus
import dev.minipcap.upload.UploadStore
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.CopyOnWriteArraySet

/**
 * Public Download/MiniPcap via MediaStore (API 29+, no storage permission): visible
 * over USB (MTP) and `adb pull /sdcard/Download/MiniPcap/` once published.
 */
class MediaStoreDownloads(ctx: Context) : ExportDestination {
    private val cr: ContentResolver = ctx.contentResolver
    // Shared storage is the emulated /data partition on API 29+ devices.
    private val spaceProbe: File = ctx.filesDir
    private val collection: Uri = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
    private val relPath = Environment.DIRECTORY_DOWNLOADS + "/" + FOLDER + "/"
    override val location = Environment.DIRECTORY_DOWNLOADS + "/" + FOLDER

    override fun usableSpace() = spaceProbe.usableSpace

    override fun create(name: String, mime: String): String {
        val v = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            // octet-stream keeps ".pcapng" (a pcap MIME type would make MediaStore change the extension).
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, relPath)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        return (cr.insert(collection, v) ?: throw IOException("MediaStore insert failed")).toString()
    }

    private fun query(uri: Uri, projection: Array<String>, selection: String? = null, args: Array<String>? = null): Cursor? =
        if (Build.VERSION.SDK_INT >= 30) {
            cr.query(uri, projection, Bundle().apply {
                putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_INCLUDE)
                if (selection != null) {
                    putString(ContentResolver.QUERY_ARG_SQL_SELECTION, selection)
                    putStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS, args)
                }
            }, null)
        } else {
            @Suppress("DEPRECATION")
            cr.query(MediaStore.setIncludePending(uri), projection, selection, args, null)
        }

    override fun nameOf(ref: String): String? =
        runCatching {
            query(Uri.parse(ref), arrayOf(MediaStore.MediaColumns.DISPLAY_NAME))?.use { if (it.moveToFirst()) it.getString(0) else null }
        }.getOrNull()

    override fun openOutput(ref: String): SyncedOutput {
        val pfd = cr.openFileDescriptor(Uri.parse(ref), "w") ?: throw IOException("cannot open export target")
        val out = FileOutputStream(pfd.fileDescriptor)
        return object : SyncedOutput() {
            override fun write(b: Int) = out.write(b)
            override fun write(b: ByteArray, off: Int, len: Int) = out.write(b, off, len)
            override fun sync() = out.fd.sync()
            override fun close() {
                out.close()
                pfd.close()
            }
        }
    }

    override fun openInput(ref: String): InputStream =
        cr.openInputStream(Uri.parse(ref)) ?: throw IOException("cannot read exported file")

    override fun size(ref: String): Long? =
        runCatching { cr.openFileDescriptor(Uri.parse(ref), "r")?.use(ParcelFileDescriptor::getStatSize) }.getOrNull()

    override fun publish(ref: String) {
        val v = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
        if (cr.update(Uri.parse(ref), v, null, null) != 1) throw IOException("publish failed")
    }

    override fun delete(ref: String) = cr.delete(Uri.parse(ref), null, null) > 0

    override fun findOwn(name: String): List<String> {
        val out = ArrayList<String>()
        query(collection, arrayOf(MediaStore.MediaColumns._ID),
            "${MediaStore.MediaColumns.DISPLAY_NAME}=? AND ${MediaStore.MediaColumns.RELATIVE_PATH}=?", arrayOf(name, relPath))
            ?.use { while (it.moveToNext()) out += ContentUris.withAppendedId(collection, it.getLong(0)).toString() }
        return out
    }

    companion object {
        const val FOLDER = "MiniPcap"
    }
}

/**
 * Process-wide coordinator for moving finalized pairs to Downloads. Moves run one at a
 * time in [ExportJobService]; a capture being moved is locked against upload and vice versa.
 */
object Exports {
    private const val TAG = "Exports"
    private const val PREFS = "export"
    private val locked = HashSet<String>()
    val listeners = CopyOnWriteArraySet<() -> Unit>()

    class Progress(val id: String, val done: Long, val total: Long)
    @Volatile var progress: Progress? = null
        private set

    fun autoMove(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("auto_move", true)
    fun setAutoMove(ctx: Context, on: Boolean) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("auto_move", on).apply()

    fun mover(ctx: Context): CaptureMover {
        val dir = CaptureFileProvider.capturesDir(ctx)
        return CaptureMover(SessionStore(dir), ExportStore(dir), MediaStoreDownloads(ctx))
    }

    fun store(ctx: Context) = ExportStore(CaptureFileProvider.capturesDir(ctx))

    @Synchronized fun tryLock(id: String) = locked.add(id)
    @Synchronized fun unlock(id: String) { locked.remove(id) }
    @Synchronized fun isLocked(id: String) = id in locked

    fun notifyListeners() = listeners.forEach { runCatching { it() } }

    /** User action "Move to Downloads" (works with auto-move off, and retries a failed move). */
    fun request(ctx: Context, id: String) {
        store(ctx).update(id) { if (it.status == ExportStatus.EXPORTED) it else it.copy(status = ExportStatus.QUEUED) }
        ExportJobService.schedule(ctx)
        notifyListeners()
    }

    /** Pairs the job should move now, oldest first. */
    fun pending(ctx: Context): List<String> {
        val mover = mover(ctx)
        val exports = store(ctx)
        val auto = autoMove(ctx)
        return SessionStore(CaptureFileProvider.capturesDir(ctx)).list().sortedBy { it.seq }.filter {
            val st = exports.get(it.id).status
            mover.eligible(it) && (st == ExportStatus.QUEUED || (auto && st == ExportStatus.NOT_EXPORTED))
        }.map { it.id }
    }

    /**
     * Moves one pair on the calling (job) thread. Returns false if it was skipped because
     * an upload holds or awaits it; the job retries it after the upload ends.
     */
    fun moveOne(ctx: Context, id: String, cancelled: () -> Boolean): Boolean {
        val up = UploadStore(CaptureFileProvider.capturesDir(ctx)).get(id).status
        if (up == UploadStatus.QUEUED || up == UploadStatus.UPLOADING) return false
        if (!tryLock(id)) return false
        var last = 0L
        try {
            mover(ctx).move(id, cancelled) { done, total ->
                val now = System.currentTimeMillis()
                if (now - last >= 1000 || done == total) {
                    last = now
                    progress = Progress(id, done, total)
                    notifyListeners()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "move failed: ${e.javaClass.simpleName}")
            store(ctx).update(id) { it.copy(status = ExportStatus.FAILED, lastError = e.message ?: e.javaClass.simpleName) }
        } finally {
            progress = null
            unlock(id)
            notifyListeners()
        }
        return true
    }
}
