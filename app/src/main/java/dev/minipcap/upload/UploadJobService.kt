package dev.minipcap.upload

import android.app.Notification
import android.app.NotificationManager
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.util.Log
import dev.minipcap.R
import dev.minipcap.notify.Notifications
import dev.minipcap.storage.ExportJobService
import dev.minipcap.storage.Exports
import dev.minipcap.meta.MetaFormat
import dev.minipcap.session.SessionRecord
import dev.minipcap.session.SessionState
import dev.minipcap.session.SessionStore
import dev.minipcap.session.SessionFormat
import dev.minipcap.session.Sessions
import java.util.concurrent.CopyOnWriteArraySet

/**
 * User-triggered upload of one finalized capture pair. API 34+: user-initiated
 * data transfer job (visible notification, survives Activity exit); API 29-33:
 * a regular JobScheduler job with a network constraint. Never runs automatically
 * after Stop and never during an active capture.
 */
class UploadJobService : JobService() {

    companion object {
        private const val TAG = "UploadJob"
        const val JOB_ID = 1001
        private const val EXTRA_ID = "capture_id"
        val listeners = CopyOnWriteArraySet<() -> Unit>()
        @Volatile private var cancelRequested = false

        fun stores(ctx: Context): Pair<SessionStore, UploadStore> =
            Sessions.store(ctx) to UploadStore(Sessions.dir(ctx))

        /** Validates and schedules; returns an error message or null. Call from a visible Activity. */
        fun schedule(ctx: Context, captureId: String): String? {
            if (Sessions.active != null) return "Stop logging before uploading"
            val (sessions, uploads) = stores(ctx)
            val rec = sessions.get(captureId) ?: return "Unknown capture"
            if (rec.state != SessionState.COMPLETE) return "Capture is not complete"
            if (rec.format != SessionFormat.PCAP_META) return "Older capture format cannot be uploaded (copy it over USB or share it)"
            if (Sessions.isLocked(captureId)) return "Capture is being moved to Downloads — try again when done"
            val pair = Exports.mover(ctx).pairFor(rec) ?: return "Packet or metadata file is missing (finalized pair not found)"
            uploads.get(captureId).takeIf { it.status == UploadStatus.SUCCEEDED }?.let {
                return "Already uploaded (receipt ${it.receiptId})"
            }
            val settings = UploadSettings(ctx).load()
            UploadSettings.validateUrl(settings.baseUrl)?.let { return "Upload server: $it" }
            val js = ctx.getSystemService(JobScheduler::class.java)
            if (js.getPendingJob(JOB_ID) != null) return "Another upload is already queued or running"
            val extras = PersistableBundle().apply { putString(EXTRA_ID, captureId) }
            val b = JobInfo.Builder(JOB_ID, ComponentName(ctx, UploadJobService::class.java))
                .setExtras(extras)
                .setRequiredNetworkType(if (settings.wifiOnly) JobInfo.NETWORK_TYPE_UNMETERED else JobInfo.NETWORK_TYPE_ANY)
            val bytes = pair.pcap.length() + pair.meta.length()
            b.setEstimatedNetworkBytes(0, bytes)
            if (Build.VERSION.SDK_INT >= 34) b.setUserInitiated(true)
            cancelRequested = false
            val r = try {
                js.schedule(b.build())
            } catch (e: Exception) {
                return "Could not schedule upload: ${e.javaClass.simpleName}"
            }
            if (r != JobScheduler.RESULT_SUCCESS) return "Could not schedule upload"
            uploads.update(captureId) { it.copy(status = UploadStatus.QUEUED, lastError = null, bytesSent = 0, bytesTotal = bytes) }
            listeners.forEach { it() }
            return null
        }

        fun cancel(ctx: Context) {
            cancelRequested = true
            ctx.getSystemService(JobScheduler::class.java).cancel(JOB_ID)
        }

        fun isPending(ctx: Context) = ctx.getSystemService(JobScheduler::class.java).getPendingJob(JOB_ID) != null
    }

    @Volatile private var stopped = false
    private var worker: Thread? = null

    override fun onStartJob(params: JobParameters): Boolean {
        val id = params.extras.getString(EXTRA_ID) ?: return false
        stopped = false
        if (Build.VERSION.SDK_INT >= 34)
            setNotification(params, Notifications.ID_UPLOAD, progressNotification(id, 0, 0, "Preparing upload"),
                JobService.JOB_END_NOTIFICATION_POLICY_REMOVE)
        worker = Thread({ run(params, id) }, "upload").also { it.start() }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        stopped = true
        val id = params.extras.getString(EXTRA_ID) ?: return false
        val (_, uploads) = stores(this)
        val userCancel = cancelRequested ||
            (Build.VERSION.SDK_INT >= 31 && params.stopReason == JobParameters.STOP_REASON_CANCELLED_BY_APP) ||
            (Build.VERSION.SDK_INT >= 34 && params.stopReason == JobParameters.STOP_REASON_USER)
        uploads.update(id) {
            if (it.status == UploadStatus.SUCCEEDED) it
            else if (userCancel) it.copy(status = UploadStatus.CANCELED, lastError = "Canceled — local files kept")
            else it.copy(status = UploadStatus.FAILED, lastError = "Interrupted by the system (network/constraints) — Retry")
        }
        listeners.forEach { it() }
        return false // the user decides whether to retry
    }

    private fun progressNotification(id: String, sent: Long, total: Long, text: String): Notification {
        val b = Notification.Builder(this, Notifications.CH_UPLOAD)
            .setSmallIcon(R.drawable.ic_stat_capture)
            .setContentTitle(getString(R.string.n_upload_title, id.take(8)))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
        if (total > 0) b.setProgress(1000, (sent * 1000 / total).toInt(), false)
        return b.build()
    }

    private fun run(params: JobParameters, id: String) {
        val (sessions, uploads) = stores(this)
        val nm = getSystemService(NotificationManager::class.java)
        var lastUi = 0L
        // Held for the whole upload so the pair cannot be moved to Downloads meanwhile.
        val locked = Sessions.tryLock(id)
        try {
            if (!locked) throw UploadException("Capture is being moved to Downloads — Retry when done", false)
            if (Sessions.active != null) throw UploadException("Stop logging before uploading", false)
            val rec = sessions.get(id) ?: throw UploadException("Capture no longer exists", false)
            if (rec.state != SessionState.COMPLETE) throw UploadException("Capture is not complete", false)
            val pair = Exports.mover(this).pairFor(rec) ?: throw UploadException("Packet or metadata file is missing", false)
            if (rec.format != SessionFormat.PCAP_META)
                throw UploadException("Older capture format (PCAPNG + JSON) cannot be uploaded; copy it over USB or share it", false)
            val scan = pair.meta.open().buffered(1 shl 16).use { MetaFormat.scan(it, pair.meta.length()) }
            if (scan.sessionId?.toString() != id || scan.endStatus != MetaFormat.END_COMPLETE || scan.truncatedBytes != 0L)
                throw UploadException("Metadata file does not match this capture or is incomplete", false)
            val cfg = UploadSettings(this)
            val server = cfg.load()
            UploadSettings.validateUrl(server.baseUrl)?.let { throw UploadException(it, false) }
            uploads.update(id) { it.copy(status = UploadStatus.UPLOADING, attempts = it.attempts + 1, lastError = null) }
            listeners.forEach { it() }
            val pd = UploadClient.sha256(pair.pcap)
            val md = UploadClient.sha256(pair.meta)
            uploads.update(id) { it.copy(captureSha256 = pd.sha256, metadataSha256 = md.sha256) }
            val receipt = UploadClient(server.baseUrl, cfg.token()).upload(id, pair.pcap, pair.meta, pd, md,
                onProgress = { sent, total ->
                    val now = System.currentTimeMillis()
                    if (now - lastUi >= 1000 || sent == total) {
                        lastUi = now
                        uploads.update(id) { it.copy(bytesSent = sent, bytesTotal = total) }
                        nm.notify(Notifications.ID_UPLOAD, progressNotification(id, sent, total,
                            "Uploading ${sent * 100 / maxOf(total, 1)}%"))
                        listeners.forEach { it() }
                    }
                },
                cancelled = { stopped })
            uploads.update(id) {
                it.copy(status = UploadStatus.SUCCEEDED, receiptId = receipt.receiptId, httpStatus = receipt.httpStatus,
                    lastError = null, bytesSent = it.bytesTotal)
            }
        } catch (e: UploadCancelled) {
            // onStopJob already recorded CANCELED/FAILED.
        } catch (e: UploadException) {
            Log.w(TAG, "upload failed: ${e.userMessage}") // no URL, token or content in logs
            if (!stopped) uploads.update(id) {
                it.copy(status = UploadStatus.FAILED, httpStatus = e.httpStatus,
                    lastError = e.userMessage + if (e.retryable) " — Retry" else "")
            }
        } catch (e: Exception) {
            Log.w(TAG, "upload failed: ${e.javaClass.simpleName}")
            if (!stopped) uploads.update(id) { it.copy(status = UploadStatus.FAILED, lastError = "Unexpected error: ${e.javaClass.simpleName}") }
        } finally {
            if (locked) Sessions.unlock(id)
            val r = uploads.get(id)
            if (Build.VERSION.SDK_INT < 34) nm.cancel(Notifications.ID_UPLOAD)
            if (!stopped) nm.notify(Notifications.ID_UPLOAD + 1, Notification.Builder(this, Notifications.CH_UPLOAD)
                .setSmallIcon(R.drawable.ic_stat_capture)
                .setContentTitle(getString(R.string.n_upload_title, id.take(8)))
                .setContentText(if (r.status == UploadStatus.SUCCEEDED) "Uploaded — receipt ${r.receiptId}" else (r.lastError ?: "Upload failed"))
                .setAutoCancel(true)
                .build())
            listeners.forEach { it() }
            ExportJobService.schedule(this) // a move that waited for this upload
            if (!stopped) jobFinished(params, false)
        }
    }
}
