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
import dev.minipcap.service.CaptureVpnService
import dev.minipcap.service.Notifications
import dev.minipcap.storage.CaptureFileProvider
import dev.minipcap.storage.SessionState
import dev.minipcap.storage.SessionStore
import org.json.JSONObject
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

        fun stores(ctx: Context): Pair<SessionStore, UploadStore> {
            val dir = CaptureFileProvider.capturesDir(ctx)
            return SessionStore(dir) to UploadStore(dir)
        }

        /** Validates and schedules; returns an error message or null. Call from a visible Activity. */
        fun schedule(ctx: Context, captureId: String): String? {
            if (CaptureVpnService.active != null) return "Stop logging before uploading"
            val (sessions, uploads) = stores(ctx)
            val rec = sessions.get(captureId) ?: return "Unknown capture"
            val pair = sessions.pairFor(rec) ?: return "Capture is not complete (no finalized PCAPNG + sidecar pair)"
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
        try {
            if (CaptureVpnService.active != null) throw UploadException("Stop logging before uploading", false)
            val rec = sessions.get(id) ?: throw UploadException("Capture no longer exists", false)
            if (rec.state != SessionState.COMPLETE) throw UploadException("Capture is not complete", false)
            val pair = sessions.pairFor(rec) ?: throw UploadException("Capture or sidecar file is missing", false)
            val meta = runCatching { JSONObject(pair.meta.readText()) }.getOrNull()
                ?: throw UploadException("Sidecar is not valid JSON", false)
            if (meta.optString("capture_id") != id || meta.optString("status") != "complete" ||
                meta.optString("capture_file") != pair.pcap.name)
                throw UploadException("Sidecar does not match the capture file", false)
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
            val r = uploads.get(id)
            if (Build.VERSION.SDK_INT < 34) nm.cancel(Notifications.ID_UPLOAD)
            if (!stopped) nm.notify(Notifications.ID_UPLOAD + 1, Notification.Builder(this, Notifications.CH_UPLOAD)
                .setSmallIcon(R.drawable.ic_stat_capture)
                .setContentTitle(getString(R.string.n_upload_title, id.take(8)))
                .setContentText(if (r.status == UploadStatus.SUCCEEDED) "Uploaded — receipt ${r.receiptId}" else (r.lastError ?: "Upload failed"))
                .setAutoCancel(true)
                .build())
            listeners.forEach { it() }
            if (!stopped) jobFinished(params, false)
        }
    }
}
