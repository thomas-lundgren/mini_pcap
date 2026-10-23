package dev.minipcap

import android.app.Application
import android.util.Log
import dev.minipcap.service.Notifications
import dev.minipcap.storage.CaptureFileProvider
import dev.minipcap.storage.ExportJobService
import dev.minipcap.storage.SessionRecord
import dev.minipcap.storage.SessionStore
import dev.minipcap.upload.UploadJobService
import dev.minipcap.upload.UploadStore

class App : Application() {
    /** Sessions recovered at this launch (shown once by the UI). */
    @Volatile var recovered: List<SessionRecord> = emptyList()

    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        // A fresh process cannot have a running capture, so any session still marked
        // active was interrupted (force-stop, crash, reboot): recover it now.
        val dir = CaptureFileProvider.capturesDir(this)
        val store = SessionStore(dir)
        recovered = try {
            store.recoverInterrupted(activeId = null, nowMs = System.currentTimeMillis(),
                nowBootNs = android.os.SystemClock.elapsedRealtimeNanos())
        } catch (e: Exception) {
            Log.e("App", "recovery failed: ${e.javaClass.simpleName}")
            emptyList()
        }
        val pending = UploadJobService.isPending(this)
        val uploads = UploadStore(dir)
        store.list().forEach { uploads.reconcileInterrupted(it.id, pending) }
        // The job first finishes or rolls back an interrupted move to Downloads, then moves pending pairs.
        ExportJobService.schedule(this)
    }
}
