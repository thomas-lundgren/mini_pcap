package dev.minipcap

import android.app.Application
import dev.minipcap.notify.Notifications
import dev.minipcap.session.Sessions
import dev.minipcap.storage.ExportJobService
import dev.minipcap.upload.UploadJobService
import dev.minipcap.upload.UploadStore

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        // A fresh process cannot have a running capture, so any session still marked active
        // was interrupted (force-stop, crash, reboot). Recovery scans whole files: run it off
        // the main thread, then reconcile uploads and resume pending moves to Downloads.
        Sessions.recoverAsync(this) {
            val pending = UploadJobService.isPending(this)
            val uploads = UploadStore(Sessions.dir(this))
            Sessions.store(this).list().forEach { uploads.reconcileInterrupted(it.id, pending) }
            ExportJobService.schedule(this)
        }
    }
}
