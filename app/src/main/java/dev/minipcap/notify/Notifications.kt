package dev.minipcap.notify

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import dev.minipcap.R
import java.util.Locale

object Notifications {
    const val CH_CAPTURE = "capture_status"
    const val CH_RESULT = "capture_result"
    const val CH_UPLOAD = "upload_status"
    const val ID_CAPTURE = 1
    const val ID_RESULT = 2
    const val ID_UPLOAD = 3

    fun createChannels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_CAPTURE, ctx.getString(R.string.ch_capture), NotificationManager.IMPORTANCE_LOW).apply {
            setShowBadge(false)
        })
        nm.createNotificationChannel(NotificationChannel(CH_RESULT, ctx.getString(R.string.ch_result), NotificationManager.IMPORTANCE_DEFAULT))
        nm.createNotificationChannel(NotificationChannel(CH_UPLOAD, ctx.getString(R.string.ch_upload), NotificationManager.IMPORTANCE_LOW))
    }

    /** The app's launcher activity (no compile-time dependency on the UI layer). */
    fun appIntent(ctx: Context): Intent =
        (ctx.packageManager.getLaunchIntentForPackage(ctx.packageName) ?: Intent())
            .setPackage(ctx.packageName).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)

    private fun openApp(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx, 0, appIntent(ctx), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    private fun base(ctx: Context, channel: String, title: String, text: String): Notification.Builder =
        Notification.Builder(ctx, channel)
            .setSmallIcon(R.drawable.ic_stat_capture)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(openApp(ctx))
            .setOnlyAlertOnce(true)

    fun starting(ctx: Context): Notification =
        base(ctx, CH_CAPTURE, ctx.getString(R.string.n_starting_title), ctx.getString(R.string.n_starting_text))
            .setOngoing(true).build()

    /** Ongoing recording status with the session-scoped [stop] action (built by the capture service). */
    fun recording(ctx: Context, stop: PendingIntent, elapsedMs: Long, packets: Long?, bytes: Long?): Notification {
        val text = if (packets == null) ctx.getString(R.string.n_recording_static)
        else String.format(Locale.US, "%s • %,d packets • %s", duration(elapsedMs), packets, size(bytes ?: 0))
        val pub = base(ctx, CH_CAPTURE, ctx.getString(R.string.n_recording_title), ctx.getString(R.string.n_recording_static)).build()
        return base(ctx, CH_CAPTURE, ctx.getString(R.string.n_recording_title), text)
            .setOngoing(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(pub)
            .setUsesChronometer(false)
            .addAction(Notification.Action.Builder(null, ctx.getString(R.string.stop_logging), stop).build())
            .build()
    }

    fun stopping(ctx: Context): Notification =
        base(ctx, CH_CAPTURE, ctx.getString(R.string.n_stopping_title), ctx.getString(R.string.n_stopping_text))
            .setOngoing(true).build()

    fun completed(ctx: Context, id: String): Notification =
        base(ctx, CH_RESULT, ctx.getString(R.string.n_saved_title), ctx.getString(R.string.n_saved_text, id.take(8)))
            .setAutoCancel(true).build()

    fun error(ctx: Context, reason: String): Notification =
        base(ctx, CH_RESULT, ctx.getString(R.string.n_error_title), reason).setAutoCancel(true).build()

    fun duration(ms: Long): String {
        val s = ms / 1000
        return if (s >= 3600) String.format(Locale.US, "%d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
        else String.format(Locale.US, "%02d:%02d", s / 60, s % 60)
    }

    fun size(b: Long): String = when {
        b >= 1L shl 30 -> String.format(Locale.US, "%.2f GB", b / 1073741824.0)
        b >= 1L shl 20 -> String.format(Locale.US, "%.1f MB", b / 1048576.0)
        b >= 1L shl 10 -> String.format(Locale.US, "%.1f KB", b / 1024.0)
        else -> "$b B"
    }
}
