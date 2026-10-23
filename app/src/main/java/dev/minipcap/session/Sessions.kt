package dev.minipcap.session

import android.annotation.SuppressLint
import android.content.Context
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.util.concurrent.CopyOnWriteArraySet

/**
 * Process-wide session registry: the single [SessionStore], the running [CaptureSession],
 * change listeners for the UI, and the transfer lock that keeps a pair from being moved
 * to Downloads while it is uploaded (and vice versa).
 */
object Sessions {
    private const val TAG = "Sessions"

    fun dir(ctx: Context) = File(ctx.applicationContext.filesDir, "captures")

    @Volatile private var store: SessionStore? = null

    fun store(ctx: Context): SessionStore =
        store ?: synchronized(this) { store ?: SessionStore(dir(ctx)).also { store = it } }

    /** The recording in progress, if any (set by the capture service). It holds only the application context. */
    @SuppressLint("StaticFieldLeak")
    @Volatile var active: CaptureSession? = null
    @Volatile var lastResult: String? = null

    val listeners = CopyOnWriteArraySet<() -> Unit>()
    fun notifyListeners() = listeners.forEach { runCatching { it() } }

    private val locked = HashSet<String>()
    @Synchronized fun tryLock(id: String) = locked.add(id)
    @Synchronized fun unlock(id: String) { locked.remove(id) }
    @Synchronized fun isLocked(id: String) = id in locked

    /** Sessions recovered at this launch (shown once by the UI). */
    @Volatile var recovered: List<SessionRecord> = emptyList()
    @Volatile var recoveryDone = false
        private set

    /** Next-launch recovery on a background thread (it scans whole files); then [then]. */
    fun recoverAsync(ctx: Context, then: () -> Unit) {
        val app = ctx.applicationContext
        Thread({
            recovered = try {
                store(app).recoverInterrupted(active?.id, System.currentTimeMillis(), SystemClock.elapsedRealtimeNanos())
            } catch (e: Exception) {
                Log.e(TAG, "recovery failed: ${e.javaClass.simpleName}")
                emptyList()
            }
            recoveryDone = true
            runCatching(then)
            notifyListeners()
        }, "session-recovery").start()
    }
}
