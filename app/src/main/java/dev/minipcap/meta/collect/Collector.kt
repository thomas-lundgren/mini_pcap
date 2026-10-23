package dev.minipcap.meta.collect

import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.SystemClock
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter
import java.util.concurrent.Executor

/**
 * One independent metadata source. start/stop run on the collector's handler thread;
 * callbacks only encode records into the writer (never block, never touch packets).
 * [source] is the SENSOR_STATUS source reported if start fails.
 */
abstract class Collector(
    protected val ctx: Context,
    protected val w: MetaWriter,
    protected val handler: Handler,
    val source: Int,
) {
    protected val exec = Executor { handler.post(it) }
    protected fun now() = SystemClock.elapsedRealtimeNanos()
    protected fun has(p: String) = ctx.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED
    protected fun status(source: Int, state: Int, detail: String = "") = MetaRecords.sensorStatus(w, now(), source, state, detail)
    abstract fun start()
    abstract fun stop()
}
