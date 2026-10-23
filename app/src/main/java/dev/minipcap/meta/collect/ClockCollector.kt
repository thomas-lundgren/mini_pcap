package dev.minipcap.meta.collect

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter

/**
 * CLOCK_SYNC at start, every [periodMs], on wall-clock/timezone broadcasts and at stop.
 * [clockPair] returns {CLOCK_BOOTTIME ns, CLOCK_REALTIME ns} read back to back with
 * nanosecond precision (native clock_gettime).
 */
class ClockCollector(
    ctx: Context, w: MetaWriter, handler: Handler,
    private val clockPair: () -> LongArray,
    private val periodMs: Long = 60_000,
) : Collector(ctx, w, handler, 0) {
    private val tick = object : Runnable {
        override fun run() {
            sync(MetaFormat.CLOCK_PERIODIC)
            handler.postDelayed(this, periodMs)
        }
    }
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) =
            sync(if (i.action == Intent.ACTION_TIMEZONE_CHANGED) MetaFormat.CLOCK_TZ_CHANGED else MetaFormat.CLOCK_TIME_CHANGED)
    }

    fun sync(reason: Int) {
        val p = clockPair()
        MetaRecords.clockSync(w, p[0], p[1], reason)
    }

    override fun start() {
        sync(MetaFormat.CLOCK_START)
        handler.postDelayed(tick, periodMs)
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_TIME_CHANGED)
            addAction(Intent.ACTION_TIMEZONE_CHANGED)
        }
        // System broadcasts: no export needed; RECEIVER_NOT_EXPORTED is required on API 33+.
        if (Build.VERSION.SDK_INT >= 33) ctx.registerReceiver(receiver, f, null, handler, Context.RECEIVER_NOT_EXPORTED)
        else ctx.registerReceiver(receiver, f, null, handler)
    }

    override fun stop() {
        handler.removeCallbacks(tick)
        runCatching { ctx.unregisterReceiver(receiver) }
    }
}
