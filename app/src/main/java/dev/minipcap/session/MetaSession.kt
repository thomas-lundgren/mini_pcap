package dev.minipcap.session

import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.os.Process
import android.os.SystemClock
import android.util.Log
import dev.minipcap.meta.apps.FlowResult
import dev.minipcap.meta.apps.UidInfo
import dev.minipcap.meta.collect.ClockCollector
import dev.minipcap.meta.collect.Collector
import dev.minipcap.meta.collect.LocationCollector
import dev.minipcap.meta.collect.MeasurementConfig
import dev.minipcap.meta.collect.MotionCollector
import dev.minipcap.meta.collect.NetworkCollector
import dev.minipcap.meta.collect.RadioCollector
import java.io.File
import java.util.UUID

/**
 * Metadata side of one recording: the binary writer plus independent collectors on their
 * own threads ("mpc-meta" for state sources, "mpc-sensors" for motion). Nothing here
 * touches the packet path; collectors only enqueue records.
 *
 * Lifecycle: [start] -> records -> [stopCollectors] -> (flow/app records still accepted)
 * -> [finish] (or [abandon] after a failed start).
 */
class MetaSession(
    private val ctx: Context,
    file: File,
    sessionId: UUID,
    anchorBootNs: Long,
    anchorRealNs: Long,
    private val cfg: MeasurementConfig,
    /** {CLOCK_BOOTTIME ns, CLOCK_REALTIME ns} read back to back (native). */
    clockPair: () -> LongArray,
) {
    private fun now() = SystemClock.elapsedRealtimeNanos()

    val writer = MetaWriter(file, sessionId, anchorBootNs, anchorRealNs, now(), clock = { now() })
    private val metaThread = HandlerThread("mpc-meta", Process.THREAD_PRIORITY_BACKGROUND).apply { start() }
    private val sensorThread = HandlerThread("mpc-sensors", Process.THREAD_PRIORITY_BACKGROUND).apply { start() }
    private val meta = Handler(metaThread.looper)
    private val sensors = Handler(sensorThread.looper)
    private val clock = ClockCollector(ctx, writer, meta, clockPair)
    private val collectors = ArrayList<Pair<Collector, Handler>>()

    fun start(info: Map<String, String>) {
        MetaRecords.sessionInfo(writer, now(), info + cfg.asInfo())
        collectors += clock to meta
        if (cfg.gps) collectors += LocationCollector(ctx, writer, meta, cfg) to meta
        else disabled(MetaFormat.SRC_LOCATION, MetaFormat.SRC_GNSS)
        if (cfg.radio) collectors += RadioCollector(ctx, writer, meta, cfg) to meta
        else disabled(MetaFormat.SRC_RADIO, MetaFormat.SRC_CELL_INFO)
        if (cfg.motion) collectors += MotionCollector(ctx, writer, sensors, cfg) to sensors
        else disabled(MetaFormat.SRC_ACCEL, MetaFormat.SRC_GYRO)
        if (cfg.network) collectors += NetworkCollector(ctx, writer, meta, cfg) to meta
        else disabled(MetaFormat.SRC_NETWORK, MetaFormat.SRC_WIFI)
        for ((c, h) in collectors) h.post {
            try {
                c.start()
            } catch (e: Exception) {
                Log.w(TAG, "collector ${c.javaClass.simpleName} failed to start: ${e.javaClass.simpleName}")
                MetaRecords.sensorStatus(writer, now(), c.source, MetaFormat.ST_ERROR, "start: ${e.javaClass.simpleName}")
            }
        }
    }

    private fun disabled(vararg sources: Int) =
        sources.forEach { MetaRecords.sensorStatus(writer, now(), it, MetaFormat.ST_DISABLED_BY_USER, "") }

    fun flow(r: FlowResult) =
        MetaRecords.flowMapping(writer, now(), r.flowId, r.firstSeenNs, r.key, r.uid ?: -1, r.resolution, r.attempts, r.latencyMs)

    fun uid(uid: Int, info: UidInfo) =
        MetaRecords.uidMapping(writer, now(), uid, info.appClass, info.classSource, info.note, info.packages, info.appNames)

    fun stats(counters: Map<String, Long>) = MetaRecords.captureStats(writer, now(), counters)

    /** Stops every collector and waits for their threads; flow/app records are still accepted. */
    fun stopCollectors() {
        for ((c, h) in collectors) h.post { runCatching { c.stop() } }
        metaThread.quitSafely()
        sensorThread.quitSafely()
        metaThread.join(2000)
        sensorThread.join(2000)
    }

    /**
     * Final records (stats, CLOCK_SYNC stop, SESSION_END), then closes the file. Returns true
     * only if the file is complete: every accepted record on disk and SESSION_END last.
     */
    fun finish(status: Int, reason: String, counters: Map<String, Long>): Boolean {
        stats(counters)
        clock.sync(MetaFormat.CLOCK_STOP)
        val endOk = MetaRecords.sessionEnd(writer, now(), status, reason,
            counters + mapOf("meta_records_dropped" to writer.droppedTotal))
        return writer.close() && endOk
    }

    /** After a failed start: stop everything and close without a session end (file is discarded). */
    fun abandon() {
        stopCollectors()
        writer.close()
    }

    companion object {
        private const val TAG = "MetaSession"
    }
}
