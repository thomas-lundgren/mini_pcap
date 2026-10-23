package dev.minipcap.meta

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.os.Process
import android.os.SystemClock
import dev.minipcap.capture.FlowResult
import dev.minipcap.capture.MeasurementConfig
import dev.minipcap.capture.UidInfo
import java.io.File
import java.util.UUID

/**
 * Metadata side of one recording session: the binary writer plus independent collectors
 * on their own threads ("mpc-meta" for state sources, "mpc-sensors" for motion). Nothing
 * here touches the packet path; collectors only enqueue records.
 */
class MetaSession(
    private val ctx: Context,
    file: File,
    sessionId: UUID,
    anchorBootNs: Long,
    anchorRealNs: Long,
    private val cfg: MeasurementConfig,
) {
    init {
        MetaWriter.clock = { SystemClock.elapsedRealtimeNanos() }
    }

    val writer = MetaWriter(file, sessionId, anchorBootNs, anchorRealNs, SystemClock.elapsedRealtimeNanos())
    private val metaThread = HandlerThread("mpc-meta", Process.THREAD_PRIORITY_BACKGROUND).apply { start() }
    private val sensorThread = HandlerThread("mpc-sensors", Process.THREAD_PRIORITY_BACKGROUND).apply { start() }
    private val meta = Handler(metaThread.looper)
    private val sensors = Handler(sensorThread.looper)
    private val clock = ClockCollector(ctx, writer, meta)
    private val collectors = ArrayList<Pair<Collector, Handler>>()

    private fun now() = SystemClock.elapsedRealtimeNanos()

    fun start(info: Map<String, String>) {
        MetaRecords.sessionInfo(writer, now(), info + cfg.asInfo())
        collectors += clock to meta
        if (cfg.gps) collectors += LocationCollector(ctx, writer, meta, cfg) to meta
        else MetaRecords.sensorStatus(writer, now(), MetaFormat.SRC_LOCATION, MetaFormat.ST_DISABLED_BY_USER, "")
        if (cfg.radio) collectors += RadioCollector(ctx, writer, meta, cfg) to meta
        else MetaRecords.sensorStatus(writer, now(), MetaFormat.SRC_RADIO, MetaFormat.ST_DISABLED_BY_USER, "")
        if (cfg.motion) collectors += MotionCollector(ctx, writer, sensors, cfg) to sensors
        else MetaRecords.sensorStatus(writer, now(), MetaFormat.SRC_ACCEL, MetaFormat.ST_DISABLED_BY_USER, "")
        collectors += NetworkCollector(ctx, writer, meta, cfg) to meta
        for ((c, h) in collectors) h.post { runCatching { c.start() } }
    }

    fun flow(r: FlowResult) =
        MetaRecords.flowMapping(writer, now(), r.flowId, r.firstSeenNs, r.key, r.uid ?: -1, r.resolution, r.attempts, r.latencyMs)

    fun uid(uid: Int, info: UidInfo) =
        MetaRecords.uidMapping(writer, now(), uid, info.appClass, info.classSource, info.note, info.packages, info.appNames)

    fun stats(counters: Map<String, Long>) = MetaRecords.captureStats(writer, now(), counters)

    /** Stop collectors (waiting for their threads), then the final records, then close the file. */
    fun stopCollectors() {
        for ((c, h) in collectors) h.post { runCatching { c.stop() } }
        metaThread.quitSafely()
        sensorThread.quitSafely()
        metaThread.join(2000)
        sensorThread.join(2000)
    }

    fun finish(status: Int, reason: String, counters: Map<String, Long>) {
        stats(counters)
        clock.sync(MetaFormat.CLOCK_STOP)
        MetaRecords.sessionEnd(writer, now(), status, reason, counters + mapOf(
            "meta_records_dropped" to writer.droppedTotal))
        writer.close()
    }
}
