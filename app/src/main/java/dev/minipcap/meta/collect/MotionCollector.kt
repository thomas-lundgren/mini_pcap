package dev.minipcap.meta.collect

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Handler
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter
import kotlin.math.abs

/**
 * Sampling decision per sensor stream (pure, allocation free): ALL keeps every sample;
 * MAX_RATE keeps samples on a [hz] schedule (exact on average, 10 % jitter tolerated, no
 * catch-up bursts after a gap); THRESHOLD keeps a sample whose x/y/z changed by at least
 * [threshold] since the last kept one, or after 1 s unchanged.
 */
class MotionFilter(private val mode: MotionMode, hz: Int, private val threshold: Float) {
    private val periodNs = 1_000_000_000L / hz.coerceIn(1, 1000)
    private val toleranceNs = periodNs / 10
    private var nextDue = Long.MIN_VALUE / 2
    private var lastTs = Long.MIN_VALUE / 2
    private val last = FloatArray(3)

    /** True if the sample should be recorded (and is remembered as the last kept one). */
    fun keep(tsNs: Long, v: FloatArray): Boolean {
        val ok = when (mode) {
            MotionMode.ALL -> true
            MotionMode.MAX_RATE -> {
                if (tsNs < nextDue - toleranceNs) return false
                nextDue = if (tsNs - nextDue > periodNs) tsNs + periodNs else nextDue + periodNs
                true
            }
            MotionMode.THRESHOLD -> tsNs - lastTs >= 1_000_000_000L || abs(v[0] - last[0]) >= threshold ||
                abs(v[1] - last[1]) >= threshold || abs(v[2] - last[2]) >= threshold
        }
        if (ok) {
            lastTs = tsNs
            last[0] = v[0]; last[1] = v[1]; last[2] = v[2]
        }
        return ok
    }
}

/**
 * MOTION_SAMPLE straight from sensor events (sensor timestamps, same clock as packets).
 * Uses platform batching (200 ms max report latency) so the CPU wakes rarely.
 */
class MotionCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler, MetaFormat.SRC_ACCEL), SensorEventListener {
    private val sm = ctx.getSystemService(SensorManager::class.java)
    private val periodUs = 1_000_000 / cfg.motionHz.coerceIn(1, 1000)
    private val accel = MotionFilter(cfg.motionMode, cfg.motionHz, cfg.motionThreshold)
    private val gyro = MotionFilter(cfg.motionMode, cfg.motionHz, cfg.motionThreshold)

    override fun onSensorChanged(e: SensorEvent) {
        val isGyro = e.sensor.type == Sensor.TYPE_GYROSCOPE
        if (!(if (isGyro) gyro else accel).keep(e.timestamp, e.values)) return
        MetaRecords.motion(w, e.timestamp, if (isGyro) MetaFormat.SENSOR_GYRO else MetaFormat.SENSOR_ACCEL, e.accuracy, e.values, 3)
    }

    override fun onAccuracyChanged(s: Sensor?, accuracy: Int) {}

    override fun start() {
        register(sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER), MetaFormat.SRC_ACCEL)
        if (cfg.gyro) register(sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE), MetaFormat.SRC_GYRO)
        else status(MetaFormat.SRC_GYRO, MetaFormat.ST_DISABLED_BY_USER)
    }

    private fun register(s: Sensor?, src: Int) {
        if (s == null) {
            status(src, MetaFormat.ST_UNAVAILABLE)
            return
        }
        // Up to 200 ms of samples are delivered in one batch; timestamps stay per sample.
        val ok = runCatching { sm.registerListener(this, s, periodUs, 200_000, handler) }.getOrDefault(false)
        status(src, if (ok) MetaFormat.ST_ACTIVE else MetaFormat.ST_ERROR, "${s.name} ${cfg.motionMode.name.lowercase()} ${cfg.motionHz} Hz")
    }

    override fun stop() {
        sm.flush(this) // deliver the batched FIFO before unregistering (best effort)
        sm.unregisterListener(this)
    }
}
