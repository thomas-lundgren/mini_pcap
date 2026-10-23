package dev.minipcap

import dev.minipcap.meta.CellMeasurement
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.util.UUID

/**
 * Performance contract of the metadata path: high-rate producers (motion samples) must not
 * allocate per record and must sustain far more than any sensor rate, without blocking.
 */
class MetaWriterPerfTest {
    private val sid = UUID.fromString("00000000-0000-4000-8000-0000000000bb")
    // Unit tests compile against android.jar (no java.lang.management) but run on a JVM: use reflection.
    private val mx: Any? = runCatching {
        Class.forName("java.lang.management.ManagementFactory").getMethod("getThreadMXBean").invoke(null)
    }.getOrNull()
    private val iface = runCatching { Class.forName("com.sun.management.ThreadMXBean") }.getOrNull()

    private fun allocated(): Long =
        iface!!.getMethod("getThreadAllocatedBytes", Long::class.javaPrimitiveType).invoke(mx, Thread.currentThread().id) as Long

    @Test
    fun motionSamplesDoNotAllocatePerRecord() {
        assumeTrue(mx != null && iface != null && iface.isInstance(mx) &&
            iface.getMethod("isThreadAllocatedMemorySupported").invoke(mx) == true)
        iface!!.getMethod("setThreadAllocatedMemoryEnabled", Boolean::class.javaPrimitiveType).invoke(mx, true)
        val f = Files.createTempFile("perf", ".meta").toFile()
        val w = MetaWriter(f, sid, 0, 0, 0, poolSize = 4096)
        val v = floatArrayOf(0.1f, 9.8f, 0.3f)
        repeat(20_000) { MetaRecords.motion(w, it.toLong(), MetaFormat.SENSOR_ACCEL, 3, v, 3) } // warm up (JIT)
        Thread.sleep(300)
        val n = 50_000
        var accepted = 0
        val a0 = allocated()
        for (i in 0 until n) {
            if (MetaRecords.motion(w, 1_000_000L + i, MetaFormat.SENSOR_ACCEL, 3, v, 3)) accepted++
            if (i % 2000 == 1999) Thread.sleep(1) // let the writer recycle buffers (realistic pacing)
        }
        val perRecord = (allocated() - a0).toDouble() / n
        w.close()
        println("motion emit: %.2f bytes allocated per record on the producer thread (%d/%d accepted)".format(perRecord, accepted, n))
        assertTrue("producer allocates %.1f B/record".format(perRecord), perRecord < 4.0)
    }

    @Test
    fun throughputFarAboveSensorRates() {
        val f = Files.createTempFile("perf", ".meta").toFile()
        val w = MetaWriter(f, sid, 0, 0, 0, poolSize = 4096)
        val v = floatArrayOf(0.1f, 9.8f, 0.3f)
        val cell = listOf(CellMeasurement(MetaFormat.RAT_LTE, true, 1, 0, 123, 6300, 3, arrayOf(-95, -11, 12, -60, 9, 3, null, null)))
        val n = 200_000
        var accepted = 0
        val t0 = System.nanoTime()
        for (i in 0 until n) {
            if (MetaRecords.motion(w, i.toLong(), MetaFormat.SENSOR_ACCEL, 3, v, 3)) accepted++
            if (i % 100 == 0) MetaRecords.signalStrength(w, i.toLong(), true, cell)
        }
        val produceS = (System.nanoTime() - t0) / 1e9
        w.close()
        val totalS = (System.nanoTime() - t0) / 1e9
        val s = MetaFormat.scan(f)
        val rate = s.records / totalS
        println("meta writer: %d records (%.1f MB) in %.2f s = %.0f records/s end-to-end, producer %.0f ns/record, dropped %d"
            .format(s.records, f.length() / 1e6, totalS, rate, produceS * 1e9 / n, w.droppedTotal))
        assertEquals(0L, s.truncatedBytes)
        assertTrue("records lost without being counted", s.records + w.droppedTotal >= n.toLong())
        // A 400 Hz accelerometer + 400 Hz gyroscope is 800 records/s; demand > 100x headroom.
        assertTrue("writer too slow: %.0f records/s".format(rate), rate > 80_000)
    }
}
