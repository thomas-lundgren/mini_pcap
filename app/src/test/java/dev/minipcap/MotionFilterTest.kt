package dev.minipcap

import dev.minipcap.meta.collect.MotionFilter
import dev.minipcap.meta.collect.MotionMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MotionFilterTest {
    private fun kept(f: MotionFilter, samples: List<Pair<Long, FloatArray>>) = samples.count { (t, v) -> f.keep(t, v) }
    private val ms = 1_000_000L

    @Test
    fun allKeepsEverySample() {
        val s = (0 until 100).map { it * 2 * ms to floatArrayOf(0f, 0f, 9.8f) } // 500 Hz
        assertEquals(100, kept(MotionFilter(MotionMode.ALL, 50, 0.5f), s))
    }

    @Test
    fun maxRateCapsTheRateWithJitterTolerance() {
        val s = (0 until 1000).map { it * 2 * ms to floatArrayOf(0f, 0f, 9.8f) } // 2 s at 500 Hz
        val n = kept(MotionFilter(MotionMode.MAX_RATE, 50, 0.5f), s) // 50 Hz over 2 s, both ends included
        assertTrue("kept $n", n in 100..101)
        // A sensor at the requested rate with 5 % jitter is not decimated.
        val j = (0 until 100).map { (it * 20 * ms + (if (it % 2 == 0) ms else 0)) to floatArrayOf(0f, 0f, 9.8f) }
        assertEquals(100, kept(MotionFilter(MotionMode.MAX_RATE, 50, 0.5f), j))
    }

    @Test
    fun thresholdKeepsChangesAndRefreshesOncePerSecond() {
        val f = MotionFilter(MotionMode.THRESHOLD, 50, 0.5f)
        val still = (0 until 150).map { it * 20 * ms to floatArrayOf(0f, 0f, 9.8f) } // 3 s unchanged
        assertEquals(3, kept(f, still)) // first + one refresh per second
        val g = MotionFilter(MotionMode.THRESHOLD, 50, 0.5f)
        assertEquals(true, g.keep(0, floatArrayOf(0f, 0f, 9.8f)))
        assertEquals(false, g.keep(20 * ms, floatArrayOf(0.4f, 0f, 9.8f)))  // below threshold
        assertEquals(true, g.keep(40 * ms, floatArrayOf(0.6f, 0f, 9.8f)))   // x changed by 0.6
        assertEquals(false, g.keep(60 * ms, floatArrayOf(0.9f, 0f, 9.8f)))  // 0.3 since the last kept sample
    }
}
