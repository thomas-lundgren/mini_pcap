package dev.minipcap.capture

import java.nio.ByteBuffer

/**
 * JNI facade for the native packet path. Every call is lifecycle or batched control:
 * start/stop, ~1 Hz counter snapshots and clock pairs, batched new-flow announcements.
 * No method is invoked per packet.
 */
object NativeCore {
    init {
        System.loadLibrary("mpcnative")
    }

    /** New-flow announcement shared through a direct buffer: flow_id u64, key[40], first_seen_ns u64. */
    const val FLOW_REQUEST_BYTES = 56

    val counterNames: List<String> by lazy { nativeCounterNames().toList() }
    private val counterIndex: Map<String, Int> by lazy { counterNames.withIndex().associate { (i, n) -> n to i } }

    fun counterIndex(name: String): Int = counterIndex[name] ?: -1

    @JvmStatic external fun nativeCounterNames(): Array<String>

    /**
     * Starts forwarding + capture on [tunFd] (ownership passes to native code, also on failure).
     * [snaplen]: IP bytes kept per packet, 0 = full, -1 = headers only; at least the IP +
     * transport header is always kept. Returns an opaque handle (tagged pointer, may be
     * negative) or -errno in [-4095, -1].
     */
    @JvmStatic external fun nativeStart(tunFd: Int, pcapPath: String?, snaplen: Int, mtu: Int, variant: Int, ringBytes: Int): Long

    /** Ordered stop: quiesce tap, stop forwarding/close TUN, drain + fsync the PCAP. 0 = file complete. */
    @JvmStatic external fun nativeStop(handle: Long): Int

    @JvmStatic external fun nativeDestroy(handle: Long)

    @JvmStatic external fun nativeCounters(handle: Long, out: LongArray): Int

    /** Blocks up to [timeoutMs]; returns the number of announcements written to [buf], or -1 once closed. */
    @JvmStatic external fun nativeUidPoll(handle: Long, buf: ByteBuffer, max: Int, timeoutMs: Int): Int

    /** Benchmark-only synthetic writer stall (PERFORMANCE_PLAN V32). */
    @JvmStatic external fun nativeWriterStall(handle: Long, ms: Int)

    /** out[0] = CLOCK_BOOTTIME ns, out[1] = CLOCK_REALTIME ns, read back to back in native code. */
    @JvmStatic external fun nativeClockPair(out: LongArray)

    @JvmStatic external fun nativeRecordSizes(): Int

    fun clockPair(): LongArray = LongArray(2).also { nativeClockPair(it) }

    fun checkLayout() {
        val s = nativeRecordSizes()
        check(s == FLOW_REQUEST_BYTES) { "native flow announcement layout mismatch: $s bytes" }
    }
}

/** Counter snapshot keyed by native counter name. */
class CounterSnapshot(private val values: LongArray) {
    operator fun get(name: String): Long {
        val i = NativeCore.counterIndex(name)
        return if (i in values.indices) values[i] else 0L
    }

    fun toMap(): Map<String, Long> =
        NativeCore.counterNames.withIndex().associate { (i, n) -> n to values.getOrElse(i) { 0L } }
}
