package dev.minipcap.capture

import java.nio.ByteBuffer

/**
 * JNI facade for the native data plane. Every call here is lifecycle or batched
 * control: start/stop, ~1 Hz counter snapshots and context records, batched UID exchange.
 * No method is invoked per packet.
 */
object NativeCore {
    init {
        System.loadLibrary("mpcnative")
    }

    /** Sizes of the UID request/resolution records shared through direct buffers. */
    const val UID_REQUEST_BYTES = 48
    const val UID_RESOLUTION_BYTES = 56

    val counterNames: List<String> by lazy { nativeCounterNames().toList() }

    fun counterIndex(name: String): Int = counterNames.indexOf(name)

    @JvmStatic external fun nativeCounterNames(): Array<String>

    /** Returns an opaque handle (tagged pointer, may be negative), or -errno in [-4095, -1]. Takes ownership of [tunFd]. */
    @JvmStatic external fun nativeStart(
        tunFd: Int,
        pcapPath: String?,
        snaplen: Int,
        mtu: Int,
        variant: Int,
        ringBytes: Int,
        userAppl: String,
        os: String,
        hardware: String,
        uidHoldMs: Int,
    ): Long

    /** Ordered stop: quiesce tap, stop forwarding/close TUN, drain+fsync writer. 0 = file complete. */
    @JvmStatic external fun nativeStop(handle: Long): Int

    @JvmStatic external fun nativeDestroy(handle: Long)

    @JvmStatic external fun nativeCounters(handle: Long, out: LongArray): Int

    /** Blocks up to [timeoutMs]; returns number of 48-byte requests written, or -1 once closed. */
    @JvmStatic external fun nativeUidPoll(handle: Long, buf: ByteBuffer, max: Int, timeoutMs: Int): Int

    @JvmStatic external fun nativeUidDeliver(handle: Long, buf: ByteBuffer, count: Int): Int

    /** Context record kinds (native MPC_CTX_*): STATE is referenced by packets as c=<seq>. */
    const val CTX_STATE = 1
    const val CTX_INFO = 2

    /** ~1 Hz: queue one JSON context record for the ctx0 interface. 0 = queued. */
    @JvmStatic external fun nativeContext(handle: Long, kind: Int, seq: Int, info: ByteArray?, json: ByteArray): Int

    /** Benchmark-only synthetic writer stall (PERFORMANCE_PLAN V32). */
    @JvmStatic external fun nativeWriterStall(handle: Long, ms: Int)

    @JvmStatic external fun nativeRecordSizes(): Int

    fun checkLayout() {
        val s = nativeRecordSizes()
        check(s ushr 16 == UID_REQUEST_BYTES && (s and 0xffff) == UID_RESOLUTION_BYTES) {
            "native UID record layout mismatch: $s"
        }
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
