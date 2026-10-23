package dev.minipcap.meta

import java.io.File
import java.io.FileOutputStream
import java.nio.BufferOverflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLongArray

/**
 * Asynchronous writer of the binary metadata sidecar. Collectors encode a record into a
 * pooled buffer and enqueue it; one writer thread appends to the file, flushing about
 * once per second. Producers never block and never allocate in steady state: an
 * exhausted pool drops the record and the loss is reported as DROPPED_EVENTS.
 */
class MetaWriter(
    private val file: File,
    sessionId: UUID,
    anchorBootNs: Long,
    anchorRealNs: Long,
    startBootNs: Long,
    poolSize: Int = 512,
    private val bufBytes: Int = 4096,
    private val flushIntervalMs: Long = 1000,
) {
    private val pool = ArrayBlockingQueue<ByteBuffer>(poolSize)
    private val queue = ArrayBlockingQueue<ByteBuffer>(poolSize)
    private val out: FileOutputStream = MetaFormat.create(file, sessionId, anchorBootNs, anchorRealNs, startBootNs)
    private val stage = ByteBuffer.allocate(64 shl 10)
    @Volatile private var accepting = true
    @Volatile private var stopping = false

    // Drops by (record type & 0xff) * 4 + reason: pending (not yet reported) and total.
    private val pendingDrops = AtomicLongArray(256 * 4)
    private val totalDrops = AtomicLongArray(256 * 4)
    @Volatile var recordsWritten = 0L
        private set
    @Volatile var bytesWritten = MetaFormat.HEADER_BYTES.toLong()
        private set
    @Volatile var writeErrors = 0L
        private set

    private val thread = Thread({ run() }, "mpc-meta-writer").apply {
        priority = Thread.NORM_PRIORITY - 1
    }

    init {
        repeat(poolSize) { pool.offer(ByteBuffer.allocate(bufBytes).order(ByteOrder.LITTLE_ENDIAN)) }
        thread.start()
    }

    val droppedTotal: Long get() = (0 until totalDrops.length()).sumOf { totalDrops.get(it) }

    /**
     * Starts a record; null (and a counted drop) if the writer is closed or the pool is empty.
     * [critical] records (session info/end) wait up to 2 s for a buffer instead of dropping.
     */
    @PublishedApi internal fun begin(type: Int, flags: Int, tsNs: Long, critical: Boolean = false): ByteBuffer? {
        if (!accepting) return null
        val b = if (critical) pool.poll(2, TimeUnit.SECONDS) else pool.poll()
        if (b == null) {
            drop(type, MetaFormat.DROP_QUEUE_FULL)
            return null
        }
        b.clear()
        b.putShort(type.toShort()).putShort(flags.toShort()).putInt(0).putLong(tsNs)
        return b
    }

    @PublishedApi internal fun commit(b: ByteBuffer) {
        MetaFormat.pad8(b)
        b.putInt(4, b.position())
        b.flip()
        queue.offer(b) // capacity == pool size, never fails
    }

    @PublishedApi internal fun abort(b: ByteBuffer, type: Int) {
        pool.offer(b)
        drop(type, MetaFormat.DROP_TOO_LARGE)
    }

    /** Encode one record with [fill]; inline so the lambda is not allocated. Thread-safe. */
    inline fun emit(type: Int, flags: Int, tsNs: Long, critical: Boolean = false, fill: (ByteBuffer) -> Unit): Boolean {
        val b = begin(type, flags, tsNs, critical) ?: return false
        try {
            fill(b)
            MetaFormat.pad8(b)
        } catch (e: BufferOverflowException) {
            abort(b, type)
            return false
        }
        commit(b)
        return true
    }

    private fun drop(type: Int, reason: Int) {
        val i = (type and 0xff) * 4 + reason
        pendingDrops.incrementAndGet(i)
        totalDrops.incrementAndGet(i)
    }

    private fun run() {
        var lastFlush = System.nanoTime()
        while (true) {
            val b = queue.poll(200, TimeUnit.MILLISECONDS)
            if (b != null) {
                write(b)
                pool.offer(b)
                var more = queue.poll()
                while (more != null) {
                    write(more)
                    pool.offer(more)
                    more = queue.poll()
                }
            }
            reportDrops()
            val now = System.nanoTime()
            if (now - lastFlush >= flushIntervalMs * 1_000_000) {
                flushStage()
                lastFlush = now
            }
            if (stopping && queue.isEmpty()) break
        }
        reportDrops()
        flushStage()
    }

    private fun write(b: ByteBuffer) {
        if (b.remaining() > stage.remaining()) flushStage()
        stage.put(b)
        recordsWritten++
    }

    private fun flushStage() {
        if (stage.position() == 0) return
        try {
            out.write(stage.array(), 0, stage.position())
            bytesWritten += stage.position()
        } catch (e: Exception) {
            writeErrors++
        }
        stage.clear()
    }

    /** Writer thread only: DROPPED_EVENTS for every (type, reason) with new losses. */
    private fun reportDrops() {
        for (i in 0 until pendingDrops.length()) {
            if (pendingDrops.get(i) == 0L) continue
            val n = pendingDrops.getAndSet(i, 0)
            val b = ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN)
            b.putShort(MetaFormat.DROPPED_EVENTS.toShort()).putShort(MetaFormat.TS_LOGGER.toShort()).putInt(40)
                .putLong(clock())
            b.putShort((i / 4).toShort()).putShort((i % 4).toShort()).putInt(minOf(n, 0xffffffffL).toInt())
                .putLong(totalDrops.get(i))
            MetaFormat.pad8(b)
            b.putInt(4, b.position())
            b.flip()
            write(b)
        }
    }

    /**
     * Stop accepting records, write everything queued, fsync and close. Call after the
     * final CLOCK_SYNC and SESSION_END records were emitted.
     */
    fun close() {
        if (!accepting && stopping) return
        accepting = false
        stopping = true
        thread.join(5000)
        try {
            out.fd.sync()
        } catch (e: Exception) {
            writeErrors++
        }
        out.close()
    }

    companion object {
        /**
         * Monotonic clock for records the writer creates itself. The app sets it to
         * SystemClock::elapsedRealtimeNanos (CLOCK_BOOTTIME, the packet clock); JVM tests keep nanoTime.
         */
        @Volatile var clock: () -> Long = { System.nanoTime() }
    }
}
