package dev.minipcap.meta

import java.io.File
import java.io.FileOutputStream
import java.nio.BufferOverflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLongArray

/**
 * Asynchronous writer of the binary metadata file (`<session>.meta`). Collectors encode a record into a
 * pooled buffer and enqueue it; one writer thread appends to the file, flushing about
 * once per second. Producers never block and never allocate in steady state: an
 * exhausted pool drops the record and the loss is reported as DROPPED_EVENTS.
 */
class MetaWriter(
    file: File,
    sessionId: UUID,
    anchorBootNs: Long,
    anchorRealNs: Long,
    startBootNs: Long,
    /** Monotonic clock for records the writer creates itself (CLOCK_BOOTTIME on Android). */
    private val clock: () -> Long = System::nanoTime,
    poolSize: Int = 512,
    private val bufBytes: Int = 4096,
    private val flushIntervalMs: Long = 1000,
) {
    private val pool = ArrayBlockingQueue<ByteBuffer>(poolSize)
    private val queue = ArrayBlockingQueue<ByteBuffer>(poolSize + LARGE_SLOTS)
    private val out: FileOutputStream = MetaFormat.create(file, sessionId, anchorBootNs, anchorRealNs, startBootNs)
    private val stage = ByteBuffer.allocate(64 shl 10)
    private var stageRecords = 0
    private val inFlight = AtomicInteger()
    @Volatile private var accepting = true
    @Volatile private var stopping = false
    @Volatile private var failed = false // first write error latches: no torn records after it
    private var ended = false            // writer thread: SESSION_END written, nothing may follow

    // Drops by (record type & 0xff) * 8 + reason: pending (not yet reported) and total.
    private val pendingDrops = AtomicLongArray(256 * 8)
    private val totalDrops = AtomicLongArray(256 * 8)
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
     * Every non-null result must end in [commit] or [abort].
     */
    @PublishedApi internal fun begin(type: Int, flags: Int, tsNs: Long, critical: Boolean): ByteBuffer? {
        inFlight.incrementAndGet()
        if (!accepting) {
            inFlight.decrementAndGet()
            drop(type, MetaFormat.DROP_CLOSED)
            return null
        }
        val b = if (critical) pool.poll(2, TimeUnit.SECONDS) else pool.poll()
        if (b == null) {
            inFlight.decrementAndGet()
            drop(type, MetaFormat.DROP_QUEUE_FULL)
            return null
        }
        return header(b, type, flags, tsNs)
    }

    private fun header(b: ByteBuffer, type: Int, flags: Int, tsNs: Long): ByteBuffer {
        b.clear()
        b.putShort(type.toShort()).putShort(flags.toShort()).putInt(0).putLong(tsNs)
        return b
    }

    /**
     * Rare path for a record that does not fit a pooled buffer (e.g. a UID shared by many
     * packages): returns the pooled buffer and starts the record again in a one-off buffer.
     */
    @PublishedApi internal fun grow(b: ByteBuffer): ByteBuffer {
        val type = b.getShort(0).toInt() and 0xffff
        val flags = b.getShort(2).toInt() and 0xffff
        val ts = b.getLong(8)
        pool.offer(b)
        return header(ByteBuffer.allocate(LARGE_BYTES).order(ByteOrder.LITTLE_ENDIAN), type, flags, ts)
    }

    @PublishedApi internal fun commit(b: ByteBuffer) {
        MetaFormat.pad8(b)
        b.putInt(4, b.position())
        b.flip()
        if (!queue.offer(b)) drop(b.getShort(0).toInt(), MetaFormat.DROP_QUEUE_FULL) // only if many large records pile up
        inFlight.decrementAndGet()
    }

    @PublishedApi internal fun abort(b: ByteBuffer, type: Int, reason: Int) {
        if (b.capacity() == bufBytes) pool.offer(b)
        drop(type, reason)
        inFlight.decrementAndGet()
    }

    /**
     * Encode one record with [fill]; inline so no lambda is allocated. Thread-safe, never
     * blocks (except critical records waiting for a buffer). [fill] may run twice if the
     * record outgrows a pooled buffer, so it must only write to the buffer.
     */
    inline fun emit(type: Int, flags: Int, tsNs: Long, critical: Boolean = false, crossinline fill: (ByteBuffer) -> Unit): Boolean {
        var b = begin(type, flags, tsNs, critical) ?: return false
        try {
            try {
                fill(b)
            } catch (e: BufferOverflowException) {
                b = grow(b)
                fill(b)
            }
        } catch (e: BufferOverflowException) {
            abort(b, type, MetaFormat.DROP_TOO_LARGE)
            return false
        } catch (e: RuntimeException) {
            abort(b, type, MetaFormat.DROP_ENCODE_ERROR)
            return false
        }
        commit(b)
        return true
    }

    private fun drop(type: Int, reason: Int) {
        val i = (type and 0xff) * 8 + reason
        pendingDrops.incrementAndGet(i)
        totalDrops.incrementAndGet(i)
    }

    private fun run() {
        var lastFlush = System.nanoTime()
        while (true) {
            var b = queue.poll(200, TimeUnit.MILLISECONDS)
            while (b != null) {
                write(b)
                if (b.capacity() == bufBytes) pool.offer(b)
                b = queue.poll()
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
        val type = b.getShort(b.position()).toInt() and 0xffff
        if (ended || failed) { // after SESSION_END (or a write error) nothing is appended
            drop(type, if (failed) MetaFormat.DROP_WRITE_ERROR else MetaFormat.DROP_CLOSED)
            return
        }
        if (type == MetaFormat.SESSION_END) {
            reportDrops() // the final loss report precedes SESSION_END
            ended = true
        }
        if (b.remaining() > stage.remaining()) flushStage()
        if (b.remaining() > stage.capacity()) { // larger than the staging buffer: write directly
            if (writeOut(b.array(), b.position(), b.remaining(), 1)) recordsWritten++
            return
        }
        stage.put(b)
        stageRecords++
    }

    private fun flushStage() {
        if (stage.position() == 0) return
        if (writeOut(stage.array(), 0, stage.position(), stageRecords)) recordsWritten += stageRecords
        stage.clear()
        stageRecords = 0
    }

    private fun writeOut(a: ByteArray, off: Int, len: Int, records: Int): Boolean {
        if (failed) {
            repeat(records) { drop(0, MetaFormat.DROP_WRITE_ERROR) }
            return false
        }
        return try {
            out.write(a, off, len)
            bytesWritten += len
            true
        } catch (e: Exception) {
            // A partial write (e.g. ENOSPC) would leave a torn record: cut back to the last
            // complete record and stop writing; the file stays valid up to that point.
            failed = true
            writeErrors++
            runCatching { out.channel.truncate(bytesWritten) }
            repeat(records) { drop(0, MetaFormat.DROP_WRITE_ERROR) }
            false
        }
    }

    /** Writer thread only: one DROPPED_EVENTS record per (type, reason) with new losses. */
    private fun reportDrops() {
        if (ended || failed) return
        for (i in 0 until pendingDrops.length()) {
            if (pendingDrops.get(i) == 0L) continue
            val n = pendingDrops.getAndSet(i, 0)
            val b = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
            b.putShort(MetaFormat.DROPPED_EVENTS.toShort()).putShort(MetaFormat.TS_LOGGER.toShort()).putInt(32).putLong(clock())
            b.putShort((i / 8).toShort()).putShort((i % 8).toShort()).putInt(minOf(n, 0xffffffffL).toInt())
                .putLong(totalDrops.get(i))
            b.flip()
            if (b.remaining() > stage.remaining()) flushStage()
            stage.put(b)
            stageRecords++
        }
    }

    /**
     * Stops accepting records, waits for producers already inside [emit], writes everything
     * queued, fsyncs and closes. Call after the final CLOCK_SYNC and SESSION_END were emitted.
     * Returns true only if every accepted record reached the disk and SESSION_END was written.
     */
    fun close(): Boolean {
        if (!accepting) return false
        accepting = false
        val deadline = System.nanoTime() + 2_000_000_000L
        while (inFlight.get() > 0 && System.nanoTime() < deadline) Thread.sleep(1)
        stopping = true
        thread.join(5000)
        var ok = !thread.isAlive // a writer stuck in I/O: the file is left for recovery
        try {
            out.fd.sync()
        } catch (e: Exception) {
            writeErrors++
            ok = false
        }
        runCatching { out.close() }
        return ok && !failed && ended
    }

    companion object {
        /** Capacity of the one-off buffer for an oversized record. */
        const val LARGE_BYTES = 1 shl 20
        private const val LARGE_SLOTS = 64
    }
}
