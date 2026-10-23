package dev.minipcap.meta

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/** Constants and codecs of the `<session>.meta` binary metadata file (docs/META_FORMAT.md, v1.0). */
object MetaFormat {
    val MAGIC = byteArrayOf('M'.code.toByte(), 'P'.code.toByte(), 'C'.code.toByte(), 'M'.code.toByte(),
        'E'.code.toByte(), 'T'.code.toByte(), 'A'.code.toByte(), 0)
    const val VERSION_MAJOR = 1
    const val VERSION_MINOR = 0
    const val HEADER_BYTES = 64
    const val RECORD_HEADER_BYTES = 16

    // Record types
    const val SESSION_INFO = 0x0001
    const val CLOCK_SYNC = 0x0002
    const val SESSION_END = 0x0003
    const val CAPTURE_STATS = 0x0004
    const val DROPPED_EVENTS = 0x0005
    const val SENSOR_STATUS = 0x0006
    const val LOCATION = 0x0010
    const val GNSS_STATUS = 0x0011
    const val MOTION_SAMPLE = 0x0020
    const val RADIO_STATE = 0x0030
    const val CELL_IDENTITY = 0x0031
    const val CELL_MEASUREMENT = 0x0032
    const val SIGNAL_STRENGTH = 0x0033
    const val NETWORK_STATE = 0x0040
    const val WIFI_STATE = 0x0041
    const val UID_MAPPING = 0x0050
    const val FLOW_MAPPING = 0x0051

    // Record flags: timestamp source (bits 0-2) and REFRESH
    const val TS_LOGGER = 0
    const val TS_SENSOR = 1
    const val TS_LOCATION = 2
    const val TS_MODEM = 3
    const val TS_PACKET = 4
    const val FLAG_REFRESH = 0x8

    // CLOCK_SYNC reasons
    const val CLOCK_START = 0
    const val CLOCK_PERIODIC = 1
    const val CLOCK_TIME_CHANGED = 2
    const val CLOCK_TZ_CHANGED = 3
    const val CLOCK_STOP = 4

    // SESSION_END status
    const val END_COMPLETE = 1
    const val END_RECOVERED = 2

    // DROPPED_EVENTS reasons
    const val DROP_QUEUE_FULL = 1
    const val DROP_TOO_LARGE = 2
    const val DROP_WRITE_ERROR = 3
    const val DROP_ENCODE_ERROR = 4
    const val DROP_CLOSED = 5 // emitted after close(): counted, cannot be written

    // SENSOR_STATUS sources and states
    const val SRC_LOCATION = 1
    const val SRC_GNSS = 2
    const val SRC_ACCEL = 3
    const val SRC_GYRO = 4
    const val SRC_RADIO = 5
    const val SRC_CELL_INFO = 6
    const val SRC_NETWORK = 7
    const val SRC_WIFI = 8
    const val SRC_APPS = 9
    const val ST_ACTIVE = 0
    const val ST_UNAVAILABLE = 1
    const val ST_PERMISSION_DENIED = 2
    const val ST_DISABLED_BY_USER = 3
    const val ST_DISABLED_IN_SYSTEM = 4
    const val ST_ERROR = 5
    const val ST_STOPPED = 6

    // MOTION_SAMPLE sensors
    const val SENSOR_ACCEL = 1
    const val SENSOR_GYRO = 2
    const val SENSOR_LINEAR_ACCEL = 3
    const val SENSOR_GRAVITY = 4
    const val SENSOR_MAGNETOMETER = 5
    const val SENSOR_ROTATION_VECTOR = 6
    const val SENSOR_PRESSURE = 7

    // Cell entries
    const val RAT_GSM = 1
    const val RAT_WCDMA = 2
    const val RAT_TDSCDMA = 3
    const val RAT_CDMA = 4
    const val RAT_LTE = 5
    const val RAT_NR = 6

    // FLOW_MAPPING resolution
    const val RES_FIRST_LOOKUP = 1
    const val RES_AFTER_RETRY = 2
    const val RES_UNRESOLVED_INVALID_UID = 3
    const val RES_UNRESOLVED_SESSION_ENDED = 4

    fun header(sessionId: UUID, anchorBootNs: Long, anchorRealNs: Long, startBootNs: Long): ByteBuffer {
        val b = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN)
        b.put(MAGIC).putShort(VERSION_MAJOR.toShort()).putShort(VERSION_MINOR.toShort()).putInt(HEADER_BYTES)
        b.order(ByteOrder.BIG_ENDIAN).putLong(sessionId.mostSignificantBits).putLong(sessionId.leastSignificantBits)
        b.order(ByteOrder.LITTLE_ENDIAN).putLong(anchorBootNs).putLong(anchorRealNs).putLong(startBootNs).putInt(0).putInt(0)
        b.flip()
        return b
    }

    fun putStr(b: ByteBuffer, s: String?) {
        val bytes = (s ?: "").toByteArray(Charsets.UTF_8)
        val n = minOf(bytes.size, 0xffff)
        b.putShort(n.toShort())
        b.put(bytes, 0, n)
    }

    fun putStrList(b: ByteBuffer, list: List<String>) {
        b.putShort(list.size.toShort())
        for (s in list) putStr(b, s)
    }

    fun putCounters(b: ByteBuffer, counters: Map<String, Long>) {
        b.putShort(counters.size.toShort())
        for ((k, v) in counters) {
            putStr(b, k)
            b.putLong(v)
        }
    }

    fun pad8(b: ByteBuffer) {
        while (b.position() and 7 != 0) b.put(0)
    }

    /** Result of walking a meta file; [validBytes] ends at the last complete record. */
    data class Scan(
        val sessionId: UUID?,
        val anchorBootNs: Long,
        val anchorRealNs: Long,
        val validBytes: Long,
        val truncatedBytes: Long,
        val records: Long,
        val endStatus: Int?, // status of SESSION_END if it is the final record, else null
    ) {
        val headerOk get() = sessionId != null
    }

    /** Streams [inp] (closed by the caller); never trusts lengths that run past the data. */
    fun scan(inp: InputStream, size: Long): Scan {
        val hdr = ByteArray(HEADER_BYTES)
        if (readFully(inp, hdr) < HEADER_BYTES) return Scan(null, 0, 0, 0, size, 0, null)
        val h = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN)
        if (!hdr.copyOf(8).contentEquals(MAGIC) || h.getShort(8).toInt() != VERSION_MAJOR)
            return Scan(null, 0, 0, 0, size, 0, null)
        val hlen = h.getInt(12)
        if (hlen < HEADER_BYTES || hlen > size) return Scan(null, 0, 0, 0, size, 0, null)
        val id = ByteBuffer.wrap(hdr, 16, 16).order(ByteOrder.BIG_ENDIAN).let { UUID(it.long, it.long) }
        skipFully(inp, (hlen - HEADER_BYTES).toLong())
        var off = hlen.toLong()
        var records = 0L
        var end: Int? = null
        val rh = ByteArray(RECORD_HEADER_BYTES)
        val rb = ByteBuffer.wrap(rh).order(ByteOrder.LITTLE_ENDIAN)
        while (off + RECORD_HEADER_BYTES <= size) {
            if (readFully(inp, rh) < RECORD_HEADER_BYTES) break
            val type = rb.getShort(0).toInt() and 0xffff
            val len = rb.getInt(4).toLong() and 0xffffffffL
            if (len < RECORD_HEADER_BYTES || len % 8 != 0L || off + len > size) break
            if (type == SESSION_END && len >= RECORD_HEADER_BYTES + 1) {
                val st = inp.read()
                if (st < 0) break
                if (!skipFully(inp, len - RECORD_HEADER_BYTES - 1)) break
                end = st
            } else if (!skipFully(inp, len - RECORD_HEADER_BYTES)) {
                break
            } else {
                end = null // a record after SESSION_END: the session end is not final
            }
            off += len
            records++
        }
        return Scan(id, h.getLong(32), h.getLong(40), off, size - off, records, end)
    }

    fun scan(f: File): Scan = f.inputStream().buffered(1 shl 16).use { scan(it, f.length()) }

    /**
     * Crash recovery: cut an interrupted file back to its last complete record and append
     * SESSION_END(recovered) unless it already ends a session. Returns the scan before repair.
     */
    fun recover(f: File, nowBootNs: Long, reason: String): Scan {
        val s = scan(f)
        if (!s.headerOk) return s
        RandomAccessFile(f, "rw").use { raf ->
            if (s.truncatedBytes > 0) raf.setLength(s.validBytes)
            if (s.endStatus == null) {
                raf.seek(s.validBytes)
                val b = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN)
                b.putShort(SESSION_END.toShort()).putShort(TS_LOGGER.toShort()).putInt(0).putLong(nowBootNs)
                b.put(END_RECOVERED.toByte())
                putStr(b, reason)
                b.putShort(0) // no counters known after process death
                pad8(b)
                b.putInt(4, b.position())
                raf.write(b.array(), 0, b.position())
            }
            raf.fd.sync()
        }
        return s
    }

    private fun readFully(inp: InputStream, b: ByteArray): Int {
        var n = 0
        while (n < b.size) {
            val r = inp.read(b, n, b.size - n)
            if (r < 0) break
            n += r
        }
        return n
    }

    private fun skipFully(inp: InputStream, n: Long): Boolean {
        var left = n
        while (left > 0) {
            val s = inp.skip(left)
            if (s <= 0) {
                if (inp.read() < 0) return false
                left--
            } else {
                left -= s
            }
        }
        return true
    }

    /** Writes the header for a new file (used by the writer and by tests). */
    fun create(f: File, sessionId: UUID, anchorBootNs: Long, anchorRealNs: Long, startBootNs: Long): FileOutputStream {
        val out = FileOutputStream(f)
        try {
            out.write(header(sessionId, anchorBootNs, anchorRealNs, startBootNs).array())
        } catch (e: IOException) {
            out.close()
            throw e
        }
        return out
    }
}
