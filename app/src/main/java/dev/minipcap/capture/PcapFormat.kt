package dev.minipcap.capture

import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The packet file written by the native writer: classic PCAP, nanosecond magic, link type
 * LINKTYPE_LINUX_SLL (113), little endian. Used for crash recovery: a record is plausible
 * only if 16 <= incl_len <= orig_len and incl_len <= snaplen; the file is cut before the
 * first implausible or incomplete record.
 */
object PcapFormat {
    const val MAGIC_NS = 0xA1B23C4D.toInt()
    const val MAGIC_US = 0xA1B2C3D4.toInt()
    const val LINKTYPE_LINUX_SLL = 113
    const val FILE_HEADER = 24
    const val RECORD_HEADER = 16
    const val SLL_HEADER = 16

    data class Scan(val validBytes: Long, val truncatedBytes: Long, val packets: Long)

    /** One buffered sequential pass (no per-record syscalls), safe on multi-GB files. */
    fun scan(f: File): Scan {
        val size = f.length()
        if (size < FILE_HEADER) return Scan(0, size, 0)
        BufferedInputStream(FileInputStream(f), 1 shl 20).use { inp ->
            val hdr = ByteArray(FILE_HEADER)
            if (inp.readNBytesCompat(hdr) < FILE_HEADER) return Scan(0, size, 0)
            val h = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN)
            val magic = h.getInt(0)
            if ((magic != MAGIC_NS && magic != MAGIC_US) || h.getInt(20) != LINKTYPE_LINUX_SLL) return Scan(0, size, 0)
            val snaplen = h.getInt(16).toLong() and 0xffffffffL
            var off = FILE_HEADER.toLong()
            var packets = 0L
            val rec = ByteArray(RECORD_HEADER)
            val rb = ByteBuffer.wrap(rec).order(ByteOrder.LITTLE_ENDIAN)
            while (off + RECORD_HEADER <= size) {
                if (inp.readNBytesCompat(rec) < RECORD_HEADER) break
                val incl = rb.getInt(8).toLong() and 0xffffffffL
                val orig = rb.getInt(12).toLong() and 0xffffffffL
                if (incl < SLL_HEADER || incl > orig || (snaplen != 0L && incl > snaplen) || off + RECORD_HEADER + incl > size) break
                if (inp.skipFully(incl) < incl) break
                off += RECORD_HEADER + incl
                packets++
            }
            return Scan(off, size - off, packets)
        }
    }

    /** Cuts an interrupted file back to its last complete, plausible record. */
    fun truncateToValidPrefix(f: File): Scan {
        val s = scan(f)
        if (s.truncatedBytes > 0 && s.validBytes > 0) RandomAccessFile(f, "rw").use { raf ->
            raf.setLength(s.validBytes)
            raf.fd.sync()
        }
        return s
    }

    private fun BufferedInputStream.readNBytesCompat(b: ByteArray): Int {
        var n = 0
        while (n < b.size) {
            val r = read(b, n, b.size - n)
            if (r < 0) break
            n += r
        }
        return n
    }

    private fun BufferedInputStream.skipFully(n: Long): Long {
        var left = n
        while (left > 0) {
            val s = skip(left)
            if (s <= 0) {
                if (read() < 0) break
                left--
            } else {
                left -= s
            }
        }
        return n - left
    }
}
