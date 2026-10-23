package dev.minipcap

import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/** Independent builders of the session file pair (PCAP with Linux SLL + binary meta) for JVM tests. */
object TestCapture {
    fun pcapHeader(): ByteArray = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        .putInt(0xA1B23C4D.toInt()).putShort(2).putShort(4).putInt(0).putInt(0).putInt(256 + 16).putInt(113).array()

    fun record(ipLen: Int): ByteArray {
        val b = ByteBuffer.allocate(16 + 16 + ipLen).order(ByteOrder.LITTLE_ENDIAN)
        b.putInt(1).putInt(0).putInt(16 + ipLen).putInt(16 + ipLen)
        b.order(ByteOrder.BIG_ENDIAN).putShort(4).putShort(0xFFFE.toShort()).putShort(0).putLong(0).putShort(0x0800)
        b.put(ByteArray(ipLen) { 0x45 })
        return b.array()
    }

    fun pcap(packets: Int): ByteArray = ByteArrayOutputStream().apply {
        write(pcapHeader()); repeat(packets) { write(record(40 + it % 200)) }
    }.toByteArray()

    /** Meta file with SESSION_INFO and, if [end] != null, SESSION_END(end). */
    fun meta(f: File, id: String, end: Int? = MetaFormat.END_COMPLETE) {
        val w = MetaWriter(f, UUID.fromString(id), 1000, 2000, 1000)
        MetaRecords.sessionInfo(w, 1000, mapOf("ip_snaplen" to "256"))
        MetaRecords.clockSync(w, 1001, 2001, MetaFormat.CLOCK_START)
        if (end != null) MetaRecords.sessionEnd(w, 5000, end, "user_stop", mapOf("records_written" to 1L))
        w.close()
    }
}
