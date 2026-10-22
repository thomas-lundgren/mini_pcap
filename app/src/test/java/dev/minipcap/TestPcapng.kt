package dev.minipcap

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Independent little-endian PCAPNG builder for JVM tests. */
object TestPcapng {
    private fun block(type: Int, body: ByteArray): ByteArray {
        val total = 12 + body.size
        return ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(type).putInt(total).put(body).putInt(total).array()
    }

    fun shb(): ByteArray = block(0x0A0D0D0A, ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        .putInt(0x1A2B3C4D).putShort(1).putShort(0).putLong(-1).array())

    fun idb(): ByteArray = block(1, ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        .putShort(101).putShort(0).putInt(256).array())

    fun epb(len: Int): ByteArray {
        val padded = (len + 3) and 3.inv()
        return block(6, ByteBuffer.allocate(20 + padded).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0).putInt(0).putInt(1).putInt(len).putInt(len).put(ByteArray(padded) { 0x45 }).array())
    }

    fun file(packets: Int): ByteArray = ByteArrayOutputStream().apply {
        write(shb()); write(idb()); repeat(packets) { write(epb(40 + it % 1400)) }
    }.toByteArray()
}
