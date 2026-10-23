package dev.minipcap.core

import java.io.File
import java.io.FileInputStream
import java.io.InputStream

/** One artifact of a finalized pair, wherever it is stored (app-private or shared storage). */
interface CaptureFile {
    val name: String
    fun length(): Long
    fun open(): InputStream
}

class PrivateFile(val file: File) : CaptureFile {
    override val name: String get() = file.name
    override fun length() = file.length()
    override fun open(): InputStream = FileInputStream(file)
}
