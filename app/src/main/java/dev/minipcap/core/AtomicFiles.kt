package dev.minipcap.core

import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/** Small state files (session/upload/export records): write to a temp file, fsync, rename. */
object AtomicFiles {
    fun write(target: File, text: String) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        FileOutputStream(tmp).use { out ->
            out.write(text.toByteArray(Charsets.UTF_8))
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IOException("rename failed: ${target.name}")
        }
    }
}
