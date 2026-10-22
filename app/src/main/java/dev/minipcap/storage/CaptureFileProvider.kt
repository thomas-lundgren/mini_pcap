package dev.minipcap.storage

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/**
 * Minimal read-only provider exposing only finalized artifacts (`*.pcapng`,
 * `*.meta.json`) from the private captures directory via temporary URI grants.
 * Not exported; never serves `.partial` files or state/upload records.
 */
class CaptureFileProvider : ContentProvider() {
    override fun onCreate() = true

    private fun resolve(uri: Uri): File {
        val name = uri.lastPathSegment ?: throw FileNotFoundException()
        if ('/' in name || name.startsWith(".") || !(name.endsWith(".pcapng") || name.endsWith(".meta.json")))
            throw FileNotFoundException("not shareable")
        val f = File(capturesDir(context!!), name)
        if (!f.isFile) throw FileNotFoundException()
        return f
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw SecurityException("read-only")
        return ParcelFileDescriptor.open(resolve(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri): String =
        if (uri.lastPathSegment?.endsWith(".json") == true) "application/json" else "application/vnd.tcpdump.pcap"

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, args: Array<out String>?, sort: String?): Cursor {
        val f = resolve(uri)
        val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val c = MatrixCursor(cols)
        c.addRow(cols.map { if (it == OpenableColumns.SIZE) f.length() else if (it == OpenableColumns.DISPLAY_NAME) f.name else null })
        return c
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, args: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, args: Array<out String>?) = 0

    companion object {
        const val AUTHORITY = "dev.minipcap.files"
        fun capturesDir(ctx: Context) = File(ctx.filesDir, "captures")
        fun uriFor(f: File): Uri = Uri.Builder().scheme("content").authority(AUTHORITY).appendPath(f.name).build()
    }
}
