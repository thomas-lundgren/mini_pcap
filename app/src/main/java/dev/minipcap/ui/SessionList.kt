package dev.minipcap.ui

import android.app.AlertDialog
import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import dev.minipcap.R
import dev.minipcap.core.PrivateFile
import dev.minipcap.notify.Notifications
import dev.minipcap.session.CapturePair
import dev.minipcap.session.SessionRecord
import dev.minipcap.session.SessionState
import dev.minipcap.session.Sessions
import dev.minipcap.storage.CaptureFileProvider
import dev.minipcap.storage.ExportFile
import dev.minipcap.storage.ExportStatus
import dev.minipcap.storage.Exports
import dev.minipcap.upload.UploadJobService
import dev.minipcap.upload.UploadStatus
import java.text.DateFormat
import java.util.Date

/** "Saved captures" list: one row per session with its location/upload state, and its actions. */
class SessionList(private val ui: MainActivity, private val container: LinearLayout, private val onChange: () -> Unit) {
    private var lastRendered: List<String> = emptyList()

    fun render(list: List<SessionRecord>) {
        val (store, uploads) = UploadJobService.stores(ui)
        val exports = Exports.store(ui)
        val moving = Exports.progress
        val rows = list.map { r ->
            val u = uploads.get(r.id).status
            val e = exports.get(r.id)
            val size = if (e.status == ExportStatus.EXPORTED) e.pcapSize else store.pcapFinal(r.id).takeIf { it.exists() }?.length()
            val where = when {
                moving?.id == r.id -> "  moving ${moving.done * 100 / maxOf(moving.total, 1)}%"
                e.status == ExportStatus.EXPORTED -> "  in ${e.location}"
                e.status == ExportStatus.QUEUED -> "  move queued"
                e.status == ExportStatus.FAILED -> "  move failed: ${e.lastError}"
                else -> ""
            }
            "${r.id.take(8)}  ${r.state}  ${r.variant}  ${size?.let { Notifications.size(it) } ?: "-"}  " +
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(r.createdMs)) +
                (if (u != UploadStatus.NOT_UPLOADED) "  upload:$u" else "") +
                (r.stopReason?.let { "  ($it)" } ?: "") + where
        }
        if (rows == lastRendered) return
        lastRendered = rows
        container.removeAllViews()
        list.zip(rows).forEach { (r, text) ->
            container.addView(TextView(ui).apply {
                this.text = text
                textSize = 12f
                setPadding(0, 12, 0, 12)
                setOnClickListener { actions(r) }
            })
        }
    }

    private fun actions(r: SessionRecord) {
        val store = Sessions.store(ui)
        val mover = Exports.mover(ui)
        val pair = mover.pairFor(r)
        val e = Exports.store(ui).get(r.id)
        val items = ArrayList<Pair<String, () -> Unit>>()
        if (pair != null) items += ui.getString(R.string.share_pair) to { share(pair) }
        if (pair != null && r.state == SessionState.COMPLETE && Sessions.active == null)
            items += ui.getString(R.string.upload_this) to { ui.scheduleUpload(r.id) }
        if (mover.eligible(r) && e.status != ExportStatus.EXPORTED && e.status != ExportStatus.QUEUED && !Sessions.isLocked(r.id))
            items += ui.getString(R.string.move_to_downloads) to { Exports.request(ui, r.id); onChange() }
        if (!r.state.isActive) items += ui.getString(R.string.delete) to {
            AlertDialog.Builder(ui).setMessage(R.string.delete_confirm)
                .setPositiveButton(R.string.delete) { _, _ ->
                    if (Sessions.isLocked(r.id)) {
                        Toast.makeText(ui, R.string.delete_busy, Toast.LENGTH_LONG).show()
                    } else {
                        if (!mover.deleteExported(r.id)) Toast.makeText(ui, R.string.delete_shared_failed, Toast.LENGTH_LONG).show()
                        store.delete(r.id)
                    }
                    onChange()
                }
                .setNegativeButton(android.R.string.cancel, null).show()
        }
        if (items.isEmpty()) return
        AlertDialog.Builder(ui).setTitle(r.id)
            .setItems(items.map { it.first }.toTypedArray()) { _, i -> items[i].second() }
            .show()
    }

    private fun share(pair: CapturePair) {
        val files = listOf(pair.pcap, pair.meta)
        val uris = ArrayList(files.map {
            when (it) {
                is PrivateFile -> CaptureFileProvider.uriFor(it.file)
                is ExportFile -> Uri.parse(it.ref)
                else -> throw IllegalStateException("unknown file location")
            }
        })
        val clip = ClipData.newRawUri(files[0].name, uris[0]).apply { for (u in uris.drop(1)) addItem(ClipData.Item(u)) }
        val send = Intent(Intent.ACTION_SEND_MULTIPLE)
            .setType("*/*")
            .putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        send.clipData = clip
        ui.startActivity(Intent.createChooser(send, ui.getString(R.string.share_pair)))
    }
}
