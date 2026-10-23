package dev.minipcap.ui

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.LinearLayout
import android.widget.RadioGroup
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import dev.minipcap.App
import dev.minipcap.BuildConfig
import dev.minipcap.R
import dev.minipcap.capture.CaptureConfig
import dev.minipcap.capture.FilterMode
import dev.minipcap.capture.Variant
import dev.minipcap.service.CaptureVpnService
import dev.minipcap.service.Notifications
import dev.minipcap.storage.CaptureFileProvider
import dev.minipcap.storage.CapturePair
import dev.minipcap.storage.ExportFile
import dev.minipcap.storage.ExportStatus
import dev.minipcap.storage.Exports
import dev.minipcap.storage.PrivateFile
import dev.minipcap.storage.SessionRecord
import dev.minipcap.storage.SessionState
import dev.minipcap.upload.UploadJobService
import dev.minipcap.upload.UploadStatus
import java.text.DateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private lateinit var tvState: TextView
    private lateinit var tvCounters: TextView
    private lateinit var btnStartStop: Button
    private lateinit var rgFilter: RadioGroup
    private lateinit var btnPickApps: Button
    private lateinit var spSnaplen: Spinner
    private lateinit var spVariant: Spinner
    private lateinit var tvLatest: TextView
    private lateinit var tvUploadStatus: TextView
    private lateinit var btnUpload: Button
    private lateinit var btnCancelUpload: Button
    private lateinit var listSessions: LinearLayout
    private var loadingConfig = false
    private val listener: () -> Unit = { main.post { refresh() } }
    private val ticker = object : Runnable {
        override fun run() {
            refresh()
            main.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        tvState = findViewById(R.id.tvState)
        tvCounters = findViewById(R.id.tvCounters)
        btnStartStop = findViewById(R.id.btnStartStop)
        rgFilter = findViewById(R.id.rgFilter)
        btnPickApps = findViewById(R.id.btnPickApps)
        spSnaplen = findViewById(R.id.spSnaplen)
        spVariant = findViewById(R.id.spVariant)
        tvLatest = findViewById(R.id.tvLatest)
        tvUploadStatus = findViewById(R.id.tvUploadStatus)
        btnUpload = findViewById(R.id.btnUpload)
        btnCancelUpload = findViewById(R.id.btnCancelUpload)
        listSessions = findViewById(R.id.listSessions)

        spSnaplen.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item,
            CaptureConfig.SNAPLENS.map { if (it == 0) "Full packet" else "$it bytes" })
        spVariant.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, Variant.entries.map { it.label })
        // Benchmark variants are a development tool only.
        findViewById<View>(R.id.rowVariant).visibility = if (BuildConfig.DEBUG) View.VISIBLE else View.GONE

        btnStartStop.setOnClickListener { onStartStop() }
        btnPickApps.setOnClickListener { startActivity(Intent(this, AppPickerActivity::class.java)) }
        findViewById<Button>(R.id.btnSettings).setOnClickListener { startActivity(Intent(this, SettingsActivity::class.java)) }
        btnUpload.setOnClickListener { uploadLatest() }
        btnCancelUpload.setOnClickListener {
            UploadJobService.cancel(this)
            refresh()
        }
        rgFilter.setOnCheckedChangeListener { _, _ -> saveConfig() }
        val sel = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>?, v: View?, pos: Int, id: Long) = saveConfig()
            override fun onNothingSelected(p: AdapterView<*>?) {}
        }
        spSnaplen.onItemSelectedListener = sel
        spVariant.onItemSelectedListener = sel

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)

        if (savedInstanceState == null) handleDebugCommand(intent)
        val rec = (application as App).recovered
        if (rec.isNotEmpty()) {
            (application as App).recovered = emptyList()
            AlertDialog.Builder(this)
                .setTitle(R.string.recovered_title)
                .setMessage(getString(R.string.recovered_text, rec.size, rec.joinToString("\n") { "${it.id.take(8)}: ${it.state}" }))
                .setPositiveButton(android.R.string.ok, null)
                .show()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDebugCommand(intent)
    }

    /**
     * Debug builds only: automation hook for validation/perf scripts, e.g.
     *   am start -n dev.minipcap/.ui.MainActivity --es cmd start --es variant E --ei snaplen 256
     * Commands: start, stop, stall (--ei ms), upload, server (--es url, --es token),
     * move (latest finalized pair), automove (--ez on).
     * Release builds ignore these extras entirely.
     */
    private fun handleDebugCommand(i: Intent?) {
        if (!BuildConfig.DEBUG || i == null) return
        val cmd = i.getStringExtra("cmd") ?: return
        i.removeExtra("cmd")
        when (cmd) {
            "start" -> {
                var c = CaptureConfig.load(this)
                i.getStringExtra("variant")?.let { v -> c = c.copy(variant = Variant.valueOf(v)) }
                if (i.hasExtra("snaplen")) c = c.copy(snaplen = i.getIntExtra("snaplen", 256))
                i.getStringExtra("mode")?.let { m -> c = c.copy(filterMode = FilterMode.valueOf(m)) }
                i.getStringExtra("pkgs")?.let { p -> c = c.copy(selectedPackages = p.split(',').filter { it.isNotBlank() }.toSet()) }
                CaptureConfig.save(this, c)
                loadConfig()
                onStartStop()
            }
            "stop" -> CaptureVpnService.active?.let { CaptureVpnService.requestStop(this, it.id) }
            "stall" -> startService(Intent(this, CaptureVpnService::class.java)
                .setAction(CaptureVpnService.ACTION_DEBUG_STALL)
                .putExtra(CaptureVpnService.EXTRA_STALL_MS, i.getIntExtra("ms", 1000)))
            "upload" -> uploadLatest()
            "move" -> UploadJobService.stores(this).first.list().firstOrNull { Exports.mover(this).eligible(it) }
                ?.let { Exports.request(this, it.id) }
            "automove" -> Exports.setAutoMove(this, i.getBooleanExtra("on", true))
            "server" -> {
                val s = dev.minipcap.upload.UploadSettings(this)
                s.save(i.getStringExtra("url") ?: s.load().baseUrl, i.getBooleanExtra("wifi_only", false))
                if (i.hasExtra("token")) s.setToken(i.getStringExtra("token"))
            }
        }
    }

    override fun onResume() {
        super.onResume()
        loadConfig()
        CaptureVpnService.listeners.add(listener)
        UploadJobService.listeners.add(listener)
        Exports.listeners.add(listener)
        main.post(ticker)
    }

    override fun onPause() {
        CaptureVpnService.listeners.remove(listener)
        UploadJobService.listeners.remove(listener)
        Exports.listeners.remove(listener)
        main.removeCallbacks(ticker)
        super.onPause()
    }

    private fun loadConfig() {
        loadingConfig = true
        val c = CaptureConfig.load(this)
        rgFilter.check(when (c.filterMode) {
            FilterMode.ALL -> R.id.rbAll
            FilterMode.INCLUDE -> R.id.rbInclude
            FilterMode.EXCLUDE -> R.id.rbExclude
        })
        spSnaplen.setSelection(CaptureConfig.SNAPLENS.indexOf(c.snaplen).coerceAtLeast(0))
        spVariant.setSelection(c.variant.ordinal)
        btnPickApps.text = getString(R.string.select_apps, c.selectedPackages.size)
        loadingConfig = false
    }

    private fun saveConfig() {
        if (loadingConfig) return
        val old = CaptureConfig.load(this)
        val mode = when (rgFilter.checkedRadioButtonId) {
            R.id.rbInclude -> FilterMode.INCLUDE
            R.id.rbExclude -> FilterMode.EXCLUDE
            else -> FilterMode.ALL
        }
        val variant = if (BuildConfig.DEBUG) Variant.entries[spVariant.selectedItemPosition] else Variant.F
        CaptureConfig.save(this, old.copy(filterMode = mode, snaplen = CaptureConfig.SNAPLENS[spSnaplen.selectedItemPosition], variant = variant))
        btnPickApps.isEnabled = mode != FilterMode.ALL
    }

    private fun onStartStop() {
        val a = CaptureVpnService.active
        if (a != null) {
            if (a.state == SessionState.RECORDING) CaptureVpnService.requestStop(this, a.id)
            return
        }
        val c = CaptureConfig.load(this)
        if (c.filterMode == FilterMode.INCLUDE && c.selectedPackages.isEmpty()) {
            Toast.makeText(this, R.string.include_empty, Toast.LENGTH_LONG).show()
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) startActivityForResult(consent, REQ_VPN) else CaptureVpnService.start(this)
    }

    @Deprecated("Activity result API without AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) CaptureVpnService.start(this)
            else Toast.makeText(this, R.string.vpn_denied, Toast.LENGTH_LONG).show()
        }
    }

    private fun uploadLatest() {
        val (sessions, _) = UploadJobService.stores(this)
        val latest = sessions.latestCompleted(Exports.mover(this)::pairFor)
        if (latest == null) {
            Toast.makeText(this, R.string.no_complete_capture, Toast.LENGTH_LONG).show()
            return
        }
        scheduleUpload(latest.id)
    }

    private fun scheduleUpload(id: String) {
        val err = UploadJobService.schedule(this, id)
        if (err != null) Toast.makeText(this, err, Toast.LENGTH_LONG).show()
        refresh()
    }

    private fun refresh() {
        val a = CaptureVpnService.active
        val recording = a != null
        tvState.text = when (a?.state) {
            null -> getString(R.string.state_idle)
            SessionState.PREPARING -> getString(R.string.n_starting_title)
            SessionState.RECORDING -> getString(R.string.n_recording_title)
            SessionState.STOPPING -> getString(R.string.n_stopping_title)
            else -> a.state.name
        }
        btnStartStop.text = getString(if (recording) R.string.stop_logging else R.string.start_logging)
        btnStartStop.isEnabled = a == null || a.state == SessionState.RECORDING
        for (v in listOf(rgFilter, spSnaplen, spVariant)) v.isEnabled = !recording
        for (i in 0 until rgFilter.childCount) rgFilter.getChildAt(i).isEnabled = !recording
        btnPickApps.isEnabled = !recording && rgFilter.checkedRadioButtonId != R.id.rbAll

        val c = a?.counters
        tvCounters.text = if (a != null && c != null) {
            val r = a.resolver
            String.format(Locale.US,
                "%s  %s\nobserved UL %,d / DL %,d pkts\nrecorded %,d  drops %,d  file %s\nflows %,d  uid resolved %,d  misses %,d\ntcp %d  udp %d  connect fail %,d",
                a.id.take(8), Notifications.duration(SystemClock.elapsedRealtime() - a.startedElapsed),
                c["pkts_ul"], c["pkts_dl"], c["records_written"],
                c["capture_queue_drops_ul"] + c["capture_queue_drops_dl"], Notifications.size(c["file_bytes"]),
                c["flows_created"], r?.resolved ?: 0, r?.misses ?: 0,
                c["tcp_conns_active"], c["udp_sessions_active"], c["tcp_connect_failures"])
        } else CaptureVpnService.lastResult ?: ""

        val (sessions, uploads) = UploadJobService.stores(this)
        val latest = sessions.latestCompleted(Exports.mover(this)::pairFor)
        tvLatest.text = if (latest == null) getString(R.string.no_complete_capture)
        else getString(R.string.latest_complete, latest.id.take(8),
            DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(Date(latest.finalizedMs)),
            Notifications.size(latest.pcap.length()))
        val ur = latest?.let { uploads.get(it.id) }
        tvUploadStatus.text = when (ur?.status) {
            null -> ""
            UploadStatus.NOT_UPLOADED -> getString(R.string.u_ready)
            UploadStatus.QUEUED -> getString(R.string.u_queued)
            UploadStatus.UPLOADING -> if (ur.bytesTotal > 0) getString(R.string.u_progress, ur.bytesSent * 100 / ur.bytesTotal) else getString(R.string.u_hashing)
            UploadStatus.SUCCEEDED -> getString(R.string.u_done, ur.receiptId ?: "")
            UploadStatus.FAILED -> getString(R.string.u_failed, ur.lastError ?: "")
            UploadStatus.CANCELED -> getString(R.string.u_canceled)
        }
        val busy = ur?.status == UploadStatus.QUEUED || ur?.status == UploadStatus.UPLOADING
        btnUpload.isEnabled = !recording && latest != null && !busy
        btnUpload.text = getString(if (ur?.status == UploadStatus.FAILED || ur?.status == UploadStatus.CANCELED) R.string.retry_upload else R.string.upload_latest)
        btnCancelUpload.isEnabled = busy
        renderSessions(sessions.list().take(20))
    }

    private var lastRendered: List<String> = emptyList()

    private fun renderSessions(list: List<SessionRecord>) {
        val (_, uploads) = UploadJobService.stores(this)
        val exports = Exports.store(this)
        val moving = Exports.progress
        val rows = list.map { r ->
            val u = uploads.get(r.id).status
            val e = exports.get(r.id)
            val size = if (e.status == ExportStatus.EXPORTED) e.pcapSize
                else CaptureFileProvider.capturesDir(this).resolve("${r.id}.pcapng").takeIf { it.exists() }?.length()
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
        listSessions.removeAllViews()
        list.zip(rows).forEach { (r, text) ->
            val tv = TextView(this).apply {
                this.text = text
                textSize = 12f
                setPadding(0, 12, 0, 12)
                setOnClickListener { sessionActions(r) }
            }
            listSessions.addView(tv)
        }
    }

    private fun sessionActions(r: SessionRecord) {
        val (sessions, _) = UploadJobService.stores(this)
        val mover = Exports.mover(this)
        val pair = mover.pairFor(r)
        val e = Exports.store(this).get(r.id)
        val items = ArrayList<Pair<String, () -> Unit>>()
        if (pair != null) items += getString(R.string.share_pair) to { share(pair) }
        if (pair != null && r.state == SessionState.COMPLETE && CaptureVpnService.active == null)
            items += getString(R.string.upload_this) to { scheduleUpload(r.id) }
        if (mover.eligible(r) && e.status != ExportStatus.EXPORTED && e.status != ExportStatus.QUEUED && !Exports.isLocked(r.id))
            items += getString(R.string.move_to_downloads) to { Exports.request(this, r.id); refresh() }
        if (!r.state.isActive) items += getString(R.string.delete) to {
            AlertDialog.Builder(this).setMessage(R.string.delete_confirm)
                .setPositiveButton(R.string.delete) { _, _ ->
                    if (Exports.isLocked(r.id)) {
                        Toast.makeText(this, R.string.delete_busy, Toast.LENGTH_LONG).show()
                    } else {
                        if (!mover.deleteExported(r.id)) Toast.makeText(this, R.string.delete_shared_failed, Toast.LENGTH_LONG).show()
                        sessions.delete(r.id)
                    }
                    refresh()
                }
                .setNegativeButton(android.R.string.cancel, null).show()
        }
        if (items.isEmpty()) return
        AlertDialog.Builder(this).setTitle(r.id)
            .setItems(items.map { it.first }.toTypedArray()) { _, i -> items[i].second() }
            .show()
    }

    private fun share(pair: CapturePair) {
        val files = listOf(pair.pcap, pair.meta)
        val uris = ArrayList(files.map {
            when (it) {
                is PrivateFile -> CaptureFileProvider.uriFor(it.file)
                is ExportFile -> Uri.parse(it.ref)
                else -> throw IllegalStateException()
            }
        })
        val clip = ClipData.newRawUri(files[0].name, uris[0]).apply { for (u in uris.drop(1)) addItem(ClipData.Item(u)) }
        val send = Intent(Intent.ACTION_SEND_MULTIPLE)
            .setType("*/*")
            .putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        send.clipData = clip
        startActivity(Intent.createChooser(send, getString(R.string.share_pair)))
    }

    companion object {
        private const val REQ_VPN = 1
        private const val REQ_NOTIF = 2
    }
}
