package dev.minipcap.ui

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
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
import android.widget.CheckBox
import android.widget.RadioGroup
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import dev.minipcap.BuildConfig
import dev.minipcap.R
import dev.minipcap.capture.CaptureConfig
import dev.minipcap.capture.FilterMode
import dev.minipcap.meta.collect.MeasurementConfig
import dev.minipcap.capture.Variant
import dev.minipcap.service.CaptureVpnService
import dev.minipcap.notify.Notifications
import dev.minipcap.storage.Exports
import dev.minipcap.session.SessionState
import dev.minipcap.session.Sessions
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
    private lateinit var cbGps: CheckBox
    private lateinit var cbRadio: CheckBox
    private lateinit var cbMotion: CheckBox
    private lateinit var tvLatest: TextView
    private lateinit var tvUploadStatus: TextView
    private lateinit var btnUpload: Button
    private lateinit var btnCancelUpload: Button
    private lateinit var sessionList: SessionList
    private val debug = DebugCommands(this)
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
        cbGps = findViewById(R.id.cbGps)
        cbRadio = findViewById(R.id.cbRadio)
        cbMotion = findViewById(R.id.cbMotion)
        tvLatest = findViewById(R.id.tvLatest)
        tvUploadStatus = findViewById(R.id.tvUploadStatus)
        btnUpload = findViewById(R.id.btnUpload)
        btnCancelUpload = findViewById(R.id.btnCancelUpload)
        sessionList = SessionList(this, findViewById(R.id.listSessions)) { refresh() }

        spSnaplen.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item,
            CaptureConfig.SNAPLENS.map {
                when (it) {
                    0 -> "Full packet"
                    CaptureConfig.HEADERS_ONLY -> "Headers only (IP + TCP/UDP)"
                    else -> "$it bytes (always incl. headers)"
                }
            })
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
        for (cb in listOf(cbGps, cbRadio, cbMotion)) cb.setOnCheckedChangeListener { _, _ -> saveConfig() }
        val sel = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>?, v: View?, pos: Int, id: Long) = saveConfig()
            override fun onNothingSelected(p: AdapterView<*>?) {}
        }
        spSnaplen.onItemSelectedListener = sel
        spVariant.onItemSelectedListener = sel

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)

        if (savedInstanceState == null) debug.handle(intent)
    }

    /** Once, after next-launch recovery has finished (it runs in the background). */
    private fun showRecovered() {
        if (!Sessions.recoveryDone) return
        val rec = Sessions.recovered
        if (rec.isEmpty()) return
        Sessions.recovered = emptyList()
        AlertDialog.Builder(this)
            .setTitle(R.string.recovered_title)
            .setMessage(getString(R.string.recovered_text, rec.size, rec.joinToString("\n") { "${it.id.take(8)}: ${it.state}" }))
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        debug.handle(intent)
    }

    override fun onResume() {
        super.onResume()
        loadConfig()
        Sessions.listeners.add(listener)
        UploadJobService.listeners.add(listener)
        Exports.listeners.add(listener)
        main.post(ticker)
    }

    override fun onPause() {
        Sessions.listeners.remove(listener)
        UploadJobService.listeners.remove(listener)
        Exports.listeners.remove(listener)
        main.removeCallbacks(ticker)
        super.onPause()
    }

    internal fun loadConfig() {
        loadingConfig = true
        val c = CaptureConfig.load(this)
        rgFilter.check(when (c.filterMode) {
            FilterMode.ALL -> R.id.rbAll
            FilterMode.INCLUDE -> R.id.rbInclude
            FilterMode.EXCLUDE -> R.id.rbExclude
        })
        spSnaplen.setSelection(CaptureConfig.SNAPLENS.indexOf(c.snaplen).coerceAtLeast(0))
        spVariant.setSelection(c.variant.ordinal)
        val m = MeasurementConfig.load(this)
        cbGps.isChecked = m.gps
        cbRadio.isChecked = m.radio
        cbMotion.isChecked = m.motion
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
        CaptureConfig.save(this, old.copy(filterMode = mode, snaplen = CaptureConfig.SNAPLENS[spSnaplen.selectedItemPosition],
            variant = variant))
        MeasurementConfig.save(this, MeasurementConfig.load(this).copy(gps = cbGps.isChecked, radio = cbRadio.isChecked,
            motion = cbMotion.isChecked))
        btnPickApps.isEnabled = mode != FilterMode.ALL
    }

    internal fun onStartStop(automated: Boolean = false) {
        val a = Sessions.active
        if (a != null) {
            if (a.state == SessionState.RECORDING) CaptureVpnService.requestStop(this, a.id)
            return
        }
        val c = CaptureConfig.load(this)
        if (c.filterMode == FilterMode.INCLUDE && c.selectedPackages.isEmpty()) {
            Toast.makeText(this, R.string.include_empty, Toast.LENGTH_LONG).show()
            return
        }
        // Measurements: ask for the runtime permissions once per Start; capture starts either
        // way and the .meta file records SENSOR_STATUS permission_denied for what was refused.
        // Automation (debug) never shows dialogs: grant with `adb shell pm grant` beforehand.
        val m = MeasurementConfig.load(this)
        if (!automated) {
            val wanted = (if (m.gps) LOCATION_PERMISSIONS else emptyList()) +
                (if (m.radio) LOCATION_PERMISSIONS + Manifest.permission.READ_PHONE_STATE else emptyList())
            val missing = wanted.distinct().filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
            if (missing.isNotEmpty()) {
                requestPermissions(missing.toTypedArray(), REQ_CONTEXT)
                return
            }
        }
        prepareVpnAndStart()
    }

    private fun prepareVpnAndStart() {
        val consent = VpnService.prepare(this)
        if (consent != null) startActivityForResult(consent, REQ_VPN) else CaptureVpnService.start(this)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_CONTEXT) return
        if (grantResults.any { it != PackageManager.PERMISSION_GRANTED })
            Toast.makeText(this, R.string.context_permissions_partial, Toast.LENGTH_LONG).show()
        prepareVpnAndStart()
    }

    @Deprecated("Activity result API without AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) CaptureVpnService.start(this)
            else Toast.makeText(this, R.string.vpn_denied, Toast.LENGTH_LONG).show()
        }
    }

    internal fun uploadLatest() {
        val (sessions, _) = UploadJobService.stores(this)
        val latest = sessions.latestCompleted(Exports.mover(this)::pairFor)
        if (latest == null) {
            Toast.makeText(this, R.string.no_complete_capture, Toast.LENGTH_LONG).show()
            return
        }
        scheduleUpload(latest.id)
    }

    internal fun scheduleUpload(id: String) {
        val err = UploadJobService.schedule(this, id)
        if (err != null) Toast.makeText(this, err, Toast.LENGTH_LONG).show()
        refresh()
    }

    private fun refresh() {
        val a = Sessions.active
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
        for (v in listOf(rgFilter, spSnaplen, spVariant, cbGps, cbRadio, cbMotion)) v.isEnabled = !recording
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
        } else Sessions.lastResult ?: ""

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
        sessionList.render(sessions.list().take(20))
        showRecovered()
    }

    companion object {
        private const val REQ_VPN = 1
        private const val REQ_NOTIF = 2
        private const val REQ_CONTEXT = 3
        private val LOCATION_PERMISSIONS = listOf(Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION)
    }
}
