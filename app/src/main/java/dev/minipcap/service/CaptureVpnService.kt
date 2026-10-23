package dev.minipcap.service

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import dev.minipcap.BuildConfig
import dev.minipcap.capture.CaptureConfig
import dev.minipcap.capture.FilterMode
import dev.minipcap.capture.Variant
import dev.minipcap.meta.collect.MeasurementConfig
import dev.minipcap.notify.Notifications
import dev.minipcap.session.CaptureSession
import dev.minipcap.session.SessionState
import dev.minipcap.session.Sessions
import dev.minipcap.storage.ExportJobService
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Android shell of a recording: VPN establishment, foreground notification with Stop
 * logging, the 1 Hz status ticker and storage guards. The recording itself (native packet
 * path, metadata, finalization) is [CaptureSession].
 */
class CaptureVpnService : VpnService() {

    companion object {
        private const val TAG = "CaptureVpnService"
        const val ACTION_START = "dev.minipcap.action.START"
        const val ACTION_STOP_LOGGING = "dev.minipcap.action.STOP_LOGGING"
        const val EXTRA_SESSION_ID = "session_id"
        const val EXTRA_STALL_MS = "stall_ms"
        const val ACTION_DEBUG_STALL = "dev.minipcap.action.DEBUG_STALL"
        private const val LOW_STORAGE_BYTES = 200L shl 20
        const val TUN_ADDR4 = "10.111.0.2"
        const val TUN_ADDR6 = "fd00:6d70:6300::2"

        @Volatile var staleStopActions = 0
            private set

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, CaptureVpnService::class.java).setAction(ACTION_START))
        }

        /**
         * Explicit, immutable, session-scoped Stop action into this non-exported service. The
         * request code is derived from the session id so a stale PendingIntent from an older
         * session cannot be reused for the current one.
         */
        fun stopAction(ctx: Context, sessionId: String): PendingIntent = PendingIntent.getService(
            ctx, sessionId.hashCode(),
            Intent(ctx, CaptureVpnService::class.java).setAction(ACTION_STOP_LOGGING).putExtra(EXTRA_SESSION_ID, sessionId),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

        fun requestStop(ctx: Context, sessionId: String) {
            ctx.startService(Intent(ctx, CaptureVpnService::class.java)
                .setAction(ACTION_STOP_LOGGING).putExtra(EXTRA_SESSION_ID, sessionId))
        }
    }

    /** Serializes start/stop so Stop is ordered and idempotent. */
    private val control = Executors.newSingleThreadExecutor { Thread(it, "capture-control") }
    private lateinit var tickerThread: HandlerThread
    private lateinit var ticker: Handler

    override fun onCreate() {
        super.onCreate()
        tickerThread = HandlerThread("capture-status").also { it.start() }
        ticker = Handler(tickerThread.looper)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                // Must enter the foreground promptly after startForegroundService().
                goForeground(Notifications.starting(this))
                control.execute { startCapture() }
            }
            ACTION_STOP_LOGGING -> {
                val id = intent.getStringExtra(EXTRA_SESSION_ID)
                val a = Sessions.active
                if (a == null || id != a.id) {
                    staleStopActions++
                    Log.i(TAG, "ignoring stale Stop logging action")
                    if (a == null) stopSelf(startId)
                } else {
                    control.execute { stopCapture("user_stop") }
                }
            }
            ACTION_DEBUG_STALL -> if (BuildConfig.DEBUG) Sessions.active?.stallWriter(intent.getIntExtra(EXTRA_STALL_MS, 0))
            else -> {
                // Restarted by the system without an explicit Start (e.g. always-on VPN):
                // never resume capture without explicit user action.
                if (Sessions.active == null) stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    /** Location access in the background needs the "location" FGS type (while-in-use permission). */
    private fun locationType(): Int {
        val m = MeasurementConfig.load(this)
        val granted = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        return if ((m.gps || m.radio) && CaptureConfig.load(this).variant == Variant.F && granted)
            ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION else 0
    }

    private fun goForeground(n: Notification) {
        val loc = locationType()
        if (Build.VERSION.SDK_INT >= 34) {
            for (type in listOf(ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED or loc,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE or loc)) {
                try {
                    startForeground(Notifications.ID_CAPTURE, n, type)
                    return
                } catch (e: Exception) {
                    Log.w(TAG, "FGS type $type rejected: ${e.javaClass.simpleName}")
                }
            }
            // Never fail to start capture because of the optional location type.
            startForeground(Notifications.ID_CAPTURE, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else if (loc != 0) {
            startForeground(Notifications.ID_CAPTURE, n, loc)
        } else {
            startForeground(Notifications.ID_CAPTURE, n)
        }
    }

    private fun notify(id: Int, n: Notification) = getSystemService(NotificationManager::class.java).notify(id, n)

    // ------------------------------------------------------------------ start / stop

    private fun startCapture() {
        if (Sessions.active?.state?.isActive == true) return
        val cfg = CaptureConfig.load(this)
        val s = CaptureSession.create(this, cfg)
        Sessions.active = s
        Sessions.notifyListeners()
        try {
            val (builder, missing) = buildVpn(cfg)
            val pfd = builder.establish() ?: throw IllegalStateException("VPN permission not granted or revoked")
            s.start(pfd.detachFd(), missing) // the native engine owns the TUN fd from here
            notify(Notifications.ID_CAPTURE, Notifications.recording(this, stopAction(this, s.id), 0, if (cfg.variant.fullUi) 0 else null, 0))
            Sessions.notifyListeners()
            ticker.post(tick)
        } catch (e: Exception) {
            Log.e(TAG, "capture start failed: ${e.message}")
            Sessions.active = null
            Sessions.lastResult = "Start failed: ${e.message}"
            notify(Notifications.ID_RESULT, Notifications.error(this, e.message ?: "start failed"))
            stopForeground(STOP_FOREGROUND_REMOVE)
            Sessions.notifyListeners()
            stopSelf()
        }
    }

    private fun stopCapture(reason: String) {
        val s = Sessions.active ?: return
        if (s.state != SessionState.RECORDING) return // duplicate Stop / already stopping
        ticker.removeCallbacks(tick)
        notify(Notifications.ID_CAPTURE, Notifications.stopping(this))
        Sessions.notifyListeners()
        val ok = s.stop(reason)
        val records = s.counters?.get("records_written") ?: 0
        Sessions.lastResult = if (ok) "Saved ${s.id.take(8)} ($records packets)"
            else "Finalize failed; files kept for recovery at next start"
        Sessions.active = null
        if (ok) ExportJobService.schedule(this) // moves the pair to Downloads if enabled
        stopForeground(STOP_FOREGROUND_REMOVE)
        notify(Notifications.ID_RESULT, if (ok) Notifications.completed(this, s.id)
            else Notifications.error(this, Sessions.lastResult ?: "finalize failed"))
        Sessions.notifyListeners()
        stopSelf()
    }

    /** VPN for [cfg]'s app filter; returns the builder and the configured packages that are not installed. */
    private fun buildVpn(cfg: CaptureConfig): Pair<Builder, List<String>> {
        val cm = getSystemService(ConnectivityManager::class.java)
        val lp = cm.activeNetwork?.let { cm.getLinkProperties(it) }
        val hasV6 = lp?.linkAddresses?.any { la ->
            val ad = la.address
            ad is Inet6Address && !ad.isLinkLocalAddress && !ad.isSiteLocalAddress &&
                (ad.address[0].toInt() and 0xfe) != 0xfc
        } == true
        val b = Builder()
            .setSession("mini_pcap_collect")
            .setMtu(cfg.mtu)
            .setBlocking(false)
            .setMetered(false)
            .addAddress(TUN_ADDR4, 32)
            .addRoute("0.0.0.0", 0)
            .setConfigureIntent(PendingIntent.getActivity(this, 0, Notifications.appIntent(this), PendingIntent.FLAG_IMMUTABLE))
        if (hasV6) {
            b.addAddress(TUN_ADDR6, 128)
            b.addRoute("::", 0)
        }
        // DNS: reuse the underlying network's resolvers (reachable through the relay).
        val dns = lp?.dnsServers.orEmpty().filter { d ->
            when (d) {
                is Inet4Address -> true
                is Inet6Address -> hasV6 && !d.isLinkLocalAddress
                else -> false
            }
        }.ifEmpty {
            listOfNotNull(InetAddress.getByName("8.8.8.8"), if (hasV6) InetAddress.getByName("2001:4860:4860::8888") else null)
        }
        dns.forEach { b.addDnsServer(it) }

        // Per-app filter. The app always excludes itself so relay sockets bypass the VPN
        // (no routing loop, no per-flow protect() JNI call). Never both allow and disallow.
        val missing = ArrayList<String>()
        when (cfg.filterMode) {
            FilterMode.ALL -> b.addDisallowedApplication(packageName)
            FilterMode.INCLUDE -> {
                var added = 0
                for (p in cfg.selectedPackages.filter { it != packageName }) {
                    try {
                        b.addAllowedApplication(p); added++
                    } catch (e: PackageManager.NameNotFoundException) {
                        missing += p
                    }
                }
                // Android treats an empty allow-list as "all apps": refuse instead of widening.
                if (added == 0) throw IllegalStateException("Include mode needs at least one installed app")
            }
            FilterMode.EXCLUDE -> {
                b.addDisallowedApplication(packageName)
                for (p in cfg.selectedPackages.filter { it != packageName }) {
                    try {
                        b.addDisallowedApplication(p)
                    } catch (e: PackageManager.NameNotFoundException) {
                        missing += p
                    }
                }
            }
        }
        return b to missing
    }

    // ------------------------------------------------------------------ status

    private val tick = object : Runnable {
        override fun run() {
            val s = Sessions.active ?: return
            val c = s.tick() ?: return
            if (s.config.variant.fullUi)
                notify(Notifications.ID_CAPTURE, Notifications.recording(this@CaptureVpnService, stopAction(this@CaptureVpnService, s.id),
                    SystemClock.elapsedRealtime() - s.startedElapsed, c["records_written"], c["file_bytes"]))
            Sessions.notifyListeners()
            when {
                c["storage_errors"] > 0 -> control.execute { stopCapture("storage_error") }
                Sessions.dir(this@CaptureVpnService).usableSpace < LOW_STORAGE_BYTES -> control.execute { stopCapture("low_storage") }
                else -> ticker.postDelayed(this, 1000)
            }
        }
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked consent: graceful stop if we still run.
        control.execute { stopCapture("vpn_revoked") }
    }

    override fun onDestroy() {
        if (Sessions.active?.state == SessionState.RECORDING) {
            runCatching { control.submit { stopCapture("service_destroyed") }.get(15, TimeUnit.SECONDS) }
        }
        control.shutdown()
        tickerThread.quitSafely()
        super.onDestroy()
    }
}
