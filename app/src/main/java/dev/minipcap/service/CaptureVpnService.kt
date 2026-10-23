package dev.minipcap.service

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
import dev.minipcap.capture.ClassRules
import dev.minipcap.capture.CounterSnapshot
import dev.minipcap.capture.FilterMode
import dev.minipcap.capture.NativeCore
import dev.minipcap.capture.PackageRegistry
import dev.minipcap.capture.Sidecar
import dev.minipcap.capture.SidecarData
import dev.minipcap.capture.UidResolver
import dev.minipcap.storage.CaptureFileProvider
import dev.minipcap.storage.ExportJobService
import dev.minipcap.storage.SessionState
import dev.minipcap.storage.SessionStore
import dev.minipcap.ui.MainActivity
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.UUID
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** In-process view of the running capture, read by the UI. */
class ActiveCapture(val id: String, val config: CaptureConfig, val startedElapsed: Long, val startedUtcMs: Long) {
    @Volatile var state: SessionState = SessionState.PREPARING
    @Volatile var handle: Long = 0
    @Volatile var counters: CounterSnapshot? = null
    @Volatile var resolver: UidResolver? = null
    @Volatile var registry: PackageRegistry? = null
    @Volatile var missingPackages: List<String> = emptyList()
    @Volatile var stopReason: String? = null
}

class CaptureVpnService : VpnService() {

    companion object {
        private const val TAG = "CaptureVpnService"
        const val ACTION_START = "dev.minipcap.action.START"
        const val ACTION_STOP_LOGGING = "dev.minipcap.action.STOP_LOGGING"
        const val EXTRA_SESSION_ID = "session_id"
        const val EXTRA_STALL_MS = "stall_ms"
        const val ACTION_DEBUG_STALL = "dev.minipcap.action.DEBUG_STALL"
        private const val LOW_STORAGE_BYTES = 200L shl 20
        private const val CHECKPOINT_MS = 10_000L
        const val TUN_ADDR4 = "10.111.0.2"
        const val TUN_ADDR6 = "fd00:6d70:6300::2"

        @Volatile var active: ActiveCapture? = null
            private set
        @Volatile var lastResult: String? = null
            private set
        @Volatile var staleStopActions = 0
            private set
        val listeners = CopyOnWriteArraySet<() -> Unit>()

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, CaptureVpnService::class.java).setAction(ACTION_START))
        }

        fun requestStop(ctx: Context, sessionId: String) {
            ctx.startService(Intent(ctx, CaptureVpnService::class.java)
                .setAction(ACTION_STOP_LOGGING).putExtra(EXTRA_SESSION_ID, sessionId))
        }

        private fun notifyListeners() = listeners.forEach { runCatching { it() } }
    }

    /** Serializes start/stop/finalize so Stop is ordered and idempotent. */
    private val control = Executors.newSingleThreadExecutor { Thread(it, "capture-control") }
    private lateinit var tickerThread: HandlerThread
    private lateinit var ticker: Handler
    private lateinit var store: SessionStore
    private var lastCheckpoint = 0L
    private val checkpointLock = Any()

    override fun onCreate() {
        super.onCreate()
        store = SessionStore(CaptureFileProvider.capturesDir(this))
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
                val a = active
                if (a == null || id != a.id) {
                    staleStopActions++
                    Log.i(TAG, "ignoring stale Stop logging action")
                    if (a == null) stopSelf(startId)
                } else {
                    control.execute { stopCapture("user_stop") }
                }
            }
            ACTION_DEBUG_STALL -> if (BuildConfig.DEBUG) {
                val ms = intent.getIntExtra(EXTRA_STALL_MS, 0)
                active?.handle?.takeIf { it != 0L }?.let { NativeCore.nativeWriterStall(it, ms) }
            }
            else -> {
                // Restarted by the system without an explicit Start (e.g. always-on VPN):
                // never resume capture without explicit user action.
                if (active == null) stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    private fun goForeground(n: android.app.Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            try {
                startForeground(Notifications.ID_CAPTURE, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
                return
            } catch (e: Exception) {
                Log.w(TAG, "systemExempted FGS rejected, falling back to specialUse: ${e.javaClass.simpleName}")
            }
            startForeground(Notifications.ID_CAPTURE, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(Notifications.ID_CAPTURE, n)
        }
    }

    private fun updateNotification(n: android.app.Notification) =
        getSystemService(NotificationManager::class.java).notify(Notifications.ID_CAPTURE, n)

    // ------------------------------------------------------------------ start

    private fun startCapture() {
        if (active?.state?.isActive == true) return
        val cfg = CaptureConfig.load(this)
        val id = UUID.randomUUID().toString()
        val a = ActiveCapture(id, cfg, SystemClock.elapsedRealtime(), System.currentTimeMillis())
        store.create(id, cfg.variant.name, a.startedUtcMs)
        active = a
        notifyListeners()
        try {
            NativeCore.checkLayout()
            val builder = buildVpn(cfg, a)
            val pfd = builder.establish() ?: throw IllegalStateException("VPN permission not granted or revoked")
            val fd = pfd.detachFd() // native engine owns the TUN fd from here
            val path = if (cfg.variant.writesFile) store.pcapPartial(id).absolutePath else null
            val h = NativeCore.nativeStart(
                fd, path, cfg.snaplen, cfg.mtu, cfg.variant.nativeId, cfg.ringBytes,
                "mini_pcap_collect ${BuildConfig.VERSION_NAME}",
                "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                "${Build.MANUFACTURER} ${Build.MODEL}")
            // Handles are tagged heap pointers (may be negative as jlong); errors are -errno.
            if (h in -4095L..0L) throw IllegalStateException("native capture start failed (errno ${-h})")
            a.handle = h
            if (cfg.variant.resolvesUids) {
                val reg = PackageRegistry(packageManager, ClassRules.parse(ClassRules.loadText(this)))
                a.registry = reg
                a.resolver = UidResolver(h, getSystemService(ConnectivityManager::class.java)) { reg.noteUid(it) }
                    .also { it.start() }
            }
            a.state = SessionState.RECORDING
            store.update(id) { it.copy(state = SessionState.RECORDING) }
            lastCheckpoint = SystemClock.elapsedRealtime()
            updateNotification(Notifications.recording(this, id, 0, if (cfg.variant.fullUi) 0 else null, 0))
            notifyListeners()
            ticker.post(tick)
        } catch (e: Exception) {
            Log.e(TAG, "capture start failed: ${e.message}")
            // Never leave a running native session (and an active VPN) behind on failure.
            a.resolver?.let { NativeCore.nativeStop(a.handle); it.join(1000) }
            if (a.handle != 0L) {
                NativeCore.nativeStop(a.handle)
                NativeCore.nativeDestroy(a.handle)
                a.handle = 0
            }
            a.state = SessionState.ERROR
            store.markFinalized(id, SessionState.ERROR, System.currentTimeMillis(), "start_failed")
            store.update(id) { it.copy(error = e.message) }
            active = null
            lastResult = "Start failed: ${e.message}"
            getSystemService(NotificationManager::class.java)
                .notify(Notifications.ID_RESULT, Notifications.error(this, e.message ?: "start failed"))
            stopForeground(STOP_FOREGROUND_REMOVE)
            notifyListeners()
            stopSelf()
        }
    }

    private fun buildVpn(cfg: CaptureConfig, a: ActiveCapture): Builder {
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
            .setConfigureIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE))
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
        a.missingPackages = missing
        return b
    }

    // ------------------------------------------------------------------ status

    private val tick = object : Runnable {
        override fun run() {
            val a = active ?: return
            if (a.state != SessionState.RECORDING || a.handle == 0L) return
            val arr = LongArray(NativeCore.counterNames.size)
            NativeCore.nativeCounters(a.handle, arr)
            val c = CounterSnapshot(arr)
            a.counters = c
            val elapsed = SystemClock.elapsedRealtime() - a.startedElapsed
            if (a.config.variant.fullUi) {
                updateNotification(Notifications.recording(this@CaptureVpnService, a.id, elapsed,
                    c["records_written"], c["file_bytes"]))
                if (SystemClock.elapsedRealtime() - lastCheckpoint >= CHECKPOINT_MS) {
                    lastCheckpoint = SystemClock.elapsedRealtime()
                    checkpoint(a, c)
                }
            }
            notifyListeners()
            when {
                c["storage_errors"] > 0 -> control.execute { stopCapture("storage_error") }
                store.dir.usableSpace < LOW_STORAGE_BYTES -> control.execute { stopCapture("low_storage") }
                else -> ticker.postDelayed(this, 1000)
            }
        }
    }

    private fun sidecarData(a: ActiveCapture, c: CounterSnapshot, status: String, endedMs: Long?): SidecarData {
        val r = a.resolver
        val uidStats = HashMap<String, Long>()
        if (r != null) {
            uidStats["uid_lookup_misses"] = r.misses
            uidStats["uid_flows_resolved"] = r.resolved
            uidStats["uid_lookup_calls"] = r.lookupCalls
            uidStats["uid_requests_received"] = r.requests
            uidStats.putAll(r.latencyPercentiles())
        }
        return SidecarData(
            captureId = a.id, status = status, startedUtcMs = a.startedUtcMs, endedUtcMs = endedMs,
            snaplen = a.config.snaplen, mtu = a.config.mtu, filterMode = a.config.filterMode,
            filterPackages = a.config.selectedPackages.toList().takeIf { a.config.filterMode != FilterMode.ALL } ?: emptyList(),
            missingPackages = a.missingPackages, variant = a.config.variant,
            uidMap = a.registry?.snapshot() ?: emptyMap(),
            flowUidMap = r?.flowUidMap?.let { HashMap(it) } ?: emptyMap(),
            counters = c.toMap(), uidStats = uidStats, stopReason = a.stopReason,
            appVersion = BuildConfig.VERSION_NAME, deviceApiLevel = Build.VERSION.SDK_INT,
            anchorBoottimeNs = c["anchor_boottime_ns"], anchorRealtimeNs = c["anchor_realtime_ns"])
    }

    /** Crash-recovery checkpoint of the sidecar (atomic replace, ~every 10 s). */
    private fun checkpoint(a: ActiveCapture, c: CounterSnapshot) {
        synchronized(checkpointLock) {
            if (a.state != SessionState.RECORDING) return
            runCatching { Sidecar.writeAtomic(store.metaCheckpoint(a.id), Sidecar.build(sidecarData(a, c, "recording", null))) }
                .onFailure { Log.w(TAG, "checkpoint failed: ${it.javaClass.simpleName}") }
        }
    }

    // ------------------------------------------------------------------ stop

    /** Ordered, idempotent Stop: RECORDING -> STOPPING -> finalize -> COMPLETE. */
    private fun stopCapture(reason: String) {
        val a = active ?: return
        synchronized(checkpointLock) {
            if (a.state != SessionState.RECORDING) return // duplicate Stop / already stopping
            a.state = SessionState.STOPPING
        }
        a.stopReason = reason
        ticker.removeCallbacks(tick)
        store.update(a.id) { it.copy(state = SessionState.STOPPING, stopReason = reason) }
        updateNotification(Notifications.stopping(this))
        notifyListeners()
        val t0 = SystemClock.elapsedRealtime()
        // 1) quiesce tap, stop forwarding, close TUN; 2) drain + flush + fsync + close PCAPNG.
        val rc = NativeCore.nativeStop(a.handle)
        a.resolver?.join(3000)
        a.registry?.shutdown()
        val arr = LongArray(NativeCore.counterNames.size)
        NativeCore.nativeCounters(a.handle, arr)
        val c = CounterSnapshot(arr)
        a.counters = c
        var finalState = SessionState.COMPLETE
        try {
            val now = System.currentTimeMillis()
            if (rc != 0 && a.config.variant.writesFile)
                dev.minipcap.storage.PcapngRecovery.truncateToValidPrefix(store.pcapPartial(a.id))
            val data = sidecarData(a, c, "complete", now)
            val json = Sidecar.build(data)
            json.getJSONObject("stats").put("stop_finalize_ms", SystemClock.elapsedRealtime() - t0)
            Sidecar.writeAtomic(store.metaFinal(a.id), json)
            if (a.config.variant.writesFile && !store.pcapPartial(a.id).renameTo(store.pcapFinal(a.id)))
                throw java.io.IOException("rename of capture file failed")
            store.metaCheckpoint(a.id).delete()
            store.markFinalized(a.id, SessionState.COMPLETE, now, reason)
            ExportJobService.schedule(this) // moves the pair to Downloads if enabled
            lastResult = "Saved ${a.id.take(8)} (${c["records_written"]} packets)"
        } catch (e: Exception) {
            Log.e(TAG, "finalize failed: ${e.message}")
            finalState = SessionState.ERROR
            store.update(a.id) { it.copy(state = SessionState.ERROR, error = e.message) }
            lastResult = "Finalize failed: ${e.message}; partial files kept for recovery"
        }
        a.state = finalState
        NativeCore.nativeDestroy(a.handle)
        a.handle = 0
        active = null
        val nm = getSystemService(NotificationManager::class.java)
        stopForeground(STOP_FOREGROUND_REMOVE)
        nm.notify(Notifications.ID_RESULT,
            if (finalState == SessionState.COMPLETE) Notifications.completed(this, a.id)
            else Notifications.error(this, lastResult ?: "finalize failed"))
        notifyListeners()
        stopSelf()
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked consent: graceful stop if we still run.
        control.execute { stopCapture("vpn_revoked") }
    }

    override fun onDestroy() {
        if (active?.state == SessionState.RECORDING) {
            runCatching { control.submit { stopCapture("service_destroyed") }.get(15, TimeUnit.SECONDS) }
        }
        control.shutdown()
        tickerThread.quitSafely()
        super.onDestroy()
    }
}
