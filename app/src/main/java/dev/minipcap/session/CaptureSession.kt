package dev.minipcap.session

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.SystemClock
import android.util.Log
import dev.minipcap.BuildConfig
import dev.minipcap.capture.CaptureConfig
import dev.minipcap.capture.CounterSnapshot
import dev.minipcap.capture.FilterMode
import dev.minipcap.capture.NativeCore
import dev.minipcap.capture.PcapFormat
import dev.minipcap.capture.Variant
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.apps.ClassRules
import dev.minipcap.meta.apps.PackageRegistry
import dev.minipcap.meta.apps.UidResolver
import dev.minipcap.meta.collect.MeasurementConfig
import java.io.IOException
import java.util.UUID

/**
 * One recording: the native packet path (TUN -> .pcap), the metadata path (collectors ->
 * .meta), the flow-owner worker, and finalization. Driven by the capture service's single
 * control thread, so start/stop never run concurrently; state is readable from any thread.
 */
class CaptureSession private constructor(
    private val ctx: Context,
    private val store: SessionStore,
    val id: String,
    val config: CaptureConfig,
) {
    val startedElapsed: Long = SystemClock.elapsedRealtime()
    val startedUtcMs: Long = System.currentTimeMillis()
    @Volatile var state: SessionState = SessionState.PREPARING
        private set
    @Volatile var counters: CounterSnapshot? = null
        private set
    @Volatile var resolver: UidResolver? = null
        private set
    @Volatile var missingPackages: List<String> = emptyList()
        private set

    private var handle = 0L
    private var meta: MetaSession? = null
    private var registry: PackageRegistry? = null
    private var lastStats = 0L

    /** Native start on an established TUN (takes ownership of [tunFd]); cleans up and throws on failure. */
    fun start(tunFd: Int, missing: List<String>) {
        missingPackages = missing
        var fdOwned = true // until nativeStart, which always takes ownership (and closes it on failure)
        try {
            NativeCore.checkLayout()
            val path = if (config.variant.writesFile) store.pcapPartial(id).absolutePath else null
            fdOwned = false
            val h = NativeCore.nativeStart(tunFd, path, config.snaplen, config.mtu, config.variant.nativeId, config.ringBytes)
            // Handles are tagged heap pointers (may be negative as jlong); errors are -errno.
            if (h in -4095L..0L) throw IllegalStateException("native capture start failed (errno ${-h})")
            handle = h
            if (config.variant.writesFile) meta = startMeta(h)
            if (config.variant.resolvesUids) {
                val m = meta
                val reg = PackageRegistry(ctx.packageManager, ClassRules.parse(ClassRules.loadText(ctx))) { uid, info ->
                    m?.uid(uid, info)
                }
                registry = reg
                resolver = UidResolver(h, ctx.getSystemService(ConnectivityManager::class.java), reg::noteUid) { f ->
                    m?.flow(f)
                }.also { it.start() }
            }
            state = SessionState.RECORDING
            store.update(id) { it.copy(state = SessionState.RECORDING) }
            lastStats = SystemClock.elapsedRealtime()
        } catch (e: Exception) {
            if (fdOwned) runCatching { android.os.ParcelFileDescriptor.adoptFd(tunFd).close() }
            teardown()
            meta?.abandon()
            store.pcapPartial(id).delete()
            store.metaPartial(id).delete()
            if (handle != 0L) NativeCore.nativeDestroy(handle)
            handle = 0
            state = SessionState.FAILED
            store.markFinalized(id, SessionState.FAILED, System.currentTimeMillis(), "start_failed")
            store.update(id) { it.copy(error = e.message) }
            throw e
        }
    }

    private fun startMeta(h: Long): MetaSession {
        val c = snapshot(h)
        // Benchmark variants D/E keep only app/flow records; F runs every enabled collector.
        val m = if (config.variant == Variant.F) MeasurementConfig.load(ctx) else MeasurementConfig.APPS_ONLY
        return MetaSession(ctx, store.metaPartial(id), UUID.fromString(id), c["anchor_boottime_ns"], c["anchor_realtime_ns"],
            m, NativeCore::clockPair).also { it.start(sessionInfo()) }
    }

    private fun sessionInfo(): Map<String, String> = mapOf(
        "app_version" to BuildConfig.VERSION_NAME,
        "device_manufacturer" to Build.MANUFACTURER, "device_model" to Build.MODEL,
        "android_release" to Build.VERSION.RELEASE, "api_level" to "${Build.VERSION.SDK_INT}",
        "capture_point" to "android_vpn_tun", "forwarder" to FORWARDER_NAME,
        "pcap_file" to store.pcapFinal(id).name,
        "ip_snaplen" to if (config.snaplen == CaptureConfig.HEADERS_ONLY) "headers" else "${config.snaplen}",
        "min_capture" to "ip+transport header", "mtu" to "${config.mtu}",
        "filter_mode" to config.filterMode.name.lowercase(),
        "filter_packages" to if (config.filterMode == FilterMode.ALL) "" else config.selectedPackages.sorted().joinToString(","),
        "missing_packages" to missingPackages.sorted().joinToString(","),
        "benchmark_profile" to config.variant.profile,
        "started_utc_ms" to "$startedUtcMs",
    )

    private fun snapshot(h: Long): CounterSnapshot {
        val arr = LongArray(NativeCore.counterNames.size)
        NativeCore.nativeCounters(h, arr)
        return CounterSnapshot(arr)
    }

    /** ~1 Hz from the service: refresh counters; every [STATS_MS] also a CAPTURE_STATS record. */
    fun tick(): CounterSnapshot? {
        if (state != SessionState.RECORDING || handle == 0L) return null
        val c = snapshot(handle)
        counters = c
        if (SystemClock.elapsedRealtime() - lastStats >= STATS_MS) {
            lastStats = SystemClock.elapsedRealtime()
            meta?.stats(c.toMap())
        }
        return c
    }

    fun stallWriter(ms: Int) {
        if (handle != 0L) NativeCore.nativeWriterStall(handle, ms)
    }

    /**
     * Ordered, idempotent Stop. Returns true if the pair was finalized COMPLETE; false for a
     * duplicate Stop or a finalization error (files stay `.partial` for next-launch recovery).
     */
    fun stop(reason: String): Boolean {
        synchronized(this) {
            if (state != SessionState.RECORDING) return false
            state = SessionState.STOPPING
        }
        store.update(id) { it.copy(state = SessionState.STOPPING, stopReason = reason) }
        val t0 = SystemClock.elapsedRealtime()
        val rc = teardown()
        val c = snapshot(handle)
        counters = c
        val ok = try {
            if (rc != 0 && config.variant.writesFile) PcapFormat.truncateToValidPrefix(store.pcapPartial(id))
            val metaOk = meta?.finish(MetaFormat.END_COMPLETE, reason, c.toMap() + uidStats() +
                mapOf("stop_finalize_ms" to SystemClock.elapsedRealtime() - t0)) ?: true
            if (!metaOk) throw IOException("metadata file could not be completed")
            if (config.variant.writesFile) commitFiles()
            store.markFinalized(id, SessionState.COMPLETE, System.currentTimeMillis(), reason)
            true
        } catch (e: Exception) {
            Log.e(TAG, "finalize failed: ${e.message}")
            store.update(id) { it.copy(state = SessionState.ERROR, error = e.message) }
            false
        }
        NativeCore.nativeDestroy(handle)
        handle = 0
        state = if (ok) SessionState.COMPLETE else SessionState.ERROR
        return ok
    }

    /**
     * Shared by Stop and start failure: collectors first, then the native path (drains the
     * PCAP writer and closes the flow queue), then the flow worker records its remaining
     * flows, then app lookups end. Returns the native stop result.
     */
    private fun teardown(): Int {
        meta?.stopCollectors()
        val rc = if (handle != 0L) NativeCore.nativeStop(handle) else 0
        resolver?.let { r ->
            r.join(3000)
            if (r.isAlive) Log.w(TAG, "flow worker still running after stop; late FLOW_MAPPINGs are dropped")
        }
        registry?.shutdown()
        return rc
    }

    /** Metadata first, then packets: a crash in between leaves `.partial` files recovery understands. */
    private fun commitFiles() {
        if (!store.metaPartial(id).renameTo(store.metaFinal(id))) throw IOException("rename of the metadata file failed")
        if (!store.pcapPartial(id).renameTo(store.pcapFinal(id))) {
            store.metaFinal(id).renameTo(store.metaPartial(id))
            throw IOException("rename of the packet file failed")
        }
    }

    private fun uidStats(): Map<String, Long> {
        val r = resolver ?: return emptyMap()
        return mapOf("uid_lookup_misses" to r.misses, "uid_flows_resolved" to r.resolved,
            "uid_lookup_calls" to r.lookupCalls, "uid_requests_received" to r.requests) + r.latencyPercentiles()
    }

    companion object {
        private const val TAG = "CaptureSession"
        private const val STATS_MS = 10_000L
        const val FORWARDER_NAME = "lwip-heiher-e6d5fc6+socket-relay"

        fun create(ctx: Context, config: CaptureConfig): CaptureSession {
            val store = Sessions.store(ctx)
            val s = CaptureSession(ctx.applicationContext, store, UUID.randomUUID().toString(), config)
            store.create(s.id, config.variant.name, s.startedUtcMs)
            return s
        }
    }
}
