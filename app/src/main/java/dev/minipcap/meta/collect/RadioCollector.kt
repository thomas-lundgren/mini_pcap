package dev.minipcap.meta.collect

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.Handler
import android.telephony.CellInfo
import android.telephony.PhoneStateListener
import android.telephony.ServiceState
import android.telephony.SignalStrength
import android.telephony.SubscriptionManager
import android.telephony.TelephonyCallback
import android.telephony.TelephonyDisplayInfo
import android.telephony.TelephonyManager
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter

/**
 * Radio, event driven:
 * - RADIO_STATE (technology + NSA override, data state/activity, service state) on change
 * - CELL_IDENTITY when the serving-cell set changes, plus a periodic refresh
 * - CELL_MEASUREMENT for each new cell-info report (serving + neighbors)
 * - SIGNAL_STRENGTH for each serving signal report
 * Cell info is additionally requested every radioRefreshMs (each request wakes the modem).
 * Every listener is registered on its own, so one missing permission only loses its data.
 */
class RadioCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler, MetaFormat.SRC_RADIO) {
    private val tm: TelephonyManager? = ctx.getSystemService(TelephonyManager::class.java)?.let {
        val sub = SubscriptionManager.getDefaultDataSubscriptionId()
        if (sub != SubscriptionManager.INVALID_SUBSCRIPTION_ID) it.createForSubscriptionId(sub) else it
    }
    private val callbacks = ArrayList<TelephonyCallback>()
    private var legacyListener: PhoneStateListener? = null

    // RADIO_STATE fields (null = not reported)
    private var netType: Int? = null
    private var override: Int? = null
    private var dataState: Int? = null
    private var activity: Int? = null
    private var service: Int? = null
    private var lastRadio = ""
    private var lastCellTsMs = -1L
    private var servingKey = ""
    private var lastIdentityNs = 0L

    private val refresh = object : Runnable {
        @SuppressLint("MissingPermission") // fine location checked
        override fun run() {
            if (has(Manifest.permission.ACCESS_FINE_LOCATION)) runCatching {
                tm?.requestCellInfoUpdate(exec, object : TelephonyManager.CellInfoCallback() {
                    override fun onCellInfo(list: MutableList<CellInfo>) = cells(list)
                })
            }
            handler.postDelayed(this, cfg.radioRefreshMs)
        }
    }

    private fun radioChanged() {
        val t = tm ?: return
        val op = t.networkOperator.ifEmpty { null }
        val roaming = runCatching { t.isNetworkRoaming }.getOrNull()
        val key = "$netType/$override/$dataState/$activity/$service/$roaming/$op"
        if (key == lastRadio) return
        lastRadio = key
        MetaRecords.radioState(w, now(), netType, override, dataState, activity, service, roaming, op,
            t.networkOperatorName.ifEmpty { null })
    }

    fun cells(list: List<CellInfo>) {
        if (list.isEmpty()) return
        val newestMs = list.maxOf { CellInfoMapper.tsOf(it) } / 1_000_000
        if (newestMs == lastCellTsMs) return // the same modem report delivered twice
        lastCellTsMs = newestMs
        MetaRecords.cellMeasurement(w, newestMs * 1_000_000, true, list.mapNotNull(CellInfoMapper::measurement))
        val ids = list.filter { it.isRegistered }.mapNotNull(CellInfoMapper::identity)
        val key = ids.joinToString { "${it.rat}:${it.cid}:${it.pci}:${it.arfcn}" }
        val t = now()
        if (key != servingKey || t - lastIdentityNs >= cfg.cellIdentityRefreshMs * 1_000_000) {
            val isRefresh = key == servingKey
            servingKey = key
            lastIdentityNs = t
            MetaRecords.cellIdentity(w, t, isRefresh, ids)
        }
    }

    fun signal(s: SignalStrength) {
        val modemTs = Build.VERSION.SDK_INT >= 30
        val tsNs = if (modemTs) s.timestampMillis * 1_000_000 else now()
        val cells = s.cellSignalStrengths.mapNotNull { CellInfoMapper.strength(it, true, 1, tsNs, null, null) }
        if (cells.isNotEmpty()) MetaRecords.signalStrength(w, tsNs, modemTs, cells)
    }

    @SuppressLint("MissingPermission") // each registration is attempted and its failure recorded
    override fun start() {
        val t = tm ?: run {
            status(MetaFormat.SRC_RADIO, MetaFormat.ST_UNAVAILABLE, "no telephony")
            return
        }
        val fine = has(Manifest.permission.ACCESS_FINE_LOCATION)
        if (has(Manifest.permission.READ_PHONE_STATE)) runCatching { netType = t.dataNetworkType }
        dataState = runCatching { t.dataState }.getOrNull()
        activity = runCatching { t.dataActivity }.getOrNull()
        var registered = 0
        val failures = ArrayList<String>()
        fun note(what: String, e: Throwable?) {
            if (e == null) registered++ else failures += "$what:${if (e is SecurityException) "permission" else e.javaClass.simpleName}"
        }
        if (Build.VERSION.SDK_INT >= 31) {
            fun reg(what: String, cb: TelephonyCallback) = note(what, runCatching {
                t.registerTelephonyCallback(exec, cb)
                callbacks += cb
            }.exceptionOrNull())
            reg("signal", object : TelephonyCallback(), TelephonyCallback.SignalStrengthsListener {
                override fun onSignalStrengthsChanged(s: SignalStrength) = signal(s)
            })
            reg("data_state", object : TelephonyCallback(), TelephonyCallback.DataConnectionStateListener {
                override fun onDataConnectionStateChanged(state: Int, networkType: Int) {
                    dataState = state; netType = networkType; radioChanged()
                }
            })
            reg("data_activity", object : TelephonyCallback(), TelephonyCallback.DataActivityListener {
                override fun onDataActivity(direction: Int) { activity = direction; radioChanged() }
            })
            reg("display_info", object : TelephonyCallback(), TelephonyCallback.DisplayInfoListener {
                override fun onDisplayInfoChanged(d: TelephonyDisplayInfo) {
                    override = d.overrideNetworkType; netType = d.networkType; radioChanged()
                }
            })
            reg("service_state", object : TelephonyCallback(), TelephonyCallback.ServiceStateListener {
                override fun onServiceStateChanged(s: ServiceState) { service = s.state; radioChanged() }
            })
            if (fine) reg("cell_info", object : TelephonyCallback(), TelephonyCallback.CellInfoListener {
                override fun onCellInfoChanged(list: MutableList<CellInfo>) = cells(list)
            })
        } else {
            @Suppress("DEPRECATION")
            val l = object : PhoneStateListener(exec) {
                override fun onSignalStrengthsChanged(s: SignalStrength) = signal(s)
                override fun onDataConnectionStateChanged(state: Int, networkType: Int) { dataState = state; netType = networkType; radioChanged() }
                override fun onDataActivity(direction: Int) { activity = direction; radioChanged() }
                override fun onServiceStateChanged(s: ServiceState) { service = s.state; radioChanged() }
                override fun onCellInfoChanged(list: MutableList<CellInfo>?) { if (list != null) cells(list) }
                override fun onDisplayInfoChanged(d: TelephonyDisplayInfo) { // delivered on API 30 only (LISTEN_DISPLAY_INFO_CHANGED)
                    if (Build.VERSION.SDK_INT >= 30) {
                        override = d.overrideNetworkType
                        radioChanged()
                    }
                }
            }
            @Suppress("DEPRECATION")
            var events = PhoneStateListener.LISTEN_SIGNAL_STRENGTHS or PhoneStateListener.LISTEN_DATA_CONNECTION_STATE or
                PhoneStateListener.LISTEN_DATA_ACTIVITY
            @Suppress("DEPRECATION")
            if (has(Manifest.permission.READ_PHONE_STATE)) {
                events = events or PhoneStateListener.LISTEN_SERVICE_STATE
                if (Build.VERSION.SDK_INT == 30) events = events or PhoneStateListener.LISTEN_DISPLAY_INFO_CHANGED
            }
            @Suppress("DEPRECATION")
            if (fine) events = events or PhoneStateListener.LISTEN_CELL_INFO
            @Suppress("DEPRECATION")
            note("phone_state", runCatching { t.listen(l, events); legacyListener = l }.exceptionOrNull())
        }
        when {
            registered == 0 -> status(MetaFormat.SRC_RADIO, MetaFormat.ST_ERROR, failures.joinToString())
            failures.any { it.endsWith(":permission") } ->
                status(MetaFormat.SRC_RADIO, MetaFormat.ST_PERMISSION_DENIED, "partial: " + failures.joinToString())
            failures.isNotEmpty() -> status(MetaFormat.SRC_RADIO, MetaFormat.ST_ERROR, "partial: " + failures.joinToString())
            else -> status(MetaFormat.SRC_RADIO, MetaFormat.ST_ACTIVE)
        }
        if (fine) {
            status(MetaFormat.SRC_CELL_INFO, MetaFormat.ST_ACTIVE, "refresh ${cfg.radioRefreshMs} ms")
            runCatching { t.allCellInfo }.getOrNull()?.let { cells(it) }
            handler.postDelayed(refresh, cfg.radioRefreshMs)
        } else {
            status(MetaFormat.SRC_CELL_INFO, MetaFormat.ST_PERMISSION_DENIED, "fine location needed for cell info")
        }
        radioChanged()
    }

    override fun stop() {
        handler.removeCallbacks(refresh)
        if (Build.VERSION.SDK_INT >= 31) callbacks.forEach { cb -> runCatching { tm?.unregisterTelephonyCallback(cb) } }
        @Suppress("DEPRECATION")
        legacyListener?.let { l -> runCatching { tm?.listen(l, PhoneStateListener.LISTEN_NONE) } }
    }
}
