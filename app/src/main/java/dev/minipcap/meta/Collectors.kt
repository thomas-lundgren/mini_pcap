package dev.minipcap.meta

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.location.GnssStatus
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.location.LocationRequest
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.SystemClock
import android.telephony.CellIdentityNr
import android.telephony.CellInfo
import android.telephony.CellInfoCdma
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoTdscdma
import android.telephony.CellInfoWcdma
import android.telephony.CellSignalStrength
import android.telephony.CellSignalStrengthCdma
import android.telephony.CellSignalStrengthGsm
import android.telephony.CellSignalStrengthLte
import android.telephony.CellSignalStrengthNr
import android.telephony.CellSignalStrengthTdscdma
import android.telephony.CellSignalStrengthWcdma
import android.telephony.PhoneStateListener
import android.telephony.ServiceState
import android.telephony.SignalStrength
import android.telephony.SubscriptionManager
import android.telephony.TelephonyCallback
import android.telephony.TelephonyDisplayInfo
import android.telephony.TelephonyManager
import dev.minipcap.capture.MeasurementConfig
import dev.minipcap.capture.MotionMode
import java.util.concurrent.Executor
import kotlin.math.abs

/** One independent metadata source. start/stop run on the collector's handler thread. */
abstract class Collector(protected val ctx: Context, protected val w: MetaWriter, protected val handler: Handler) {
    protected val exec = Executor { handler.post(it) }
    protected fun now() = SystemClock.elapsedRealtimeNanos()
    protected fun has(p: String) = ctx.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED
    protected fun status(source: Int, state: Int, detail: String = "") = MetaRecords.sensorStatus(w, now(), source, state, detail)
    abstract fun start()
    abstract fun stop()
}

/** CLOCK_SYNC at start, periodically, on wall-clock/timezone changes and at stop. */
class ClockCollector(ctx: Context, w: MetaWriter, handler: Handler, private val periodMs: Long = 60_000) :
    Collector(ctx, w, handler) {
    private val tick = object : Runnable {
        override fun run() {
            sync(MetaFormat.CLOCK_PERIODIC)
            handler.postDelayed(this, periodMs)
        }
    }
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) =
            sync(if (i.action == Intent.ACTION_TIMEZONE_CHANGED) MetaFormat.CLOCK_TZ_CHANGED else MetaFormat.CLOCK_TIME_CHANGED)
    }

    /** Monotonic time bracketing the wall-clock read; the midpoint pairs with it. */
    fun sync(reason: Int) {
        val b0 = SystemClock.elapsedRealtimeNanos()
        val inst = java.time.Instant.now()
        val b1 = SystemClock.elapsedRealtimeNanos()
        MetaRecords.clockSync(w, b0 + (b1 - b0) / 2, inst.epochSecond * 1_000_000_000L + inst.nano, reason)
    }

    override fun start() {
        sync(MetaFormat.CLOCK_START)
        handler.postDelayed(tick, periodMs)
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_TIME_CHANGED)
            addAction(Intent.ACTION_TIMEZONE_CHANGED)
        }
        if (Build.VERSION.SDK_INT >= 33) ctx.registerReceiver(receiver, f, null, handler, Context.RECEIVER_NOT_EXPORTED)
        else ctx.registerReceiver(receiver, f, null, handler)
    }

    override fun stop() {
        handler.removeCallbacks(tick)
        runCatching { ctx.unregisterReceiver(receiver) }
    }
}

/** LOCATION for every fix the platform delivers (time/distance thresholds), GNSS_STATUS at most 1 Hz. */
class LocationCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler) {
    private val lm = ctx.getSystemService(LocationManager::class.java)
    private var lastGnssNs = 0L
    private var lastGnssUsed = -1
    private var satsUsed = -1

    private val listener = object : LocationListener {
        override fun onLocationChanged(l: Location) = record(l)
        override fun onLocationChanged(list: MutableList<Location>) = list.forEach { record(it) }
        override fun onProviderDisabled(p: String) { status(MetaFormat.SRC_LOCATION, MetaFormat.ST_DISABLED_IN_SYSTEM, p) }
        override fun onProviderEnabled(p: String) { status(MetaFormat.SRC_LOCATION, MetaFormat.ST_ACTIVE, p) }
    }

    private val gnss = object : GnssStatus.Callback() {
        override fun onSatelliteStatusChanged(s: GnssStatus) {
            var used = 0
            var cn0 = 0f
            var constellations = 0
            for (i in 0 until s.satelliteCount) if (s.usedInFix(i)) {
                used++
                cn0 += s.getCn0DbHz(i)
                constellations = constellations or (1 shl s.getConstellationType(i))
            }
            satsUsed = used
            val t = now()
            if (used != lastGnssUsed || t - lastGnssNs >= 1_000_000_000L) {
                lastGnssNs = t
                lastGnssUsed = used
                MetaRecords.gnssStatus(w, t, s.satelliteCount, used, if (used > 0) cn0 / used else Float.NaN, constellations)
            }
        }
    }

    private fun record(l: Location) {
        val provider = when (l.provider) {
            LocationManager.GPS_PROVIDER -> 1
            LocationManager.NETWORK_PROVIDER -> 2
            "fused" -> 3
            LocationManager.PASSIVE_PROVIDER -> 4
            else -> 0
        }
        MetaRecords.location(w, l.elapsedRealtimeNanos, now(), l.latitude, l.longitude,
            if (l.hasAltitude()) l.altitude else Double.NaN,
            if (Build.VERSION.SDK_INT >= 34 && l.hasMslAltitude()) l.mslAltitudeMeters else Double.NaN,
            if (l.hasAccuracy()) l.accuracy else Float.NaN,
            if (l.hasVerticalAccuracy()) l.verticalAccuracyMeters else Float.NaN,
            if (l.hasSpeed()) l.speed else Float.NaN,
            if (l.hasSpeedAccuracy()) l.speedAccuracyMetersPerSecond else Float.NaN,
            if (l.hasBearing()) l.bearing else Float.NaN,
            if (l.hasBearingAccuracy()) l.bearingAccuracyDegrees else Float.NaN,
            provider, if (provider == 1) satsUsed else -1)
    }

    @SuppressLint("MissingPermission") // guarded below
    override fun start() {
        val fine = has(Manifest.permission.ACCESS_FINE_LOCATION)
        if (!fine && !has(Manifest.permission.ACCESS_COARSE_LOCATION)) {
            status(MetaFormat.SRC_LOCATION, MetaFormat.ST_PERMISSION_DENIED)
            return
        }
        if (!lm.isLocationEnabled) status(MetaFormat.SRC_LOCATION, MetaFormat.ST_DISABLED_IN_SYSTEM, "location off")
        val provider = when {
            Build.VERSION.SDK_INT >= 31 && lm.hasProvider(LocationManager.FUSED_PROVIDER) -> LocationManager.FUSED_PROVIDER
            fine && lm.allProviders.contains(LocationManager.GPS_PROVIDER) -> LocationManager.GPS_PROVIDER
            else -> LocationManager.NETWORK_PROVIDER
        }
        try {
            if (Build.VERSION.SDK_INT >= 31) {
                lm.requestLocationUpdates(provider, LocationRequest.Builder(cfg.gpsMinTimeMs)
                    .setMinUpdateDistanceMeters(cfg.gpsMinDistanceM)
                    .setQuality(LocationRequest.QUALITY_HIGH_ACCURACY).build(), exec, listener)
            } else {
                lm.requestLocationUpdates(provider, cfg.gpsMinTimeMs, cfg.gpsMinDistanceM, listener, handler.looper)
            }
            status(MetaFormat.SRC_LOCATION, MetaFormat.ST_ACTIVE, provider)
        } catch (e: Exception) {
            status(MetaFormat.SRC_LOCATION, MetaFormat.ST_ERROR, e.javaClass.simpleName)
        }
        if (!fine) {
            status(MetaFormat.SRC_GNSS, MetaFormat.ST_PERMISSION_DENIED, "fine location needed")
            return
        }
        try {
            if (Build.VERSION.SDK_INT >= 30) lm.registerGnssStatusCallback(exec, gnss)
            else @Suppress("DEPRECATION") lm.registerGnssStatusCallback(gnss, handler)
            status(MetaFormat.SRC_GNSS, MetaFormat.ST_ACTIVE)
        } catch (e: Exception) {
            status(MetaFormat.SRC_GNSS, MetaFormat.ST_ERROR, e.javaClass.simpleName)
        }
    }

    override fun stop() {
        runCatching { lm.removeUpdates(listener) }
        runCatching { lm.unregisterGnssStatusCallback(gnss) }
    }
}

/**
 * MOTION_SAMPLE straight from sensor events (sensor timestamps), in one of three modes.
 * Uses the platform's batching (max report latency) so the CPU wakes rarely.
 */
class MotionCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler), SensorEventListener {
    private val sm = ctx.getSystemService(SensorManager::class.java)
    private val periodUs = (1_000_000 / cfg.motionHz.coerceIn(1, 1000))
    private val minGapNs = periodUs * 900L // MAX_RATE: tolerate 10 % jitter
    private val lastTs = LongArray(3)
    private val last = Array(3) { FloatArray(3) }

    private fun slot(type: Int) = if (type == Sensor.TYPE_GYROSCOPE) 1 else 0

    override fun onSensorChanged(e: SensorEvent) {
        val s = slot(e.sensor.type)
        val code = if (s == 1) MetaFormat.SENSOR_GYRO else MetaFormat.SENSOR_ACCEL
        when (cfg.motionMode) {
            MotionMode.ALL -> {}
            MotionMode.MAX_RATE -> if (e.timestamp - lastTs[s] < minGapNs) return
            MotionMode.THRESHOLD -> {
                val v = e.values
                val p = last[s]
                val changed = abs(v[0] - p[0]) >= cfg.motionThreshold || abs(v[1] - p[1]) >= cfg.motionThreshold ||
                    abs(v[2] - p[2]) >= cfg.motionThreshold
                if (!changed && e.timestamp - lastTs[s] < 1_000_000_000L) return
                p[0] = v[0]; p[1] = v[1]; p[2] = v[2]
            }
        }
        lastTs[s] = e.timestamp
        MetaRecords.motion(w, e.timestamp, code, e.accuracy, e.values, 3)
    }

    override fun onAccuracyChanged(s: Sensor?, accuracy: Int) {}

    override fun start() {
        val sensors = listOfNotNull(
            sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER).also { if (it == null) status(MetaFormat.SRC_ACCEL, MetaFormat.ST_UNAVAILABLE) },
            if (cfg.gyro) sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE).also { if (it == null) status(MetaFormat.SRC_GYRO, MetaFormat.ST_UNAVAILABLE) }
            else null.also { status(MetaFormat.SRC_GYRO, MetaFormat.ST_DISABLED_BY_USER) })
        for (s in sensors) {
            val src = if (s.type == Sensor.TYPE_GYROSCOPE) MetaFormat.SRC_GYRO else MetaFormat.SRC_ACCEL
            // Up to 200 ms of samples are delivered in one batch; timestamps stay per sample.
            val ok = runCatching { sm.registerListener(this, s, periodUs, 200_000, handler) }.getOrDefault(false)
            status(src, if (ok) MetaFormat.ST_ACTIVE else MetaFormat.ST_ERROR,
                "${s.name} ${cfg.motionMode.name.lowercase()} ${cfg.motionHz} Hz")
        }
    }

    override fun stop() = sm.unregisterListener(this)
}

/**
 * Radio: RADIO_STATE (technology, data state/activity, service state) on change,
 * CELL_IDENTITY when the serving-cell set changes (plus periodic refresh),
 * CELL_MEASUREMENT for each new cell-info report (serving + neighbors) and
 * SIGNAL_STRENGTH for each serving signal report. Event driven via TelephonyCallback;
 * cell info is additionally requested every radioRefreshMs.
 */
class RadioCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler) {
    private val tm: TelephonyManager? = ctx.getSystemService(TelephonyManager::class.java)?.let {
        val sub = SubscriptionManager.getDefaultDataSubscriptionId()
        if (sub != SubscriptionManager.INVALID_SUBSCRIPTION_ID) it.createForSubscriptionId(sub) else it
    }
    private val callbacks = ArrayList<Any>()
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
        @SuppressLint("MissingPermission")
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
        val name = t.networkOperatorName.ifEmpty { null }
        val roaming = runCatching { t.isNetworkRoaming }.getOrNull()
        val key = "$netType/$override/$dataState/$activity/$service/$roaming/$op"
        if (key == lastRadio) return
        lastRadio = key
        MetaRecords.radioState(w, now(), netType, override, dataState, activity, service, roaming, op, name)
    }

    private fun cellTsNs(ci: CellInfo): Long =
        if (Build.VERSION.SDK_INT >= 30) ci.timestampMillis * 1_000_000 else @Suppress("DEPRECATION") ci.timeStamp

    fun cells(list: List<CellInfo>) {
        if (list.isEmpty()) return
        val newest = list.maxOf { cellTsNs(it) } / 1_000_000
        if (newest == lastCellTsMs) return // same report delivered again
        lastCellTsMs = newest
        val meas = list.mapNotNull { measurement(it) }
        MetaRecords.cellMeasurement(w, newest * 1_000_000, true, meas)
        val serving = list.filter { it.isRegistered }
        val ids = serving.mapNotNull { identity(it) }
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
        val tsNs = if (Build.VERSION.SDK_INT >= 30) s.timestampMillis * 1_000_000 else now()
        val cells = s.cellSignalStrengths.mapNotNull { strength(it, true, 1, tsNs, null, null) }
        if (cells.isNotEmpty()) MetaRecords.signalStrength(w, tsNs, Build.VERSION.SDK_INT >= 30, cells)
    }

    @SuppressLint("MissingPermission")
    override fun start() {
        val t = tm ?: run {
            status(MetaFormat.SRC_RADIO, MetaFormat.ST_UNAVAILABLE, "no telephony")
            return
        }
        val fine = has(Manifest.permission.ACCESS_FINE_LOCATION)
        val phone = has(Manifest.permission.READ_PHONE_STATE)
        if (phone) runCatching { netType = t.dataNetworkType }
        dataState = runCatching { t.dataState }.getOrNull()
        activity = runCatching { t.dataActivity }.getOrNull()
        if (Build.VERSION.SDK_INT >= 31) {
            fun reg(cb: TelephonyCallback, what: String) = runCatching { t.registerTelephonyCallback(exec, cb); callbacks += cb }
                .onFailure { status(MetaFormat.SRC_RADIO, MetaFormat.ST_PERMISSION_DENIED, "$what: ${it.javaClass.simpleName}") }
            reg(object : TelephonyCallback(), TelephonyCallback.SignalStrengthsListener {
                override fun onSignalStrengthsChanged(s: SignalStrength) = signal(s)
            }, "signal")
            reg(object : TelephonyCallback(), TelephonyCallback.DataConnectionStateListener {
                override fun onDataConnectionStateChanged(state: Int, networkType: Int) {
                    dataState = state; netType = networkType; radioChanged()
                }
            }, "data_state")
            reg(object : TelephonyCallback(), TelephonyCallback.DataActivityListener {
                override fun onDataActivity(direction: Int) { activity = direction; radioChanged() }
            }, "data_activity")
            if (phone) {
                reg(object : TelephonyCallback(), TelephonyCallback.DisplayInfoListener {
                    override fun onDisplayInfoChanged(d: TelephonyDisplayInfo) {
                        override = d.overrideNetworkType; netType = d.networkType; radioChanged()
                    }
                }, "display_info")
                reg(object : TelephonyCallback(), TelephonyCallback.ServiceStateListener {
                    override fun onServiceStateChanged(s: ServiceState) { service = s.state; radioChanged() }
                }, "service_state")
            } else {
                status(MetaFormat.SRC_RADIO, MetaFormat.ST_PERMISSION_DENIED, "READ_PHONE_STATE: no technology override/service state")
            }
            if (fine) reg(object : TelephonyCallback(), TelephonyCallback.CellInfoListener {
                override fun onCellInfoChanged(list: MutableList<CellInfo>) = cells(list)
            }, "cell_info")
        } else {
            @Suppress("DEPRECATION")
            val l = object : PhoneStateListener(exec) {
                override fun onSignalStrengthsChanged(s: SignalStrength) = signal(s)
                override fun onDataConnectionStateChanged(state: Int, networkType: Int) { dataState = state; netType = networkType; radioChanged() }
                override fun onDataActivity(direction: Int) { activity = direction; radioChanged() }
                override fun onServiceStateChanged(s: ServiceState) { service = s.state; radioChanged() }
                override fun onCellInfoChanged(list: MutableList<CellInfo>?) { if (list != null) cells(list) }
            }
            var events = PhoneStateListener.LISTEN_SIGNAL_STRENGTHS or PhoneStateListener.LISTEN_DATA_CONNECTION_STATE or
                PhoneStateListener.LISTEN_DATA_ACTIVITY
            if (phone) events = events or PhoneStateListener.LISTEN_SERVICE_STATE
            if (fine) events = events or PhoneStateListener.LISTEN_CELL_INFO
            @Suppress("DEPRECATION")
            runCatching { t.listen(l, events); legacyListener = l }
                .onFailure { status(MetaFormat.SRC_RADIO, MetaFormat.ST_ERROR, it.javaClass.simpleName) }
        }
        status(MetaFormat.SRC_RADIO, MetaFormat.ST_ACTIVE)
        if (fine) {
            status(MetaFormat.SRC_CELL_INFO, MetaFormat.ST_ACTIVE, "refresh ${cfg.radioRefreshMs} ms")
            runCatching { t.allCellInfo }.getOrNull()?.let { cells(it) }
            handler.post(refresh)
        } else {
            status(MetaFormat.SRC_CELL_INFO, MetaFormat.ST_PERMISSION_DENIED, "fine location needed for cell info")
        }
        radioChanged()
    }

    override fun stop() {
        handler.removeCallbacks(refresh)
        if (Build.VERSION.SDK_INT >= 31) callbacks.forEach { cb -> runCatching { tm?.unregisterTelephonyCallback(cb as TelephonyCallback) } }
        @Suppress("DEPRECATION")
        legacyListener?.let { l -> runCatching { tm?.listen(l, PhoneStateListener.LISTEN_NONE) } }
    }

    companion object {
        private const val NA = CellInfo.UNAVAILABLE
        private fun v(x: Int): Int? = if (x == NA || x == Int.MIN_VALUE) null else x
        private fun vl(x: Long): Long? = if (x == CellInfo.UNAVAILABLE_LONG) null else x
        private fun conn(ci: CellInfo) = when (ci.cellConnectionStatus) {
            CellInfo.CONNECTION_NONE -> 0
            CellInfo.CONNECTION_PRIMARY_SERVING -> 1
            CellInfo.CONNECTION_SECONDARY_SERVING -> 2
            else -> 3
        }
        private fun mcc(s: String?) = s?.toIntOrNull()
        private fun tsOf(ci: CellInfo): Long =
            if (Build.VERSION.SDK_INT >= 30) ci.timestampMillis * 1_000_000 else @Suppress("DEPRECATION") ci.timeStamp

        fun identity(ci: CellInfo): CellIdentity? {
            val ts = tsOf(ci)
            val reg = ci.isRegistered
            val c = conn(ci)
            return when (ci) {
                is CellInfoLte -> ci.cellIdentity.let { id ->
                    CellIdentity(MetaFormat.RAT_LTE, reg, c, ts, mcc(id.mccString), mcc(id.mncString), id.mncString?.length ?: 0,
                        v(id.ci)?.toLong(), v(id.pci), v(id.earfcn), v(id.tac), v(id.bandwidth),
                        if (Build.VERSION.SDK_INT >= 30) id.bands else null)
                }
                is CellInfoNr -> (ci.cellIdentity as CellIdentityNr).let { id ->
                    CellIdentity(MetaFormat.RAT_NR, reg, c, ts, mcc(id.mccString), mcc(id.mncString), id.mncString?.length ?: 0,
                        vl(id.nci), v(id.pci), v(id.nrarfcn), v(id.tac), null,
                        if (Build.VERSION.SDK_INT >= 30) id.bands else null)
                }
                is CellInfoWcdma -> ci.cellIdentity.let { id ->
                    CellIdentity(MetaFormat.RAT_WCDMA, reg, c, ts, mcc(id.mccString), mcc(id.mncString), id.mncString?.length ?: 0,
                        v(id.cid)?.toLong(), v(id.psc), v(id.uarfcn), v(id.lac), null, null)
                }
                is CellInfoGsm -> ci.cellIdentity.let { id ->
                    CellIdentity(MetaFormat.RAT_GSM, reg, c, ts, mcc(id.mccString), mcc(id.mncString), id.mncString?.length ?: 0,
                        v(id.cid)?.toLong(), v(id.bsic), v(id.arfcn), v(id.lac), null, null)
                }
                is CellInfoTdscdma -> ci.cellIdentity.let { id ->
                    CellIdentity(MetaFormat.RAT_TDSCDMA, reg, c, ts, mcc(id.mccString), mcc(id.mncString), id.mncString?.length ?: 0,
                        v(id.cid)?.toLong(), v(id.cpid), v(id.uarfcn), v(id.lac), null, null)
                }
                is CellInfoCdma -> ci.cellIdentity.let { id ->
                    CellIdentity(MetaFormat.RAT_CDMA, reg, c, ts, null, null, 0, v(id.basestationId)?.toLong(),
                        null, null, v(id.networkId), null, null)
                }
                else -> null
            }
        }

        fun measurement(ci: CellInfo): CellMeasurement? {
            val ts = tsOf(ci)
            return when (ci) {
                is CellInfoLte -> strength(ci.cellSignalStrength, ci.isRegistered, conn(ci), ts, v(ci.cellIdentity.pci), v(ci.cellIdentity.earfcn))
                is CellInfoNr -> (ci.cellIdentity as CellIdentityNr).let {
                    strength(ci.cellSignalStrength, ci.isRegistered, conn(ci), ts, v(it.pci), v(it.nrarfcn))
                }
                is CellInfoWcdma -> strength(ci.cellSignalStrength, ci.isRegistered, conn(ci), ts, v(ci.cellIdentity.psc), v(ci.cellIdentity.uarfcn))
                is CellInfoGsm -> strength(ci.cellSignalStrength, ci.isRegistered, conn(ci), ts, v(ci.cellIdentity.bsic), v(ci.cellIdentity.arfcn))
                is CellInfoTdscdma -> strength(ci.cellSignalStrength, ci.isRegistered, conn(ci), ts, v(ci.cellIdentity.cpid), v(ci.cellIdentity.uarfcn))
                is CellInfoCdma -> strength(ci.cellSignalStrength, ci.isRegistered, conn(ci), ts, null, null)
                else -> null
            }
        }

        /** Measurements by RAT in the m0..m7 order of docs/META_FORMAT.md; unavailable values are null. */
        fun strength(s: CellSignalStrength, reg: Boolean, conn: Int, ts: Long?, pci: Int?, arfcn: Int?): CellMeasurement? {
            val level = v(s.level)
            return when (s) {
                is CellSignalStrengthLte -> CellMeasurement(MetaFormat.RAT_LTE, reg, conn, ts, pci, arfcn, level,
                    arrayOf(v(s.rsrp), v(s.rsrq), v(s.rssnr), v(s.rssi), v(s.cqi), v(s.timingAdvance), null, null))
                is CellSignalStrengthNr -> CellMeasurement(MetaFormat.RAT_NR, reg, conn, ts, pci, arfcn, level,
                    arrayOf(v(s.ssRsrp), v(s.ssRsrq), v(s.ssSinr), v(s.csiRsrp), v(s.csiRsrq), v(s.csiSinr), null, null))
                is CellSignalStrengthWcdma -> CellMeasurement(MetaFormat.RAT_WCDMA, reg, conn, ts, pci, arfcn, level,
                    arrayOf(v(s.dbm), if (Build.VERSION.SDK_INT >= 30) v(s.ecNo) else null, null, null, null, null, null, null))
                is CellSignalStrengthGsm -> CellMeasurement(MetaFormat.RAT_GSM, reg, conn, ts, pci, arfcn, level,
                    arrayOf(if (Build.VERSION.SDK_INT >= 30) v(s.rssi) else v(s.dbm), v(s.bitErrorRate), v(s.timingAdvance),
                        null, null, null, null, null))
                is CellSignalStrengthTdscdma -> CellMeasurement(MetaFormat.RAT_TDSCDMA, reg, conn, ts, pci, arfcn, level,
                    arrayOf(v(s.rscp), null, null, null, null, null, null, null))
                is CellSignalStrengthCdma -> CellMeasurement(MetaFormat.RAT_CDMA, reg, conn, ts, pci, arfcn, level,
                    arrayOf(v(s.cdmaDbm), v(s.cdmaEcio), v(s.evdoDbm), v(s.evdoSnr), null, null, null, null))
                else -> null
            }
        }
    }
}

/** NETWORK_STATE on default-network changes; WIFI_STATE on link change and periodic refresh. */
class NetworkCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler) {
    private val cm = ctx.getSystemService(ConnectivityManager::class.java)
    private val wm = ctx.applicationContext.getSystemService(WifiManager::class.java)
    private var lastNet = ""
    private var lastWifi = ""
    private var lastWifiNs = 0L

    // The logger excludes itself from its own VPN, so its default network is the real one.
    private val callback = if (Build.VERSION.SDK_INT >= 31)
        object : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
            override fun onCapabilitiesChanged(n: Network, c: NetworkCapabilities) = caps(c)
            override fun onLost(n: Network) = lost()
        }
    else object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(n: Network, c: NetworkCapabilities) = caps(c)
        override fun onLost(n: Network) = lost()
    }

    private val poll = object : Runnable {
        override fun run() {
            @Suppress("DEPRECATION")
            runCatching { wm?.connectionInfo }.getOrNull()?.let { wifi(it) }
            handler.postDelayed(this, cfg.wifiRefreshMs)
        }
    }

    private fun caps(c: NetworkCapabilities) {
        var transports = 0
        for (t in 0..10) if (c.hasTransport(t)) transports = transports or (1 shl t)
        val validated = c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val metered = !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        val key = "$transports/$validated/$metered/${c.linkDownstreamBandwidthKbps}/${c.linkUpstreamBandwidthKbps}/${c.signalStrength}"
        if (key != lastNet) {
            lastNet = key
            MetaRecords.networkState(w, now(), transports, validated, metered, false,
                c.linkDownstreamBandwidthKbps, c.linkUpstreamBandwidthKbps, c.signalStrength)
        }
        (c.transportInfo as? WifiInfo)?.let { wifi(it) }
    }

    private fun lost() {
        lastNet = ""
        MetaRecords.networkState(w, now(), 0, false, false, true, 0, 0, Int.MIN_VALUE)
    }

    @SuppressLint("MissingPermission")
    private fun wifi(i: WifiInfo) {
        val connected = i.networkId != -1 || i.rssi > -127
        @Suppress("DEPRECATION")
        val bssid = i.bssid?.takeIf { it != "02:00:00:00:00:00" && has(Manifest.permission.ACCESS_FINE_LOCATION) }
            ?.split(':')?.mapNotNull { it.toIntOrNull(16)?.toByte() }?.toByteArray()
        val std = if (Build.VERSION.SDK_INT >= 30) i.wifiStandard else null
        val key = if (connected) "${i.rssi}/${i.frequency}/${i.linkSpeed}/${i.txLinkSpeedMbps}/${i.rxLinkSpeedMbps}/$std/${bssid?.contentToString()}" else "off"
        val t = now()
        val refresh = key == lastWifi
        if (refresh && t - lastWifiNs < 60_000_000_000L) return
        lastWifi = key
        lastWifiNs = t
        if (connected) MetaRecords.wifiState(w, t, refresh, true, i.rssi, i.frequency, i.linkSpeed,
            v(i.txLinkSpeedMbps), v(i.rxLinkSpeedMbps), std, bssid)
        else MetaRecords.wifiState(w, t, refresh, false, null, null, null, null, null, null, null)
    }

    private fun v(x: Int) = if (x < 0) null else x

    override fun start() {
        runCatching { cm.registerDefaultNetworkCallback(callback, handler) }
            .onSuccess { status(MetaFormat.SRC_NETWORK, MetaFormat.ST_ACTIVE) }
            .onFailure { status(MetaFormat.SRC_NETWORK, MetaFormat.ST_ERROR, it.javaClass.simpleName) }
        if (wm != null) {
            status(MetaFormat.SRC_WIFI, MetaFormat.ST_ACTIVE, "refresh ${cfg.wifiRefreshMs} ms")
            handler.post(poll)
        } else {
            status(MetaFormat.SRC_WIFI, MetaFormat.ST_UNAVAILABLE)
        }
    }

    override fun stop() {
        handler.removeCallbacks(poll)
        runCatching { cm.unregisterNetworkCallback(callback) }
    }
}
