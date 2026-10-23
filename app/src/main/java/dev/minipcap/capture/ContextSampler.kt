package dev.minipcap.capture

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
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
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
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
import android.telephony.SubscriptionManager
import android.telephony.TelephonyCallback
import android.telephony.TelephonyDisplayInfo
import android.telephony.TelephonyManager
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.sqrt

/**
 * Writes context records into the capture's ctx0 interface (docs/DECISIONS.md ADR-013).
 * Thread-safe; ~1 Hz STATE records plus one INFO record per first-seen app.
 * Packets reference the STATE record in effect as `c=<seq>`.
 */
class ContextWriter(private val handle: Long) {
    private val seq = AtomicInteger(0)
    private val ok = AtomicLong()
    private val failed = AtomicLong()
    val written get() = ok.get()
    val rejected get() = failed.get()

    fun nextSeq() = seq.incrementAndGet()

    private var closed = false

    @Synchronized
    fun write(kind: Int, seq: Int, info: String, json: JSONObject) {
        if (closed) {
            failed.incrementAndGet()
            return
        }
        val rc = NativeCore.nativeContext(handle, kind, seq, info.toByteArray(Charsets.UTF_8),
            json.toString().toByteArray(Charsets.UTF_8))
        if (rc == 0) ok.incrementAndGet() else failed.incrementAndGet()
    }

    /** After this returns no call reaches the native handle (it may be destroyed next). */
    @Synchronized
    fun close() {
        closed = true
    }

    /** App identity, written once per UID when the package lookup finishes. */
    fun app(uid: Int, info: UidInfo) {
        val s = nextSeq()
        val o = JSONObject().put("type", "app").put("seq", s).put("uid", uid)
            .put("packages", JSONArray(info.packages)).put("app_names", JSONArray(info.appNames))
            .put("class", info.appClass).put("class_source", info.classSource)
        if (info.note != null) o.put("note", info.note)
        write(NativeCore.CTX_INFO, s, "app $uid ${info.packages.firstOrNull() ?: "?"}", o)
    }
}

/**
 * Samples position, motion and radio state on its own thread and emits one STATE
 * context record per interval. Every section carries its own status and age: a
 * measurement is the latest the platform reported, not a per-packet measurement.
 * Missing permissions or hardware yield a status instead of values; never fatal.
 */
class ContextSampler(
    private val ctx: Context,
    private val out: ContextWriter,
    private val intervalMs: Long = 1000,
) {
    private val thread = HandlerThread("mpc-context").apply { start() }
    private val handler = Handler(thread.looper)
    private val exec = Executor { handler.post(it) }
    private val startElapsed = SystemClock.elapsedRealtime()
    @Volatile private var running = false

    private fun has(p: String) = ctx.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED
    private val fine get() = has(Manifest.permission.ACCESS_FINE_LOCATION)

    // ---- location
    private val lm = ctx.getSystemService(LocationManager::class.java)
    private var location: Location? = null
    private var locationProvider: String? = null
    private var satsUsed = -1
    private var satsVisible = -1
    private val locListener = LocationListener { location = it }
    private val gnssCallback = object : GnssStatus.Callback() {
        override fun onSatelliteStatusChanged(status: GnssStatus) {
            satsVisible = status.satelliteCount
            satsUsed = (0 until status.satelliteCount).count { status.usedInFix(it) }
        }
    }

    // ---- motion (aggregated per interval)
    private val sm = ctx.getSystemService(SensorManager::class.java)
    private var accN = 0; private var accSum = 0.0; private var accMax = 0.0
    private var gyrN = 0; private var gyrSum = 0.0; private var gyrMax = 0.0
    private var accIsLinear = true
    private var rotation: FloatArray? = null
    private var pressure: Float? = null
    private val sensorListener = object : SensorEventListener {
        override fun onSensorChanged(e: SensorEvent) {
            val v = e.values
            when (e.sensor.type) {
                Sensor.TYPE_LINEAR_ACCELERATION, Sensor.TYPE_ACCELEROMETER -> {
                    val m = sqrt((v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).toDouble()) -
                        if (e.sensor.type == Sensor.TYPE_ACCELEROMETER) SensorManager.GRAVITY_EARTH else 0f
                    accN++; accSum += m; if (m > accMax) accMax = m
                }
                Sensor.TYPE_GYROSCOPE -> {
                    val m = sqrt((v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).toDouble())
                    gyrN++; gyrSum += m; if (m > gyrMax) gyrMax = m
                }
                Sensor.TYPE_ROTATION_VECTOR -> rotation = v.copyOf()
                Sensor.TYPE_PRESSURE -> pressure = v[0]
            }
        }
        override fun onAccuracyChanged(s: Sensor?, a: Int) {}
    }

    // ---- radio
    private val tmDefault = ctx.getSystemService(TelephonyManager::class.java)
    private val tm: TelephonyManager? = tmDefault?.let {
        val sub = SubscriptionManager.getDefaultDataSubscriptionId()
        if (sub != SubscriptionManager.INVALID_SUBSCRIPTION_ID) it.createForSubscriptionId(sub) else it
    }
    private var cells: List<CellInfo>? = null
    private var cellsElapsedMs = 0L
    private var displayOverride: Int? = null
    private var telephonyCallback: Any? = null
    private val cm = ctx.getSystemService(ConnectivityManager::class.java)
    private val wm = ctx.applicationContext.getSystemService(WifiManager::class.java)

    @SuppressLint("MissingPermission") // every registration is guarded by a permission check
    fun start() {
        running = true
        handler.post {
            if (fine || has(Manifest.permission.ACCESS_COARSE_LOCATION)) {
                runCatching {
                    val provider = when {
                        Build.VERSION.SDK_INT >= 31 && lm.hasProvider(LocationManager.FUSED_PROVIDER) -> LocationManager.FUSED_PROVIDER
                        lm.allProviders.contains(LocationManager.GPS_PROVIDER) && fine -> LocationManager.GPS_PROVIDER
                        else -> LocationManager.NETWORK_PROVIDER
                    }
                    locationProvider = provider
                    if (Build.VERSION.SDK_INT >= 31) {
                        lm.requestLocationUpdates(provider, LocationRequest.Builder(intervalMs)
                            .setQuality(LocationRequest.QUALITY_HIGH_ACCURACY).build(), exec, locListener)
                    } else {
                        lm.requestLocationUpdates(provider, intervalMs, 0f, locListener, thread.looper)
                    }
                    if (fine) {
                        if (Build.VERSION.SDK_INT >= 30) lm.registerGnssStatusCallback(exec, gnssCallback)
                        else @Suppress("DEPRECATION") lm.registerGnssStatusCallback(gnssCallback, handler)
                    }
                }.onFailure { Log.w(TAG, "location unavailable: ${it.javaClass.simpleName}") }
            }
            val linear = sm.getDefaultSensor(Sensor.TYPE_LINEAR_ACCELERATION)
            accIsLinear = linear != null
            listOfNotNull(linear ?: sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER),
                sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE), sm.getDefaultSensor(Sensor.TYPE_ROTATION_VECTOR),
                sm.getDefaultSensor(Sensor.TYPE_PRESSURE))
                .forEach { sm.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_GAME, handler) }
            if (Build.VERSION.SDK_INT >= 31 && tm != null && has(Manifest.permission.READ_PHONE_STATE)) {
                runCatching {
                    val cb = object : TelephonyCallback(), TelephonyCallback.DisplayInfoListener {
                        override fun onDisplayInfoChanged(d: TelephonyDisplayInfo) { displayOverride = d.overrideNetworkType }
                    }
                    tm?.registerTelephonyCallback(exec, cb)
                    telephonyCallback = cb
                }
            }
            handler.post(tick)
        }
    }

    fun stop() {
        running = false
        handler.post {
            handler.removeCallbacks(tick)
            runCatching { lm.removeUpdates(locListener) }
            runCatching { lm.unregisterGnssStatusCallback(gnssCallback) }
            sm.unregisterListener(sensorListener)
            if (Build.VERSION.SDK_INT >= 31) (telephonyCallback as? TelephonyCallback)?.let { cb ->
                runCatching { tm?.unregisterTelephonyCallback(cb) }
            }
            thread.quitSafely()
        }
        thread.join(2000)
    }

    @SuppressLint("MissingPermission")
    private val tick = object : Runnable {
        override fun run() {
            if (!running) return
            val t0 = SystemClock.uptimeMillis() // Handler time base
            if (fine && tm != null) runCatching {
                tm.requestCellInfoUpdate(exec, object : TelephonyManager.CellInfoCallback() {
                    override fun onCellInfo(list: MutableList<CellInfo>) {
                        cells = list
                        cellsElapsedMs = SystemClock.elapsedRealtime()
                    }
                })
            }
            runCatching { emit() }.onFailure { Log.w(TAG, "context sample failed: ${it.javaClass.simpleName}") }
            handler.postAtTime(this, t0 + intervalMs)
        }
    }

    private fun emit() {
        val s = out.nextSeq()
        val now = SystemClock.elapsedRealtime()
        val o = JSONObject().put("type", "context").put("seq", s)
            .put("time_utc", Sidecar.iso(System.currentTimeMillis()))
            .put("elapsed_ms", now - startElapsed)
        val loc = locationJson(now)
        val motion = motionJson()
        val net = networkJson()
        val cell = cellularJson(now)
        val wifi = wifiJson()
        o.put("location", loc).put("motion", motion).put("network", net).put("cellular", cell).put("wifi", wifi)
        out.write(NativeCore.CTX_STATE, s, infoText(s, loc, cell, net), o)
    }

    private fun locationJson(now: Long): JSONObject {
        val o = JSONObject()
        if (!fine && !has(Manifest.permission.ACCESS_COARSE_LOCATION)) return o.put("status", "permission_denied")
        if (!lm.isLocationEnabled) return o.put("status", "disabled")
        val l = location ?: return o.put("status", "no_fix").put("provider", locationProvider)
        o.put("status", "ok").put("provider", l.provider ?: locationProvider)
            .put("fix_age_ms", now - l.elapsedRealtimeNanos / 1_000_000)
            .put("lat", l.latitude).put("lon", l.longitude)
        if (l.hasAltitude()) o.put("alt_m", round(l.altitude, 1))
        if (Build.VERSION.SDK_INT >= 34 && l.hasMslAltitude()) o.put("msl_alt_m", round(l.mslAltitudeMeters, 1))
        if (l.hasAccuracy()) o.put("h_acc_m", round(l.accuracy.toDouble(), 1))
        if (l.hasVerticalAccuracy()) o.put("v_acc_m", round(l.verticalAccuracyMeters.toDouble(), 1))
        if (l.hasSpeed()) o.put("speed_mps", round(l.speed.toDouble(), 2))
        if (l.hasSpeedAccuracy()) o.put("speed_acc_mps", round(l.speedAccuracyMetersPerSecond.toDouble(), 2))
        if (l.hasBearing()) o.put("bearing_deg", round(l.bearing.toDouble(), 1))
        if (l.hasBearingAccuracy()) o.put("bearing_acc_deg", round(l.bearingAccuracyDegrees.toDouble(), 1))
        if (satsUsed >= 0) o.put("satellites_used", satsUsed).put("satellites_visible", satsVisible)
        return o
    }

    private fun motionJson(): JSONObject {
        val o = JSONObject().put("window_ms", intervalMs)
        if (accN == 0 && gyrN == 0 && rotation == null && pressure == null) return o.put("status", "no_samples")
        o.put("status", "ok").put("acc_samples", accN).put("acc_source", if (accIsLinear) "linear_acceleration" else "accelerometer_minus_g")
        if (accN > 0) o.put("lin_acc_mean_mps2", round(accSum / accN, 3)).put("lin_acc_max_mps2", round(accMax, 3))
        if (gyrN > 0) o.put("gyro_mean_rads", round(gyrSum / gyrN, 3)).put("gyro_max_rads", round(gyrMax, 3))
        rotation?.let { rv ->
            val r = FloatArray(9)
            val ori = FloatArray(3)
            SensorManager.getRotationMatrixFromVector(r, rv)
            SensorManager.getOrientation(r, ori)
            o.put("azimuth_deg", round(Math.toDegrees(ori[0].toDouble()), 1))
                .put("pitch_deg", round(Math.toDegrees(ori[1].toDouble()), 1))
                .put("roll_deg", round(Math.toDegrees(ori[2].toDouble()), 1))
        }
        pressure?.let { o.put("pressure_hpa", round(it.toDouble(), 2)) }
        accN = 0; accSum = 0.0; accMax = 0.0; gyrN = 0; gyrSum = 0.0; gyrMax = 0.0
        return o
    }

    private fun networkJson(): JSONObject {
        val o = JSONObject()
        // The logger excludes itself from its VPN, so its default network is the real one.
        val n = cm.activeNetwork ?: return o.put("default_transport", "none")
        val caps = cm.getNetworkCapabilities(n) ?: return o.put("default_transport", "unknown")
        val transport = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
        o.put("default_transport", transport)
            .put("validated", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            .put("metered", !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
            .put("est_down_kbps", caps.linkDownstreamBandwidthKbps)
            .put("est_up_kbps", caps.linkUpstreamBandwidthKbps)
        if (caps.signalStrength != NetworkCapabilities.SIGNAL_STRENGTH_UNSPECIFIED) o.put("signal_strength", caps.signalStrength)
        return o
    }

    @SuppressLint("MissingPermission")
    private fun cellularJson(now: Long): JSONObject {
        val o = JSONObject()
        val t = tm ?: return o.put("status", "no_telephony")
        o.put("operator", t.networkOperator.ifEmpty { null } ?: JSONObject.NULL)
            .put("operator_name", t.networkOperatorName.ifEmpty { null } ?: JSONObject.NULL)
            .put("roaming", t.isNetworkRoaming)
        if (has(Manifest.permission.READ_PHONE_STATE)) {
            runCatching { o.put("data_rat", ratName(t.dataNetworkType)) }
        } else {
            o.put("data_rat_status", "permission_denied")
        }
        displayOverride?.let { o.put("override", overrideName(it)) }
        // Serving-cell signal: refreshed by the modem more often than full cell info.
        runCatching {
            t.signalStrength?.cellSignalStrengths?.let { list ->
                o.put("serving_signal", JSONArray(list.map { signalJson(it, JSONObject()) }))
            }
        }
        if (!fine) return o.put("status", "permission_denied")
        val list = cells ?: runCatching { t.allCellInfo }.getOrNull()?.also {
            cells = it
            cellsElapsedMs = now
        }
        if (list == null) return o.put("status", "no_cell_info")
        o.put("status", "ok").put("info_age_ms", now - cellsElapsedMs)
        val serving = JSONArray()
        val neighbors = JSONArray()
        for (ci in list) {
            val c = cellJson(ci, now) ?: continue
            if (ci.isRegistered) serving.put(c) else neighbors.put(c)
        }
        return o.put("serving", serving).put("neighbors", neighbors)
    }

    private fun cellJson(ci: CellInfo, now: Long): JSONObject? {
        val o = JSONObject().put("registered", ci.isRegistered)
        o.put("conn", when (ci.cellConnectionStatus) {
            CellInfo.CONNECTION_PRIMARY_SERVING -> "primary"
            CellInfo.CONNECTION_SECONDARY_SERVING -> "secondary"
            CellInfo.CONNECTION_NONE -> "none"
            else -> "unknown"
        })
        val tsMs = if (Build.VERSION.SDK_INT >= 30) ci.timestampMillis else @Suppress("DEPRECATION") ci.timeStamp / 1_000_000
        o.put("age_ms", now - tsMs)
        when (ci) {
            is CellInfoLte -> {
                val id = ci.cellIdentity
                o.put("rat", "LTE").opt("mcc", id.mccString).opt("mnc", id.mncString)
                    .num("ci", id.ci).num("pci", id.pci).num("tac", id.tac).num("arfcn", id.earfcn)
                    .num("bw_khz", id.bandwidth)
                if (Build.VERSION.SDK_INT >= 30) o.put("bands", JSONArray(id.bands.toList()))
                signalJson(ci.cellSignalStrength, o)
            }
            is CellInfoNr -> {
                val id = ci.cellIdentity as CellIdentityNr
                o.put("rat", "NR").opt("mcc", id.mccString).opt("mnc", id.mncString)
                    .numL("nci", id.nci).num("pci", id.pci).num("tac", id.tac).num("arfcn", id.nrarfcn)
                if (Build.VERSION.SDK_INT >= 30) o.put("bands", JSONArray(id.bands.toList()))
                signalJson(ci.cellSignalStrength, o)
            }
            is CellInfoWcdma -> {
                val id = ci.cellIdentity
                o.put("rat", "WCDMA").opt("mcc", id.mccString).opt("mnc", id.mncString)
                    .num("cid", id.cid).num("lac", id.lac).num("psc", id.psc).num("arfcn", id.uarfcn)
                signalJson(ci.cellSignalStrength, o)
            }
            is CellInfoGsm -> {
                val id = ci.cellIdentity
                o.put("rat", "GSM").opt("mcc", id.mccString).opt("mnc", id.mncString)
                    .num("cid", id.cid).num("lac", id.lac).num("arfcn", id.arfcn).num("bsic", id.bsic)
                signalJson(ci.cellSignalStrength, o)
            }
            is CellInfoTdscdma -> {
                val id = ci.cellIdentity
                o.put("rat", "TDSCDMA").opt("mcc", id.mccString).opt("mnc", id.mncString)
                    .num("cid", id.cid).num("lac", id.lac).num("cpid", id.cpid).num("arfcn", id.uarfcn)
                signalJson(ci.cellSignalStrength, o)
            }
            is CellInfoCdma -> {
                val id = ci.cellIdentity
                o.put("rat", "CDMA").num("bsid", id.basestationId).num("nid", id.networkId).num("sid", id.systemId)
                signalJson(ci.cellSignalStrength, o)
            }
            else -> return null
        }
        return o
    }

    companion object {
        private const val TAG = "ContextSampler"
        private const val NA = CellInfo.UNAVAILABLE

        private fun JSONObject.num(k: String, v: Int): JSONObject = if (v != NA && v != Int.MIN_VALUE) put(k, v) else this
        private fun JSONObject.numL(k: String, v: Long): JSONObject = if (v != CellInfo.UNAVAILABLE_LONG) put(k, v) else this
        private fun JSONObject.opt(k: String, v: String?): JSONObject = if (v != null) put(k, v) else this
        private fun round(v: Double, digits: Int): Double {
            var m = 1.0
            repeat(digits) { m *= 10 }
            return Math.round(v * m) / m
        }

        /** Signal fields by technology; unavailable values are omitted, never guessed. */
        fun signalJson(s: CellSignalStrength, o: JSONObject): JSONObject {
            o.num("level", s.level)
            when (s) {
                is CellSignalStrengthLte -> {
                    o.put("sig_rat", "LTE").num("rsrp", s.rsrp).num("rsrq", s.rsrq).num("rssnr", s.rssnr)
                        .num("rssi", s.rssi).num("cqi", s.cqi).num("ta", s.timingAdvance)
                }
                is CellSignalStrengthNr -> {
                    o.put("sig_rat", "NR").num("ss_rsrp", s.ssRsrp).num("ss_rsrq", s.ssRsrq).num("ss_sinr", s.ssSinr)
                        .num("csi_rsrp", s.csiRsrp).num("csi_rsrq", s.csiRsrq).num("csi_sinr", s.csiSinr)
                }
                is CellSignalStrengthWcdma -> {
                    o.put("sig_rat", "WCDMA").num("rscp", s.dbm)
                    if (Build.VERSION.SDK_INT >= 30) o.num("ecno", s.ecNo)
                }
                is CellSignalStrengthGsm -> {
                    o.put("sig_rat", "GSM").num("ber", s.bitErrorRate).num("ta", s.timingAdvance)
                    if (Build.VERSION.SDK_INT >= 30) o.num("rssi", s.rssi) else o.num("rssi", s.dbm)
                }
                is CellSignalStrengthTdscdma -> o.put("sig_rat", "TDSCDMA").num("rscp", s.rscp)
                is CellSignalStrengthCdma -> o.put("sig_rat", "CDMA").num("dbm", s.dbm)
            }
            return o
        }

        fun ratName(t: Int): String = when (t) {
            TelephonyManager.NETWORK_TYPE_NR -> "NR"
            TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
            TelephonyManager.NETWORK_TYPE_IWLAN -> "IWLAN"
            TelephonyManager.NETWORK_TYPE_HSPAP, TelephonyManager.NETWORK_TYPE_HSPA,
            TelephonyManager.NETWORK_TYPE_HSDPA, TelephonyManager.NETWORK_TYPE_HSUPA -> "HSPA"
            TelephonyManager.NETWORK_TYPE_UMTS -> "UMTS"
            TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "TD_SCDMA"
            TelephonyManager.NETWORK_TYPE_EDGE -> "EDGE"
            TelephonyManager.NETWORK_TYPE_GPRS -> "GPRS"
            TelephonyManager.NETWORK_TYPE_GSM -> "GSM"
            TelephonyManager.NETWORK_TYPE_UNKNOWN -> "UNKNOWN"
            else -> "TYPE_$t"
        }

        fun overrideName(t: Int): String = when (t) {
            TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NONE -> "NONE"
            TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_LTE_CA -> "LTE_CA"
            TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_LTE_ADVANCED_PRO -> "LTE_ADVANCED_PRO"
            TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NR_NSA -> "NR_NSA"
            TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NR_ADVANCED -> "NR_ADVANCED"
            else -> "TYPE_$t"
        }

        /** Short Wireshark Info-column summary, e.g. "ctx 42 cellular LTE pci 123 -95 dBm | fix ±4 m". */
        fun infoText(seq: Int, loc: JSONObject, cell: JSONObject, net: JSONObject): String {
            val sb = StringBuilder("ctx ").append(seq).append(' ').append(net.optString("default_transport", "?"))
            val sv = cell.optJSONArray("serving")?.optJSONObject(0)
            if (sv != null) {
                sb.append(' ').append(sv.optString("rat"))
                if (sv.has("pci")) sb.append(" pci ").append(sv.optInt("pci"))
                listOf("rsrp", "ss_rsrp", "rscp", "rssi").firstOrNull { sv.has(it) }?.let { sb.append(' ').append(sv.optInt(it)).append(" dBm") }
            } else if (cell.has("data_rat")) {
                sb.append(' ').append(cell.optString("data_rat"))
            }
            if (loc.optString("status") == "ok") {
                sb.append(" | fix")
                if (loc.has("h_acc_m")) sb.append(String.format(Locale.US, " ±%.0f m", loc.optDouble("h_acc_m")))
                if (loc.has("speed_mps")) sb.append(String.format(Locale.US, " %.1f m/s", loc.optDouble("speed_mps")))
            } else {
                sb.append(" | location ").append(loc.optString("status"))
            }
            return sb.toString()
        }
    }

    @SuppressLint("MissingPermission")
    private fun wifiJson(): JSONObject {
        val o = JSONObject()
        @Suppress("DEPRECATION")
        val wi = runCatching { wm?.connectionInfo }.getOrNull()
        if (wi == null || wi.networkId == -1 && wi.rssi <= -127) return o.put("status", "not_connected")
        o.put("status", "ok").put("rssi_dbm", wi.rssi).put("freq_mhz", wi.frequency).put("link_mbps", wi.linkSpeed)
            .put("tx_mbps", wi.txLinkSpeedMbps).put("rx_mbps", wi.rxLinkSpeedMbps)
        if (Build.VERSION.SDK_INT >= 30) o.put("standard", wi.wifiStandard)
        @Suppress("DEPRECATION")
        val bssid = wi.bssid
        if (fine && bssid != null && bssid != "02:00:00:00:00:00") o.put("bssid", bssid)
        return o
    }
}
