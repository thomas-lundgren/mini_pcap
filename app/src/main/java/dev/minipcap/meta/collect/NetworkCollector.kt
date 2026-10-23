package dev.minipcap.meta.collect

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter

/**
 * NETWORK_STATE on default-network changes; WIFI_STATE on Wi-Fi link changes, polled only
 * while Wi-Fi is the default network, with an unchanged-state refresh once a minute.
 * The logger excludes itself from its own VPN, so its default network is the real one.
 */
class NetworkCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler, MetaFormat.SRC_NETWORK) {
    private val cm = ctx.getSystemService(ConnectivityManager::class.java)
    private val wm = ctx.applicationContext.getSystemService(WifiManager::class.java)
    private var lastNet = ""
    private var lastWifi = ""
    private var lastWifiNs = 0L
    private var onWifi = false

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
            if (!onWifi) return // restarted by caps() when Wi-Fi becomes the default network
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
        val wasWifi = onWifi
        onWifi = c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        (c.transportInfo as? WifiInfo)?.let { wifi(it) }
        if (onWifi && !wasWifi) {
            handler.removeCallbacks(poll)
            handler.postDelayed(poll, cfg.wifiRefreshMs)
        } else if (!onWifi && wasWifi) {
            wifiDisconnected()
        }
    }

    private fun lost() {
        lastNet = ""
        if (onWifi) wifiDisconnected()
        onWifi = false
        MetaRecords.networkState(w, now(), 0, false, false, true, 0, 0, Int.MIN_VALUE)
    }

    private fun wifiDisconnected() {
        handler.removeCallbacks(poll)
        lastWifi = "off"
        lastWifiNs = now()
        MetaRecords.wifiState(w, lastWifiNs, false, false, null, null, null, null, null, null, null)
    }

    @SuppressLint("MissingPermission")
    private fun wifi(i: WifiInfo) {
        if (!onWifi) return
        @Suppress("DEPRECATION")
        val bssid = i.bssid?.takeIf { it != "02:00:00:00:00:00" && has(Manifest.permission.ACCESS_FINE_LOCATION) }
            ?.split(':')?.mapNotNull { it.toIntOrNull(16)?.toByte() }?.takeIf { it.size == 6 }?.toByteArray()
        // Android reports "unknown" as -1 / -127 / WIFI_STANDARD_UNKNOWN: never record those as values.
        val rssi = i.rssi.takeIf { it > -127 && it < 0 }
        val std = if (Build.VERSION.SDK_INT >= 30) i.wifiStandard.takeIf { it != ScanResult.WIFI_STANDARD_UNKNOWN } else null
        val freq = pos(i.frequency)
        val link = pos(i.linkSpeed)
        val tx = pos(i.txLinkSpeedMbps)
        val rx = pos(i.rxLinkSpeedMbps)
        val key = "$rssi/$freq/$link/$tx/$rx/$std/${bssid?.contentToString()}"
        val t = now()
        val refresh = key == lastWifi
        if (refresh && t - lastWifiNs < 60_000_000_000L) return
        lastWifi = key
        lastWifiNs = t
        MetaRecords.wifiState(w, t, refresh, true, rssi, freq, link, tx, rx, std, bssid)
    }

    private fun pos(x: Int) = x.takeIf { it > 0 }

    override fun start() {
        runCatching { cm.registerDefaultNetworkCallback(callback, handler) }
            .onSuccess { status(MetaFormat.SRC_NETWORK, MetaFormat.ST_ACTIVE) }
            .onFailure { status(MetaFormat.SRC_NETWORK, MetaFormat.ST_ERROR, it.javaClass.simpleName) }
        status(MetaFormat.SRC_WIFI, if (wm != null) MetaFormat.ST_ACTIVE else MetaFormat.ST_UNAVAILABLE,
            "polled every ${cfg.wifiRefreshMs} ms while on Wi-Fi")
    }

    override fun stop() {
        handler.removeCallbacks(poll)
        runCatching { cm.unregisterNetworkCallback(callback) }
    }
}
