package dev.minipcap.meta.collect

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.location.GnssStatus
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.location.LocationRequest
import android.os.Build
import android.os.Handler
import dev.minipcap.meta.MetaFormat
import dev.minipcap.meta.MetaRecords
import dev.minipcap.meta.MetaWriter

/** LOCATION for every fix the platform delivers (time/distance thresholds); GNSS_STATUS at most 1 Hz. */
class LocationCollector(ctx: Context, w: MetaWriter, handler: Handler, private val cfg: MeasurementConfig) :
    Collector(ctx, w, handler, MetaFormat.SRC_LOCATION) {
    private val lm = ctx.getSystemService(LocationManager::class.java)
    private var lastGnssNs = 0L
    private var satsUsed = -1
    private var satsUsedNs = 0L

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
            val t = now()
            satsUsed = used
            satsUsedNs = t
            if (t - lastGnssNs < 1_000_000_000L) return // at most 1 Hz
            lastGnssNs = t
            MetaRecords.gnssStatus(w, t, s.satelliteCount, used, if (used > 0) cn0 / used else Float.NaN, constellations)
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
        // Satellites used, if a GNSS report is recent (any provider: fused fixes are GNSS-based outdoors).
        val sats = if (now() - satsUsedNs < 2_000_000_000L) satsUsed else -1
        MetaRecords.location(w, l.elapsedRealtimeNanos, now(), l.latitude, l.longitude,
            if (l.hasAltitude()) l.altitude else Double.NaN,
            if (Build.VERSION.SDK_INT >= 34 && l.hasMslAltitude()) l.mslAltitudeMeters else Double.NaN,
            if (l.hasAccuracy()) l.accuracy else Float.NaN,
            if (l.hasVerticalAccuracy()) l.verticalAccuracyMeters else Float.NaN,
            if (l.hasSpeed()) l.speed else Float.NaN,
            if (l.hasSpeedAccuracy()) l.speedAccuracyMetersPerSecond else Float.NaN,
            if (l.hasBearing()) l.bearing else Float.NaN,
            if (l.hasBearingAccuracy()) l.bearingAccuracyDegrees else Float.NaN,
            provider, sats)
    }

    @SuppressLint("MissingPermission") // guarded below
    override fun start() {
        val fine = has(Manifest.permission.ACCESS_FINE_LOCATION)
        if (!fine && !has(Manifest.permission.ACCESS_COARSE_LOCATION)) {
            status(MetaFormat.SRC_LOCATION, MetaFormat.ST_PERMISSION_DENIED)
            return
        }
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
            // Registered either way; fixes start once the user enables location.
            if (lm.isLocationEnabled) status(MetaFormat.SRC_LOCATION, MetaFormat.ST_ACTIVE, provider)
            else status(MetaFormat.SRC_LOCATION, MetaFormat.ST_DISABLED_IN_SYSTEM, "location off; $provider registered")
        } catch (e: SecurityException) {
            status(MetaFormat.SRC_LOCATION, MetaFormat.ST_PERMISSION_DENIED, e.javaClass.simpleName)
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
