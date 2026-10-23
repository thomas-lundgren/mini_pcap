package dev.minipcap.meta

import dev.minipcap.meta.MetaFormat.putCounters
import dev.minipcap.meta.MetaFormat.putStr
import dev.minipcap.meta.MetaFormat.putStrList

/** One cell for CELL_IDENTITY (docs/META_FORMAT.md §5). Null = unavailable. */
class CellIdentity(
    val rat: Int, val registered: Boolean, val conn: Int, val tsNs: Long?,
    val mcc: Int?, val mnc: Int?, val mncDigits: Int, val cid: Long?, val pci: Int?, val arfcn: Int?,
    val tac: Int?, val bandwidthKhz: Int?, val bands: IntArray?,
)

/** One cell for CELL_MEASUREMENT / SIGNAL_STRENGTH; [m] holds m0..m7 by RAT, null = unavailable. */
class CellMeasurement(
    val rat: Int, val registered: Boolean, val conn: Int, val tsNs: Long?,
    val pci: Int?, val arfcn: Int?, val level: Int?, val m: Array<Int?>,
)

/** Typed encoders for every record type; each returns false if the record was dropped. */
object MetaRecords {
    /** Cell entry status byte: bit 0 registered (serving), bits 1-2 connection status. */
    private fun status(registered: Boolean, conn: Int) = (if (registered) 1 else 0) or ((conn and 3) shl 1)

    fun sessionInfo(w: MetaWriter, ts: Long, info: Map<String, String>) =
        w.emit(MetaFormat.SESSION_INFO, MetaFormat.TS_LOGGER, ts, critical = true) { b ->
            b.putShort(info.size.toShort())
            for ((k, v) in info) {
                putStr(b, k)
                putStr(b, v)
            }
        }

    fun clockSync(w: MetaWriter, bootNs: Long, realNs: Long, reason: Int) =
        w.emit(MetaFormat.CLOCK_SYNC, MetaFormat.TS_LOGGER, bootNs, critical = reason == MetaFormat.CLOCK_START || reason == MetaFormat.CLOCK_STOP) { b ->
            b.putLong(realNs).put(reason.toByte())
        }

    fun sessionEnd(w: MetaWriter, ts: Long, status: Int, reason: String, counters: Map<String, Long>) =
        w.emit(MetaFormat.SESSION_END, MetaFormat.TS_LOGGER, ts, critical = true) { b ->
            b.put(status.toByte())
            putStr(b, reason)
            putCounters(b, counters)
        }

    fun captureStats(w: MetaWriter, ts: Long, counters: Map<String, Long>) =
        w.emit(MetaFormat.CAPTURE_STATS, MetaFormat.TS_LOGGER, ts) { b -> putCounters(b, counters) }

    fun sensorStatus(w: MetaWriter, ts: Long, source: Int, state: Int, detail: String) =
        w.emit(MetaFormat.SENSOR_STATUS, MetaFormat.TS_LOGGER, ts) { b ->
            b.putShort(source.toShort()).put(state.toByte()).put(0)
            putStr(b, detail)
        }

    /** NaN = unavailable for every optional float/double. */
    fun location(
        w: MetaWriter, fixNs: Long, recvNs: Long, lat: Double, lon: Double, alt: Double, mslAlt: Double,
        hAcc: Float, vAcc: Float, speed: Float, speedAcc: Float, bearing: Float, bearingAcc: Float,
        provider: Int, satsUsed: Int,
    ) = w.emit(MetaFormat.LOCATION, MetaFormat.TS_LOCATION, fixNs) { b ->
        var p = 1
        if (!alt.isNaN()) p = p or (1 shl 1)
        if (!mslAlt.isNaN()) p = p or (1 shl 2)
        if (!hAcc.isNaN()) p = p or (1 shl 3)
        if (!vAcc.isNaN()) p = p or (1 shl 4)
        if (!speed.isNaN()) p = p or (1 shl 5)
        if (!speedAcc.isNaN()) p = p or (1 shl 6)
        if (!bearing.isNaN()) p = p or (1 shl 7)
        if (!bearingAcc.isNaN()) p = p or (1 shl 8)
        if (satsUsed >= 0) p = p or (1 shl 9)
        fun f(v: Float) = if (v.isNaN()) 0f else v
        fun d(v: Double) = if (v.isNaN()) 0.0 else v
        b.putInt(p).putLong(recvNs).putDouble(lat).putDouble(lon).putDouble(d(alt)).putDouble(d(mslAlt))
            .putFloat(f(hAcc)).putFloat(f(vAcc)).putFloat(f(speed)).putFloat(f(speedAcc))
            .putFloat(f(bearing)).putFloat(f(bearingAcc))
            .put(provider.toByte()).put(maxOf(satsUsed, 0).coerceAtMost(255).toByte()).putShort(0)
    }

    fun gnssStatus(w: MetaWriter, ts: Long, visible: Int, used: Int, meanCn0: Float, constellations: Int) =
        w.emit(MetaFormat.GNSS_STATUS, MetaFormat.TS_LOGGER, ts) { b ->
            b.putShort(visible.toShort()).putShort(used.toShort()).putFloat(meanCn0).putInt(constellations)
        }

    fun motion(w: MetaWriter, sensorTsNs: Long, sensor: Int, accuracy: Int, values: FloatArray, n: Int) =
        w.emit(MetaFormat.MOTION_SAMPLE, MetaFormat.TS_SENSOR, sensorTsNs) { b ->
            b.put(sensor.toByte()).put(accuracy.toByte()).put(n.toByte()).put(0)
            for (i in 0 until n) b.putFloat(values[i])
        }

    fun radioState(
        w: MetaWriter, ts: Long, dataNetworkType: Int?, override: Int?, dataState: Int?, dataActivity: Int?,
        serviceState: Int?, roaming: Boolean?, operator: String?, operatorName: String?,
    ) = w.emit(MetaFormat.RADIO_STATE, MetaFormat.TS_LOGGER, ts) { b ->
        var p = 0
        if (dataNetworkType != null) p = p or 1
        if (override != null) p = p or (1 shl 1)
        if (dataState != null) p = p or (1 shl 2)
        if (dataActivity != null) p = p or (1 shl 3)
        if (serviceState != null) p = p or (1 shl 4)
        if (roaming != null) p = p or (1 shl 5)
        if (operator != null) p = p or (1 shl 6)
        if (operatorName != null) p = p or (1 shl 7)
        b.putInt(p).putInt(dataNetworkType ?: 0).putInt(override ?: 0).putInt(dataState ?: 0)
            .putInt(dataActivity ?: 0).putInt(serviceState ?: 0)
            .put(if (roaming == true) 1 else 0).put(0).putShort(0)
        putStr(b, operator)
        putStr(b, operatorName)
    }

    fun cellIdentity(w: MetaWriter, ts: Long, refresh: Boolean, cells: List<CellIdentity>) =
        w.emit(MetaFormat.CELL_IDENTITY, MetaFormat.TS_LOGGER or (if (refresh) MetaFormat.FLAG_REFRESH else 0), ts) { b ->
            b.putShort(cells.size.toShort()).putShort(0)
            for (c in cells) {
                val start = b.position()
                var p = 0
                if (c.tsNs != null) p = p or 1
                if (c.mcc != null) p = p or (1 shl 1)
                if (c.mnc != null) p = p or (1 shl 2)
                if (c.cid != null) p = p or (1 shl 3)
                if (c.pci != null) p = p or (1 shl 4)
                if (c.arfcn != null) p = p or (1 shl 5)
                if (c.tac != null) p = p or (1 shl 6)
                if (c.bandwidthKhz != null) p = p or (1 shl 7)
                if (c.bands != null) p = p or (1 shl 8)
                b.putShort(0).put(c.rat.toByte()).put(status(c.registered, c.conn).toByte()).putInt(p).putLong(c.tsNs ?: 0)
                b.putShort((c.mcc ?: 0).toShort()).putShort((c.mnc ?: 0).toShort()).put(c.mncDigits.toByte())
                    .put(0).putShort(0)
                b.putLong(c.cid ?: 0).putInt(c.pci ?: 0).putInt(c.arfcn ?: 0).putInt(c.tac ?: 0).putInt(c.bandwidthKhz ?: 0)
                val bands = c.bands ?: IntArray(0)
                b.putShort(bands.size.toShort())
                for (x in bands) b.putInt(x)
                b.putShort(start, (b.position() - start).toShort())
            }
        }

    private fun measurements(w: MetaWriter, type: Int, flags: Int, ts: Long, cells: List<CellMeasurement>) =
        w.emit(type, flags, ts) { b ->
            b.putShort(cells.size.toShort()).putShort(0)
            for (c in cells) {
                val start = b.position()
                var p = 0
                if (c.tsNs != null) p = p or 1
                if (c.pci != null) p = p or (1 shl 1)
                if (c.arfcn != null) p = p or (1 shl 2)
                if (c.level != null) p = p or (1 shl 3)
                for (i in 0 until 8) if (c.m.getOrNull(i) != null) p = p or (1 shl (4 + i))
                b.putShort(0).put(c.rat.toByte()).put(status(c.registered, c.conn).toByte()).putInt(p).putLong(c.tsNs ?: 0)
                b.putInt(c.pci ?: 0).putInt(c.arfcn ?: 0).putInt(c.level ?: 0)
                for (i in 0 until 8) b.putInt(c.m.getOrNull(i) ?: 0)
                b.putShort(start, (b.position() - start).toShort())
            }
        }

    fun cellMeasurement(w: MetaWriter, ts: Long, sourceTs: Boolean, cells: List<CellMeasurement>) =
        measurements(w, MetaFormat.CELL_MEASUREMENT, if (sourceTs) MetaFormat.TS_MODEM else MetaFormat.TS_LOGGER, ts, cells)

    fun signalStrength(w: MetaWriter, ts: Long, sourceTs: Boolean, cells: List<CellMeasurement>) =
        measurements(w, MetaFormat.SIGNAL_STRENGTH, if (sourceTs) MetaFormat.TS_MODEM else MetaFormat.TS_LOGGER, ts, cells)

    fun networkState(
        w: MetaWriter, ts: Long, transports: Int, validated: Boolean, metered: Boolean, lost: Boolean,
        downKbps: Int, upKbps: Int, signal: Int,
    ) = w.emit(MetaFormat.NETWORK_STATE, MetaFormat.TS_LOGGER, ts) { b ->
        b.putInt(transports).put(if (validated) 1 else 0).put(if (metered) 1 else 0).put(if (lost) 1 else 0).put(0)
            .putInt(downKbps).putInt(upKbps).putInt(signal).putInt(0)
    }

    fun wifiState(
        w: MetaWriter, ts: Long, refresh: Boolean, connected: Boolean, rssi: Int?, freq: Int?, link: Int?,
        tx: Int?, rx: Int?, standard: Int?, bssid: ByteArray?,
    ) = w.emit(MetaFormat.WIFI_STATE, MetaFormat.TS_LOGGER or (if (refresh) MetaFormat.FLAG_REFRESH else 0), ts) { b ->
        var p = if (connected) 1 else 0
        if (rssi != null) p = p or (1 shl 1)
        if (freq != null) p = p or (1 shl 2)
        if (link != null) p = p or (1 shl 3)
        if (tx != null) p = p or (1 shl 4)
        if (rx != null) p = p or (1 shl 5)
        if (standard != null) p = p or (1 shl 6)
        val hasBssid = bssid != null && bssid.size == 6
        if (hasBssid) p = p or (1 shl 7)
        b.putInt(p).putInt(rssi ?: 0).putInt(freq ?: 0).putInt(link ?: 0).putInt(tx ?: 0).putInt(rx ?: 0).putInt(standard ?: 0)
        if (hasBssid) b.put(bssid!!) else b.putInt(0).putShort(0)
        b.putShort(0)
    }

    fun uidMapping(
        w: MetaWriter, ts: Long, uid: Int, cls: String, classSource: String, note: String?,
        packages: List<String>, appNames: List<String>,
    ) = w.emit(MetaFormat.UID_MAPPING, MetaFormat.TS_LOGGER, ts) { b ->
        b.putInt(uid).putInt(0)
        putStr(b, cls)
        putStr(b, classSource)
        putStr(b, note)
        putStrList(b, packages)
        putStrList(b, appNames)
    }

    /** [key] is the native 40-byte flow key (ipver, proto, lport, rport, pad, local[16], remote[16]). */
    fun flowMapping(
        w: MetaWriter, ts: Long, flowId: Long, firstSeenNs: Long, key: ByteArray, uid: Int,
        resolution: Int, attempts: Int, latencyMs: Long,
    ) = w.emit(MetaFormat.FLOW_MAPPING, MetaFormat.TS_LOGGER, ts) { b ->
        b.putLong(flowId).putLong(firstSeenNs)
        b.put(key, 0, 40) // ipver u8, proto u8, lport u16, rport u16, pad u16, local[16], remote[16]
        b.putInt(uid).put(resolution.toByte()).put(attempts.coerceAtMost(255).toByte()).putShort(0)
            .putInt(latencyMs.coerceIn(0, 0xffffffffL).toInt()).putInt(0)
    }
}
