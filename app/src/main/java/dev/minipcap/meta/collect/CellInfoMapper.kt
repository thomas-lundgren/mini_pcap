package dev.minipcap.meta.collect

import android.os.Build
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
import dev.minipcap.meta.CellIdentity
import dev.minipcap.meta.CellMeasurement
import dev.minipcap.meta.MetaFormat

/**
 * Android cell objects -> metadata cell entries (docs/META_FORMAT.md). Unavailable values
 * (CellInfo.UNAVAILABLE etc.) become null, never a number. Timestamps are the modem's,
 * on the elapsedRealtime clock.
 */
object CellInfoMapper {

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
    fun tsOf(ci: CellInfo): Long =
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
