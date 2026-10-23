package dev.minipcap.meta.apps

import android.net.ConnectivityManager
import android.os.Process
import android.os.SystemClock
import android.system.OsConstants
import dev.minipcap.capture.NativeCore
import dev.minipcap.meta.MetaFormat
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.PriorityQueue

/**
 * Final result of the owner-UID lookup for one flow generation (FLOW_MAPPING record).
 * [key] is the native 40-byte flow key; [firstSeenNs] the capture time of its first packet.
 */
class FlowResult(
    val flowId: Long, val firstSeenNs: Long, val key: ByteArray, val uid: Int?,
    val resolution: Int, val attempts: Int, val latencyMs: Long,
)

/**
 * Off-packet-path flow-owner worker. Receives batched new-flow announcements from native
 * code, calls [ConnectivityManager.getConnectionOwnerUid] (allowed for the active VPN app)
 * and retries INVALID_UID with bounded backoff. Every flow ends in exactly one [onFlow]
 * call (FLOW_MAPPING), resolved or not; nothing is sent back to the packet path.
 */
class UidResolver(
    private val handle: Long,
    private val cm: ConnectivityManager,
    private val onUid: (Int) -> Unit,
    private val onFlow: (FlowResult) -> Unit = {},
) : Thread("uid-resolver") {

    private class Pending(val key: ByteArray, val flowId: Long, val firstSeenNs: Long) {
        var attempts = 0
        var due = 0L
    }

    @Volatile var requests = 0L; private set
    @Volatile var resolved = 0L; private set
    @Volatile var misses = 0L; private set
    @Volatile var lookupCalls = 0L; private set
    private val latencies = ArrayList<Long>()

    private val reqBuf = ByteBuffer.allocateDirect(BATCH * NativeCore.FLOW_REQUEST_BYTES).order(ByteOrder.LITTLE_ENDIAN)
    private val retries = PriorityQueue<Pending>(compareBy { it.due })

    override fun run() {
        Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
        while (true) {
            val now = SystemClock.elapsedRealtime()
            val timeout = retries.peek()?.let { (it.due - now).coerceIn(0, POLL_MS.toLong()).toInt() } ?: POLL_MS
            reqBuf.clear()
            val n = NativeCore.nativeUidPoll(handle, reqBuf, BATCH, timeout)
            if (n < 0) break
            for (i in 0 until n) {
                val base = i * NativeCore.FLOW_REQUEST_BYTES
                val key = ByteArray(40)
                for (j in 0 until 40) key[j] = reqBuf.get(base + 8 + j)
                requests++
                attempt(Pending(key, reqBuf.getLong(base), reqBuf.getLong(base + 48)))
            }
            val t = SystemClock.elapsedRealtime()
            while (retries.isNotEmpty() && retries.peek()!!.due <= t) attempt(retries.poll()!!)
        }
        // Session closed: flows still pending retry are recorded as unresolved.
        for (p in retries) record(p, null, MetaFormat.RES_UNRESOLVED_SESSION_ENDED)
        retries.clear()
    }

    private fun attempt(p: Pending) {
        p.attempts++
        val uid = lookup(p.key)
        if (uid != Process.INVALID_UID) {
            record(p, uid, if (p.attempts == 1) MetaFormat.RES_FIRST_LOOKUP else MetaFormat.RES_AFTER_RETRY)
            runCatching { onUid(uid) }
            return
        }
        if (p.attempts <= RETRY_DELAYS_MS.size) {
            p.due = SystemClock.elapsedRealtime() + RETRY_DELAYS_MS[p.attempts - 1]
            retries.add(p)
        } else {
            record(p, null, MetaFormat.RES_UNRESOLVED_INVALID_UID)
        }
    }

    private fun record(p: Pending, uid: Int?, how: Int) {
        // firstSeenNs is CLOCK_BOOTTIME from the native tap = elapsedRealtimeNanos.
        val latency = (SystemClock.elapsedRealtimeNanos() - p.firstSeenNs) / 1_000_000
        runCatching { onFlow(FlowResult(p.flowId, p.firstSeenNs, p.key, uid, how, p.attempts, latency)) }
        if (uid != null) {
            resolved++
            synchronized(latencies) { if (latencies.size < 100_000) latencies.add(latency) }
        } else {
            misses++
        }
    }

    private fun lookup(key: ByteArray): Int {
        val b = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
        val ipver = key[0].toInt()
        val proto = key[1].toInt() and 0xff
        val lport = b.getShort(2).toInt() and 0xffff
        val rport = b.getShort(4).toInt() and 0xffff
        val alen = if (ipver == 4) 4 else 16
        return try {
            val local = InetSocketAddress(InetAddress.getByAddress(key.copyOfRange(8, 8 + alen)), lport)
            val remote = InetSocketAddress(InetAddress.getByAddress(key.copyOfRange(24, 24 + alen)), rport)
            val p = if (proto == 6) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP
            lookupCalls++
            cm.getConnectionOwnerUid(p, local, remote)
        } catch (e: SecurityException) {
            Process.INVALID_UID // no longer the active VPN (e.g. during Stop)
        } catch (e: IllegalArgumentException) {
            Process.INVALID_UID
        }
    }

    fun latencyPercentiles(): Map<String, Long> = synchronized(latencies) {
        if (latencies.isEmpty()) return emptyMap()
        val s = latencies.sorted()
        mapOf(
            "uid_resolve_latency_ms_p50" to s[(s.size - 1) / 2],
            "uid_resolve_latency_ms_p95" to s[((s.size - 1) * 95) / 100],
            "uid_resolve_latency_ms_max" to s.last(),
        )
    }

    companion object {
        private const val BATCH = 256
        private const val POLL_MS = 200
        private val RETRY_DELAYS_MS = longArrayOf(25, 100, 400, 1500)
    }
}
