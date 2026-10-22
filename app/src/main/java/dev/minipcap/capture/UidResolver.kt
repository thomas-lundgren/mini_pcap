package dev.minipcap.capture

import android.net.ConnectivityManager
import android.os.Process
import android.os.SystemClock
import android.system.OsConstants
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.PriorityQueue
import java.util.concurrent.ConcurrentHashMap

/** Result of the asynchronous owner-UID lookup for one flow generation. */
data class FlowResolution(val uid: Int?, val resolution: String, val attempts: Int, val latencyMs: Long)

/**
 * Off-packet-path UID worker. Receives batched new-flow requests from native code,
 * calls [ConnectivityManager.getConnectionOwnerUid] (allowed for the active VPN app),
 * retries INVALID_UID with bounded backoff and returns batched resolutions to the
 * native flow cache. Also records the sidecar `flow_uid_map`.
 */
class UidResolver(
    private val handle: Long,
    private val cm: ConnectivityManager,
    private val onUid: (Int) -> Unit,
) : Thread("uid-resolver") {

    private class Pending(val key: ByteArray, val flowId: Long, val firstSeen: Long) {
        var attempts = 0
        var due = 0L
    }

    val flowUidMap = ConcurrentHashMap<Long, FlowResolution>()

    @Volatile var requests = 0L; private set
    @Volatile var resolved = 0L; private set
    @Volatile var misses = 0L; private set
    @Volatile var lookupCalls = 0L; private set
    private val latencies = ArrayList<Long>()

    private val reqBuf = ByteBuffer.allocateDirect(BATCH * NativeCore.UID_REQUEST_BYTES).order(ByteOrder.LITTLE_ENDIAN)
    private val resBuf = ByteBuffer.allocateDirect(BATCH * NativeCore.UID_RESOLUTION_BYTES).order(ByteOrder.LITTLE_ENDIAN)
    private val retries = PriorityQueue<Pending>(compareBy { it.due })
    private var resCount = 0

    override fun run() {
        Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
        while (true) {
            val now = SystemClock.elapsedRealtime()
            val timeout = retries.peek()?.let { (it.due - now).coerceIn(0, POLL_MS.toLong()).toInt() } ?: POLL_MS
            reqBuf.clear()
            val n = NativeCore.nativeUidPoll(handle, reqBuf, BATCH, timeout)
            if (n < 0) break
            for (i in 0 until n) {
                val base = i * NativeCore.UID_REQUEST_BYTES
                val key = ByteArray(40)
                for (j in 0 until 40) key[j] = reqBuf.get(base + 8 + j)
                requests++
                attempt(Pending(key, reqBuf.getLong(base), SystemClock.elapsedRealtime()))
            }
            val t = SystemClock.elapsedRealtime()
            while (retries.isNotEmpty() && retries.peek()!!.due <= t) attempt(retries.poll()!!)
            flush()
        }
        // Session closed: flows still pending retry are recorded as unresolved.
        for (p in retries) record(p, null, "unresolved_session_ended")
        retries.clear()
    }

    private fun attempt(p: Pending) {
        p.attempts++
        val uid = lookup(p.key)
        if (uid != Process.INVALID_UID) {
            record(p, uid, if (p.attempts == 1) "resolved_after_first_packet" else "resolved_after_retry")
            queueResolution(p, uid)
            onUid(uid)
            return
        }
        if (p.attempts <= RETRY_DELAYS_MS.size) {
            p.due = SystemClock.elapsedRealtime() + RETRY_DELAYS_MS[p.attempts - 1]
            retries.add(p)
        } else {
            record(p, null, "unresolved_invalid_uid")
            queueResolution(p, -1)
        }
    }

    private fun record(p: Pending, uid: Int?, how: String) {
        val latency = SystemClock.elapsedRealtime() - p.firstSeen
        flowUidMap[p.flowId] = FlowResolution(uid, how, p.attempts, latency)
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

    private fun queueResolution(p: Pending, uid: Int) {
        val base = resCount * NativeCore.UID_RESOLUTION_BYTES
        resBuf.putLong(base, p.flowId)
        resBuf.putInt(base + 8, uid)
        resBuf.putInt(base + 12, 0)
        for (j in 0 until 40) resBuf.put(base + 16 + j, p.key[j])
        resCount++
        if (resCount == BATCH) flush()
    }

    private fun flush() {
        if (resCount == 0) return
        NativeCore.nativeUidDeliver(handle, resBuf, resCount)
        resCount = 0
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
