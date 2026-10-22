package dev.minipcap.capture

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Everything needed to render the `<capture_id>.meta.json` sidecar (schema_version 1). */
data class SidecarData(
    val captureId: String,
    val status: String, // "complete" | "recovered" | "recording" (checkpoint)
    val startedUtcMs: Long,
    val endedUtcMs: Long?,
    val snaplen: Int,
    val mtu: Int,
    val filterMode: FilterMode,
    val filterPackages: List<String>,
    val missingPackages: List<String>,
    val variant: Variant,
    val uidMap: Map<Int, UidInfo>,
    val flowUidMap: Map<Long, FlowResolution>,
    val counters: Map<String, Long>,
    val uidStats: Map<String, Long>,
    val stopReason: String?,
    val appVersion: String,
    val deviceApiLevel: Int,
    val anchorBoottimeNs: Long,
    val anchorRealtimeNs: Long,
)

object Sidecar {
    const val SCHEMA_VERSION = 1
    const val WRITER_VERSION = "mpc-native-pcapng-1"
    const val FORWARDER_NAME = "lwip-heiher-e6d5fc6+socket-relay"

    val KNOWN_LIMITATIONS = listOf(
        "Capture point is the Android VPN TUN interface, not the physical radio interface.",
        "TCP is terminated by an on-device user-space stack (lwIP); downlink TCP segments, ACK timing and SYN-ACK are synthesized locally and do not mirror server packet boundaries.",
        "UDP is relayed per datagram; downlink datagrams are re-encapsulated by the relay (IP ID/TTL differ from the network).",
        "ICMP is not forwarded by the VPN in v1.",
        "Uplink timestamps are taken at TUN read; downlink timestamps just before TUN write. Microsecond resolution is not microsecond accuracy.",
        "UID attribution uses ConnectivityManager.getConnectionOwnerUid asynchronously; early packets of a flow carry only the flow ID and are joined through flow_uid_map.",
        "Packets that are not TCP/UDP with readable ports carry no flow ID comment (flow_id 0).",
        "Capture-queue drops are logging-record drops, never forwarding drops.",
    )

    fun iso(ms: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date(ms))

    fun build(d: SidecarData): JSONObject {
        val o = JSONObject()
        o.put("schema_version", SCHEMA_VERSION)
        o.put("capture_id", d.captureId)
        o.put("capture_file", "${d.captureId}.pcapng")
        o.put("status", d.status)
        o.put("started_utc", iso(d.startedUtcMs))
        o.put("ended_utc", d.endedUtcMs?.let { iso(it) } ?: JSONObject.NULL)
        o.put("capture_point", "android_vpn_tun")
        o.put("timestamp_unit", "microseconds_since_unix_epoch")
        o.put("timestamp_source", "CLOCK_BOOTTIME at capture point, converted with one boottime/realtime anchor")
        o.put("clock_anchors", JSONObject()
            .put("boottime_ns", d.anchorBoottimeNs)
            .put("realtime_ns", d.anchorRealtimeNs))
        o.put("snaplen_bytes", if (d.snaplen == 0) JSONObject.NULL else d.snaplen)
        o.put("snaplen_mode", if (d.snaplen == 0) "full" else "prefix")
        o.put("mtu", d.mtu)
        o.put("linktype", "LINKTYPE_RAW(101)")
        o.put("direction_encoding", JSONObject()
            .put("epb_flags_outbound", "UPLINK (app -> network)")
            .put("epb_flags_inbound", "DOWNLINK (network -> app)"))
        o.put("comment_grammar", "f-<flow_id> | u-<uid>;f-<flow_id>; no comment = no flow (flow_id 0)")
        o.put("filter", JSONObject()
            .put("mode", d.filterMode.name.lowercase(Locale.US))
            .put("packages", JSONArray(d.filterPackages.sorted()))
            .put("missing_packages", JSONArray(d.missingPackages.sorted()))
            .put("self_excluded", true))

        val uidMap = JSONObject()
        for ((uid, info) in d.uidMap.toSortedMap()) {
            val e = JSONObject()
                .put("packages", JSONArray(info.packages))
                .put("app_names", JSONArray(info.appNames))
                .put("class", info.appClass)
                .put("class_source", info.classSource)
            if (info.note != null) e.put("note", info.note)
            uidMap.put(uid.toString(), e)
        }
        o.put("uid_map", uidMap)

        val flowMap = JSONObject()
        for ((flow, r) in d.flowUidMap.toSortedMap()) {
            flowMap.put(flow.toString(), JSONObject()
                .put("uid", r.uid ?: JSONObject.NULL)
                .put("resolution", r.resolution)
                .put("lookup_attempts", r.attempts)
                .put("resolve_latency_ms", r.latencyMs))
        }
        o.put("flow_uid_map", flowMap)

        val c = d.counters
        val stats = JSONObject()
            .put("packets_recorded", c["records_written"] ?: 0)
            .put("packets_observed_uplink", c["pkts_ul"] ?: 0)
            .put("packets_observed_downlink", c["pkts_dl"] ?: 0)
            .put("bytes_observed_uplink", c["bytes_ul"] ?: 0)
            .put("bytes_observed_downlink", c["bytes_dl"] ?: 0)
            .put("capture_queue_drops", (c["capture_queue_drops_ul"] ?: 0) + (c["capture_queue_drops_dl"] ?: 0))
            .put("captured_bytes", c["captured_bytes"] ?: 0)
            .put("file_bytes", c["file_bytes"] ?: 0)
            .put("storage_errors", c["storage_errors"] ?: 0)
            .put("forwarding_errors", (c["forwarding_errors"] ?: 0) + (c["tun_write_errors"] ?: 0))
            .put("uid_lookup_misses", d.uidStats["uid_lookup_misses"] ?: 0)
            .put("uid_requests_queued", c["uid_requests_queued"] ?: 0)
            .put("uid_request_queue_overflows", c["uid_request_queue_overflows"] ?: 0)
            .put("capture_ring_peak_bytes", (c["capture_ring_peak_slots"] ?: 0) * (c["capture_ring_slot_bytes"] ?: 0))
        for ((k, v) in d.uidStats) stats.put(k, v)
        o.put("stats", stats)
        o.put("native_counters", JSONObject(c.toSortedMap() as Map<*, *>))

        o.put("capture_engine", "native_ndk")
        o.put("benchmark_profile", d.variant.profile)
        o.put("app_version", d.appVersion)
        o.put("device_api_level", d.deviceApiLevel)
        o.put("writer_version", WRITER_VERSION)
        o.put("forwarder_name", FORWARDER_NAME)
        o.put("stop_reason", d.stopReason ?: JSONObject.NULL)
        o.put("known_limitations", JSONArray(KNOWN_LIMITATIONS))
        return o
    }

    /** Atomic replace on local storage: temp file, fsync, rename. */
    fun writeAtomic(target: File, json: JSONObject) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        FileOutputStream(tmp).use { out ->
            out.write(json.toString(2).toByteArray(Charsets.UTF_8))
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw java.io.IOException("rename failed for ${target.name}")
        }
    }
}
