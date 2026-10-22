package dev.minipcap

import dev.minipcap.capture.ClassRules
import dev.minipcap.capture.FilterMode
import dev.minipcap.capture.FlowResolution
import dev.minipcap.capture.Sidecar
import dev.minipcap.capture.SidecarData
import dev.minipcap.capture.UidInfo
import dev.minipcap.capture.Variant
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SidecarTest {
    private fun data() = SidecarData(
        captureId = "7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47", status = "complete",
        startedUtcMs = 1_792_000_000_000, endedUtcMs = 1_792_000_300_000, snaplen = 256, mtu = 1500,
        filterMode = FilterMode.INCLUDE, filterPackages = listOf("org.example.meet"), missingPackages = emptyList(),
        variant = Variant.F,
        uidMap = mapOf(10234 to UidInfo(listOf("org.example.meet"), listOf("Example Meet"), "realtime_video", "user_config", null),
            1000 to UidInfo(listOf("android", "com.android.settings"), listOf("Android", "Settings"), "system", "uid_range", "shared_uid")),
        flowUidMap = mapOf(1042L to FlowResolution(10234, "resolved_after_first_packet", 1, 2),
            7L to FlowResolution(null, "unresolved_invalid_uid", 5, 2100)),
        counters = mapOf("records_written" to 10L, "capture_queue_drops_ul" to 1L, "capture_queue_drops_dl" to 2L,
            "capture_ring_peak_slots" to 4L, "capture_ring_slot_bytes" to 288L),
        uidStats = mapOf("uid_lookup_misses" to 1L), stopReason = "user_stop", appVersion = "0.1.0",
        deviceApiLevel = 37, anchorBoottimeNs = 5, anchorRealtimeNs = 6)

    @Test
    fun containsContractFields() {
        val o = JSONObject(Sidecar.build(data()).toString())
        assertEquals(1, o.getInt("schema_version"))
        assertEquals("7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47.pcapng", o.getString("capture_file"))
        assertEquals("android_vpn_tun", o.getString("capture_point"))
        assertEquals("microseconds_since_unix_epoch", o.getString("timestamp_unit"))
        assertEquals("2026-10-14T17:46:40.000Z", o.getString("started_utc"))
        assertEquals("include", o.getJSONObject("filter").getString("mode"))
        val u = o.getJSONObject("uid_map").getJSONObject("10234")
        assertEquals("realtime_video", u.getString("class"))
        assertEquals(2, o.getJSONObject("uid_map").getJSONObject("1000").getJSONArray("packages").length())
        assertEquals(10234, o.getJSONObject("flow_uid_map").getJSONObject("1042").getInt("uid"))
        assertTrue(o.getJSONObject("flow_uid_map").getJSONObject("7").isNull("uid"))
        assertEquals(3, o.getJSONObject("stats").getInt("capture_queue_drops"))
        assertEquals(4 * 288, o.getJSONObject("stats").getInt("capture_ring_peak_bytes"))
        for (k in listOf("app_version", "device_api_level", "writer_version", "forwarder_name", "clock_anchors",
            "stop_reason", "known_limitations", "benchmark_profile", "capture_engine"))
            assertTrue(k, o.has(k))
        assertEquals("full_metadata", o.getString("benchmark_profile"))
    }

    @Test
    fun classRulesParse() {
        val r = ClassRules.parse("org.a=gaming\n# comment\n  org.b = web  \nbroken\n=x\norg.c=\n")
        assertEquals(mapOf("org.a" to "gaming", "org.b" to "web"), r)
    }
}
