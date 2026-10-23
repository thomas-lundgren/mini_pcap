package dev.minipcap.capture

import android.content.Context

enum class FilterMode { ALL, INCLUDE, EXCLUDE }

/** Motion logging: every sensor event, at most motionHz, or only on change beyond a threshold. */
enum class MotionMode { ALL, MAX_RATE, THRESHOLD }

/** Asynchronous metadata collectors (docs/META_FORMAT.md); each independent of packet capture. */
data class MeasurementConfig(
    val gps: Boolean = true,
    val gpsMinTimeMs: Long = 1000,
    val gpsMinDistanceM: Float = 0f,
    val radio: Boolean = true,
    /** Period of explicit cell-info refresh requests; reports between are event driven. */
    val radioRefreshMs: Long = 2000,
    /** Periodic repeat of an unchanged serving-cell identity. */
    val cellIdentityRefreshMs: Long = 60_000,
    val motion: Boolean = true,
    val motionMode: MotionMode = MotionMode.MAX_RATE,
    val motionHz: Int = 50,
    /** THRESHOLD mode: m/s² (accelerometer) or rad/s (gyroscope) change that triggers a record. */
    val motionThreshold: Float = 0.5f,
    val gyro: Boolean = true,
    val wifiRefreshMs: Long = 2000,
) {
    fun asInfo(): Map<String, String> = mapOf(
        "gps" to "$gps", "gps_min_time_ms" to "$gpsMinTimeMs", "gps_min_distance_m" to "$gpsMinDistanceM",
        "radio" to "$radio", "radio_refresh_ms" to "$radioRefreshMs", "cell_identity_refresh_ms" to "$cellIdentityRefreshMs",
        "motion" to "$motion", "motion_mode" to motionMode.name.lowercase(), "motion_hz" to "$motionHz",
        "motion_threshold" to "$motionThreshold", "gyro" to "$gyro", "wifi_refresh_ms" to "$wifiRefreshMs",
    )

    companion object {
        private const val PREFS = "measurements"

        fun load(ctx: Context): MeasurementConfig {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val d = MeasurementConfig()
            return MeasurementConfig(
                gps = p.getBoolean("gps", d.gps),
                gpsMinTimeMs = p.getLong("gps_min_time_ms", d.gpsMinTimeMs),
                gpsMinDistanceM = p.getFloat("gps_min_distance_m", d.gpsMinDistanceM),
                radio = p.getBoolean("radio", d.radio),
                radioRefreshMs = p.getLong("radio_refresh_ms", d.radioRefreshMs),
                motion = p.getBoolean("motion", d.motion),
                motionMode = runCatching { MotionMode.valueOf(p.getString("motion_mode", null)!!) }.getOrDefault(d.motionMode),
                motionHz = p.getInt("motion_hz", d.motionHz),
                motionThreshold = p.getFloat("motion_threshold", d.motionThreshold),
                gyro = p.getBoolean("gyro", d.gyro),
            )
        }

        fun save(ctx: Context, m: MeasurementConfig) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean("gps", m.gps).putLong("gps_min_time_ms", m.gpsMinTimeMs)
                .putFloat("gps_min_distance_m", m.gpsMinDistanceM)
                .putBoolean("radio", m.radio).putLong("radio_refresh_ms", m.radioRefreshMs)
                .putBoolean("motion", m.motion).putString("motion_mode", m.motionMode.name)
                .putInt("motion_hz", m.motionHz).putFloat("motion_threshold", m.motionThreshold)
                .putBoolean("gyro", m.gyro)
                .apply()
        }
    }
}

/** Benchmark variants from docs/PERFORMANCE_PLAN.md; the native ids match MPC_VARIANT_*. */
enum class Variant(val nativeId: Int, val label: String, val profile: String) {
    B(1, "B: forwarding only", "forwarding_only"),
    C(2, "C: copy to null sink", "prefix_copy_null"),
    D(3, "D: PCAPNG writer, no UID", "writer_flow_id"),
    E(4, "E: writer + UID", "writer_uid"),
    F(5, "F: full (release)", "full_metadata");

    val writesFile get() = nativeId >= D.nativeId
    val resolvesUids get() = nativeId >= E.nativeId
    val fullUi get() = this == F
}

data class CaptureConfig(
    /**
     * IP-layer bytes kept per packet; 0 = full packet, [HEADERS_ONLY] = exactly the IP +
     * transport headers. The native tap never cuts inside the headers, so every record
     * includes at least the TCP/UDP header (e.g. 72 bytes for IPv6 + TCP with options).
     */
    val snaplen: Int,
    val filterMode: FilterMode,
    val selectedPackages: Set<String>,
    val variant: Variant,
    val mtu: Int = 1500,
    val ringBytes: Int = 8 shl 20,
) {
    companion object {
        const val HEADERS_ONLY = -1 // native MPC_SNAPLEN_HEADERS
        val SNAPLENS = listOf(HEADERS_ONLY, 128, 256, 512, 0)
        const val DEFAULT_SNAPLEN = 128
        private const val PREFS = "capture_config"

        fun load(ctx: Context): CaptureConfig {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            return CaptureConfig(
                snaplen = p.getInt("snaplen", DEFAULT_SNAPLEN).takeIf { it in SNAPLENS } ?: DEFAULT_SNAPLEN,
                filterMode = runCatching { FilterMode.valueOf(p.getString("filter_mode", null)!!) }
                    .getOrDefault(FilterMode.ALL),
                selectedPackages = p.getStringSet("packages", emptySet())!!.toSet(),
                variant = runCatching { Variant.valueOf(p.getString("variant", null)!!) }
                    .getOrDefault(Variant.F),
            )
        }

        fun save(ctx: Context, c: CaptureConfig) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putInt("snaplen", c.snaplen)
                .putString("filter_mode", c.filterMode.name)
                .putStringSet("packages", c.selectedPackages)
                .putString("variant", c.variant.name)
                .apply()
        }
    }
}

/** User-configured package -> class assignments ("package=class" lines). */
object ClassRules {
    private const val PREFS = "class_rules"
    val KNOWN_CLASSES = listOf("realtime_video", "gaming", "web", "background_sync", "system", "unknown")

    fun loadText(ctx: Context): String =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("rules", "") ?: ""

    fun saveText(ctx: Context, text: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("rules", text).apply()
    }

    fun parse(text: String): Map<String, String> =
        text.lineSequence()
            .map { it.substringBefore('#').trim() }
            .filter { '=' in it }
            .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
            .filter { it.key.isNotEmpty() && it.value.isNotEmpty() }
}
