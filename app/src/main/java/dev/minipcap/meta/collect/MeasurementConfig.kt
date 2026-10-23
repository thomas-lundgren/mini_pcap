package dev.minipcap.meta.collect

import android.content.Context

/** Motion logging: every sensor event, at most motionHz, or only on change beyond a threshold. */
enum class MotionMode { ALL, MAX_RATE, THRESHOLD }

/** Asynchronous metadata collectors (docs/META_FORMAT.md); each independent of packet capture. */
data class MeasurementConfig(
    val gps: Boolean = true,
    val gpsMinTimeMs: Long = 1000,
    val gpsMinDistanceM: Float = 0f,
    val radio: Boolean = true,
    /** Explicit cell-info refresh requests (each wakes the modem); reports in between are event driven. */
    val radioRefreshMs: Long = 10_000,
    /** Periodic repeat of an unchanged serving-cell identity. */
    val cellIdentityRefreshMs: Long = 60_000,
    val motion: Boolean = true,
    val motionMode: MotionMode = MotionMode.MAX_RATE,
    val motionHz: Int = 50,
    /** THRESHOLD mode: m/s² (accelerometer) or rad/s (gyroscope) change that triggers a record. */
    val motionThreshold: Float = 0.5f,
    val gyro: Boolean = true,
    /** Default network and Wi-Fi link state; Wi-Fi is polled only while Wi-Fi is the default network. */
    val network: Boolean = true,
    val wifiRefreshMs: Long = 5_000,
) {
    fun asInfo(): Map<String, String> = mapOf(
        "gps" to "$gps", "gps_min_time_ms" to "$gpsMinTimeMs", "gps_min_distance_m" to "$gpsMinDistanceM",
        "radio" to "$radio", "radio_refresh_ms" to "$radioRefreshMs", "cell_identity_refresh_ms" to "$cellIdentityRefreshMs",
        "motion" to "$motion", "motion_mode" to motionMode.name.lowercase(), "motion_hz" to "$motionHz",
        "motion_threshold" to "$motionThreshold", "gyro" to "$gyro", "network" to "$network",
        "wifi_refresh_ms" to "$wifiRefreshMs",
    )

    companion object {
        private const val PREFS = "measurements"

        /** Benchmark variants D/E: only the app/flow records and clock, no measurement collectors. */
        val APPS_ONLY = MeasurementConfig(gps = false, radio = false, motion = false, network = false)

        fun load(ctx: Context): MeasurementConfig {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val d = MeasurementConfig()
            return MeasurementConfig(
                gps = p.getBoolean("gps", d.gps),
                gpsMinTimeMs = p.getLong("gps_min_time_ms", d.gpsMinTimeMs),
                gpsMinDistanceM = p.getFloat("gps_min_distance_m", d.gpsMinDistanceM),
                radio = p.getBoolean("radio", d.radio),
                radioRefreshMs = p.getLong("radio_refresh_ms", d.radioRefreshMs),
                cellIdentityRefreshMs = p.getLong("cell_identity_refresh_ms", d.cellIdentityRefreshMs),
                motion = p.getBoolean("motion", d.motion),
                motionMode = runCatching { MotionMode.valueOf(p.getString("motion_mode", null)!!) }.getOrDefault(d.motionMode),
                motionHz = p.getInt("motion_hz", d.motionHz),
                motionThreshold = p.getFloat("motion_threshold", d.motionThreshold),
                gyro = p.getBoolean("gyro", d.gyro),
                network = p.getBoolean("network", d.network),
                wifiRefreshMs = p.getLong("wifi_refresh_ms", d.wifiRefreshMs),
            )
        }

        fun save(ctx: Context, m: MeasurementConfig) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean("gps", m.gps).putLong("gps_min_time_ms", m.gpsMinTimeMs)
                .putFloat("gps_min_distance_m", m.gpsMinDistanceM)
                .putBoolean("radio", m.radio).putLong("radio_refresh_ms", m.radioRefreshMs)
                .putLong("cell_identity_refresh_ms", m.cellIdentityRefreshMs)
                .putBoolean("motion", m.motion).putString("motion_mode", m.motionMode.name)
                .putInt("motion_hz", m.motionHz).putFloat("motion_threshold", m.motionThreshold)
                .putBoolean("gyro", m.gyro).putBoolean("network", m.network).putLong("wifi_refresh_ms", m.wifiRefreshMs)
                .apply()
        }
    }
}
