package dev.minipcap.capture

import android.content.Context

enum class FilterMode { ALL, INCLUDE, EXCLUDE }

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
    /** IP-layer bytes kept per packet; 0 = full packet. */
    val snaplen: Int,
    val filterMode: FilterMode,
    val selectedPackages: Set<String>,
    val variant: Variant,
    val mtu: Int = 1500,
    val ringBytes: Int = 8 shl 20,
    /** Position, motion and radio context records (needs location/phone permissions). */
    val contextEnabled: Boolean = true,
    val contextIntervalMs: Long = 1000,
    /** Writer hold for late UID binding into a flow's first packets (native uid_hold_ms). */
    val uidHoldMs: Int = 500,
) {
    companion object {
        val SNAPLENS = listOf(64, 128, 256, 512, 0)
        const val DEFAULT_SNAPLEN = 256
        private const val PREFS = "capture_config"

        fun load(ctx: Context): CaptureConfig {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            return CaptureConfig(
                snaplen = p.getInt("snaplen", DEFAULT_SNAPLEN),
                filterMode = runCatching { FilterMode.valueOf(p.getString("filter_mode", null)!!) }
                    .getOrDefault(FilterMode.ALL),
                selectedPackages = p.getStringSet("packages", emptySet())!!.toSet(),
                variant = runCatching { Variant.valueOf(p.getString("variant", null)!!) }
                    .getOrDefault(Variant.F),
                contextEnabled = p.getBoolean("context", true),
            )
        }

        fun save(ctx: Context, c: CaptureConfig) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putInt("snaplen", c.snaplen)
                .putString("filter_mode", c.filterMode.name)
                .putStringSet("packages", c.selectedPackages)
                .putString("variant", c.variant.name)
                .putBoolean("context", c.contextEnabled)
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
