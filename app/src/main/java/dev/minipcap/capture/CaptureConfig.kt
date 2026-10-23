package dev.minipcap.capture

import android.content.Context

enum class FilterMode { ALL, INCLUDE, EXCLUDE }

/** Benchmark variants from docs/PERFORMANCE_PLAN.md; the native ids match MPC_VARIANT_*. */
enum class Variant(val nativeId: Int, val label: String, val profile: String) {
    B(1, "B: forwarding only", "forwarding_only"),
    C(2, "C: copy to null sink", "prefix_copy_null"),
    D(3, "D: PCAP writer, no owner lookup", "writer_only"),
    E(4, "E: writer + owner lookup", "writer_uid"),
    F(5, "F: full: + measurements (release)", "full_metadata");

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
