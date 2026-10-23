package dev.minipcap.meta.apps

import android.content.Context

/** User-configured package -> class assignments ("package=class" lines), used for UID_MAPPING. */
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
