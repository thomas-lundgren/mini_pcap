package dev.minipcap.capture

import android.content.pm.PackageManager
import android.os.Process
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/** UID -> package identity, resolved asynchronously and cached during capture. */
data class UidInfo(
    val packages: List<String>,
    val appNames: List<String>,
    val appClass: String,
    val classSource: String,
    val note: String?,
)

class PackageRegistry(private val pm: PackageManager, private val rules: Map<String, String>) {
    private val map = ConcurrentHashMap<Int, UidInfo>()
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "uid-packages").apply { priority = Thread.MIN_PRIORITY }
    }

    /** Called from the UID worker for every resolved UID; deduplicated, never blocks. */
    fun noteUid(uid: Int) {
        if (map.containsKey(uid)) return
        executor.execute { if (!map.containsKey(uid)) map[uid] = resolve(uid) }
    }

    fun snapshot(): Map<Int, UidInfo> = HashMap(map)

    fun shutdown() {
        executor.shutdown()
        executor.awaitTermination(2, java.util.concurrent.TimeUnit.SECONDS)
    }

    private fun resolve(uid: Int): UidInfo {
        val pkgs = try {
            pm.getPackagesForUid(uid)?.sorted() ?: emptyList()
        } catch (e: SecurityException) {
            emptyList()
        }
        val names = pkgs.map { pkg ->
            try {
                pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
            } catch (e: PackageManager.NameNotFoundException) {
                pkg
            }
        }
        val configured = pkgs.firstNotNullOfOrNull { rules[it] }
        val (cls, src) = when {
            configured != null -> configured to "user_config"
            uid < Process.FIRST_APPLICATION_UID -> "system" to "uid_range"
            else -> "unknown" to "default"
        }
        val note = when {
            pkgs.isEmpty() && uid >= Process.FIRST_APPLICATION_UID -> "package_not_visible_or_uninstalled"
            pkgs.isEmpty() -> "system_uid_without_package"
            pkgs.size > 1 -> "shared_uid"
            else -> null
        }
        return UidInfo(pkgs, names, cls, src, note)
    }
}
