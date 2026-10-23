package dev.minipcap.ui

import android.content.Intent
import dev.minipcap.BuildConfig
import dev.minipcap.capture.CaptureConfig
import dev.minipcap.capture.FilterMode
import dev.minipcap.capture.Variant
import dev.minipcap.meta.collect.MeasurementConfig
import dev.minipcap.meta.collect.MotionMode
import dev.minipcap.service.CaptureVpnService
import dev.minipcap.session.Sessions
import dev.minipcap.storage.Exports
import dev.minipcap.upload.UploadSettings

/**
 * Debug builds only: automation hook for validation/perf scripts, e.g.
 *   am start -n dev.minipcap/.ui.MainActivity --es cmd start --es variant E --ei snaplen 256
 * Commands: start, stop, stall (--ei ms), upload, server (--es url, --es token),
 * move (latest finalized pair), automove (--ez on). start also takes --es mode/pkgs,
 * --ez gps/radio/motion, --ei motion_hz, --es motion_mode ALL|MAX_RATE|THRESHOLD.
 * Release builds ignore these extras entirely.
 */
class DebugCommands(private val ui: MainActivity) {
    fun handle(i: Intent?) {
        if (!BuildConfig.DEBUG || i == null) return
        val cmd = i.getStringExtra("cmd") ?: return
        i.removeExtra("cmd")
        when (cmd) {
            "start" -> {
                var c = CaptureConfig.load(ui)
                i.getStringExtra("variant")?.let { v -> c = c.copy(variant = Variant.valueOf(v)) }
                if (i.hasExtra("snaplen")) c = c.copy(snaplen = i.getIntExtra("snaplen", CaptureConfig.DEFAULT_SNAPLEN))
                i.getStringExtra("mode")?.let { m -> c = c.copy(filterMode = FilterMode.valueOf(m)) }
                i.getStringExtra("pkgs")?.let { p -> c = c.copy(selectedPackages = p.split(',').filter { it.isNotBlank() }.toSet()) }
                var m = MeasurementConfig.load(ui)
                if (i.hasExtra("gps")) m = m.copy(gps = i.getBooleanExtra("gps", true))
                if (i.hasExtra("radio")) m = m.copy(radio = i.getBooleanExtra("radio", true))
                if (i.hasExtra("motion")) m = m.copy(motion = i.getBooleanExtra("motion", true))
                if (i.hasExtra("motion_hz")) m = m.copy(motionHz = i.getIntExtra("motion_hz", 50))
                i.getStringExtra("motion_mode")?.let { mm -> m = m.copy(motionMode = MotionMode.valueOf(mm)) }
                MeasurementConfig.save(ui, m)
                CaptureConfig.save(ui, c)
                ui.loadConfig()
                ui.onStartStop(automated = true)
            }
            "stop" -> Sessions.active?.let { CaptureVpnService.requestStop(ui, it.id) }
            "stall" -> ui.startService(Intent(ui, CaptureVpnService::class.java)
                .setAction(CaptureVpnService.ACTION_DEBUG_STALL)
                .putExtra(CaptureVpnService.EXTRA_STALL_MS, i.getIntExtra("ms", 1000)))
            "upload" -> ui.uploadLatest()
            "move" -> Sessions.store(ui).list().firstOrNull { Exports.mover(ui).eligible(it) }?.let { Exports.request(ui, it.id) }
            "automove" -> Exports.setAutoMove(ui, i.getBooleanExtra("on", true))
            "server" -> {
                val s = UploadSettings(ui)
                s.save(i.getStringExtra("url") ?: s.load().baseUrl, i.getBooleanExtra("wifi_only", false))
                if (i.hasExtra("token")) s.setToken(i.getStringExtra("token"))
            }
        }
    }
}
