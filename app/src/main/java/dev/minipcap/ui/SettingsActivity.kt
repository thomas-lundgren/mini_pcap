package dev.minipcap.ui

import android.app.Activity
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import dev.minipcap.R
import dev.minipcap.capture.ClassRules
import dev.minipcap.capture.MeasurementConfig
import dev.minipcap.capture.MotionMode
import dev.minipcap.storage.ExportJobService
import dev.minipcap.storage.Exports
import dev.minipcap.upload.UploadClient
import dev.minipcap.upload.UploadException
import dev.minipcap.upload.UploadSettings

class SettingsActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        val settings = UploadSettings(this)
        val url = findViewById<EditText>(R.id.url)
        val token = findViewById<EditText>(R.id.token)
        val wifi = findViewById<CheckBox>(R.id.wifiOnly)
        val status = findViewById<TextView>(R.id.status)
        val rules = findViewById<EditText>(R.id.classRules)
        val cfg = settings.load()
        url.setText(cfg.baseUrl)
        wifi.isChecked = cfg.wifiOnly
        token.hint = getString(if (cfg.hasToken) R.string.token_stored else R.string.token_none)
        rules.setText(ClassRules.loadText(this))
        val mc = MeasurementConfig.load(this)
        val motionMode = findViewById<Spinner>(R.id.motionMode)
        motionMode.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Every sample", "Up to the sampling rate", "Only on change (threshold)"))
        motionMode.setSelection(mc.motionMode.ordinal)
        val motionHz = findViewById<EditText>(R.id.motionHz).apply { setText("${mc.motionHz}") }
        val motionThreshold = findViewById<EditText>(R.id.motionThreshold).apply { setText("${mc.motionThreshold}") }
        val gyro = findViewById<CheckBox>(R.id.gyro).apply { isChecked = mc.gyro }
        val gpsInterval = findViewById<EditText>(R.id.gpsInterval).apply { setText("${mc.gpsMinTimeMs}") }
        val gpsDistance = findViewById<EditText>(R.id.gpsDistance).apply { setText("${mc.gpsMinDistanceM}") }
        val radioRefresh = findViewById<EditText>(R.id.radioRefresh).apply { setText("${mc.radioRefreshMs}") }
        val autoMove = findViewById<CheckBox>(R.id.autoMove)
        autoMove.isChecked = Exports.autoMove(this)

        fun save(): Boolean {
            val u = url.text.toString().trim()
            if (u.isNotEmpty()) UploadSettings.validateUrl(u)?.let { status.text = it; return false }
            settings.save(u, wifi.isChecked)
            val t = token.text.toString()
            if (t.isNotEmpty()) {
                settings.setToken(t)
                token.setText("")
                token.hint = getString(R.string.token_stored)
            }
            ClassRules.saveText(this, rules.text.toString())
            val cur = MeasurementConfig.load(this)
            MeasurementConfig.save(this, cur.copy(
                motionMode = MotionMode.entries[motionMode.selectedItemPosition],
                motionHz = motionHz.text.toString().toIntOrNull()?.coerceIn(1, 1000) ?: cur.motionHz,
                motionThreshold = motionThreshold.text.toString().toFloatOrNull()?.coerceAtLeast(0f) ?: cur.motionThreshold,
                gyro = gyro.isChecked,
                gpsMinTimeMs = gpsInterval.text.toString().toLongOrNull()?.coerceAtLeast(100) ?: cur.gpsMinTimeMs,
                gpsMinDistanceM = gpsDistance.text.toString().toFloatOrNull()?.coerceAtLeast(0f) ?: cur.gpsMinDistanceM,
                radioRefreshMs = radioRefresh.text.toString().toLongOrNull()?.coerceAtLeast(500) ?: cur.radioRefreshMs))
            if (autoMove.isChecked != Exports.autoMove(this)) {
                Exports.setAutoMove(this, autoMove.isChecked)
                if (autoMove.isChecked) ExportJobService.schedule(this)
            }
            return true
        }

        findViewById<Button>(R.id.save).setOnClickListener {
            if (save()) Toast.makeText(this, R.string.saved, Toast.LENGTH_SHORT).show()
        }
        findViewById<Button>(R.id.clearToken).setOnClickListener {
            settings.setToken(null)
            token.hint = getString(R.string.token_none)
            status.text = getString(R.string.token_cleared)
        }
        findViewById<Button>(R.id.test).setOnClickListener {
            if (!save()) return@setOnClickListener
            val c = settings.load()
            if (c.baseUrl.isEmpty()) {
                status.text = getString(R.string.no_server)
                return@setOnClickListener
            }
            status.text = getString(R.string.testing)
            Thread {
                val msg = try {
                    UploadClient(c.baseUrl, settings.token()).testConnection()
                } catch (e: UploadException) {
                    "Failed: ${e.userMessage}"
                } catch (e: Exception) {
                    "Failed: ${e.javaClass.simpleName}"
                }
                runOnUiThread { status.text = msg }
            }.start()
        }
    }
}
