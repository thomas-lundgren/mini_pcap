package dev.minipcap.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import dev.minipcap.R
import dev.minipcap.capture.ClassRules
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
