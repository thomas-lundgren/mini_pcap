package dev.minipcap.upload

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class UploadServerConfig(val baseUrl: String, val wifiOnly: Boolean, val hasToken: Boolean)

/**
 * Upload server settings. The bearer token is encrypted with a non-exportable
 * AndroidKeyStore AES-GCM key; only ciphertext is stored in preferences. The token
 * is never logged, exported, or written into capture or metadata files.
 */
class UploadSettings(private val ctx: Context) {
    private val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun load() = UploadServerConfig(
        baseUrl = prefs.getString("base_url", "") ?: "",
        wifiOnly = prefs.getBoolean("wifi_only", false),
        hasToken = prefs.contains("token_ct"),
    )

    fun save(baseUrl: String, wifiOnly: Boolean) {
        prefs.edit().putString("base_url", baseUrl.trim()).putBoolean("wifi_only", wifiOnly).apply()
    }

    fun setToken(token: String?) {
        if (token.isNullOrEmpty()) {
            prefs.edit().remove("token_ct").apply()
            return
        }
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, key())
        val ct = c.doFinal(token.toByteArray(Charsets.UTF_8))
        val blob = c.iv + ct
        prefs.edit().putString("token_ct", Base64.encodeToString(blob, Base64.NO_WRAP)).apply()
    }

    /** Decrypts on demand for a request; returns null when no token is configured. */
    fun token(): String? {
        val b64 = prefs.getString("token_ct", null) ?: return null
        return try {
            val blob = Base64.decode(b64, Base64.NO_WRAP)
            val c = Cipher.getInstance(TRANSFORM)
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, 12))
            String(c.doFinal(blob, 12, blob.size - 12), Charsets.UTF_8)
        } catch (e: Exception) {
            null // key invalidated (e.g. restore): user must re-enter the token
        }
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build())
        return g.generateKey()
    }

    companion object {
        private const val PREFS = "upload_settings"
        private const val ALIAS = "upload_token_key"
        private const val TRANSFORM = "AES/GCM/NoPadding"

        /** HTTPS only; returns an error message or null when valid. */
        fun validateUrl(url: String): String? {
            val u = runCatching { java.net.URL(url.trim()) }.getOrNull() ?: return "Not a valid URL"
            if (u.protocol != "https") return "Only https:// servers are allowed"
            if (u.host.isNullOrEmpty()) return "Missing host"
            if (u.query != null || u.userInfo != null) return "URL must not contain credentials or query parameters"
            return null
        }
    }
}
