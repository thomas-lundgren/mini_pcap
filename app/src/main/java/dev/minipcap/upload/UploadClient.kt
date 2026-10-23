package dev.minipcap.upload

import dev.minipcap.core.CaptureFile
import dev.minipcap.core.PrivateFile
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

class UploadException(val userMessage: String, val retryable: Boolean, val httpStatus: Int = 0) : Exception(userMessage)
class UploadCancelled : Exception("canceled")

data class FileDigest(val name: String, val size: Long, val sha256: String)
data class UploadReceipt(val receiptId: String, val httpStatus: Int, val replay: Boolean)

/** Upload protocol client (docs/UPLOAD_PROTOCOL.md). Pure java.net; no Android dependencies. */
class UploadClient(private val baseUrl: String, private val token: String?) {

    private fun endpoint(path: String): URL {
        val b = baseUrl.trimEnd('/')
        return URL("$b$path")
    }

    private fun open(url: URL): HttpURLConnection {
        val c = url.openConnection() as HttpURLConnection
        if (c !is HttpsURLConnection) throw UploadException("Only HTTPS is allowed", false)
        c.connectTimeout = 15_000
        c.readTimeout = 60_000
        c.instanceFollowRedirects = false
        if (!token.isNullOrEmpty()) c.setRequestProperty("Authorization", "Bearer $token")
        c.setRequestProperty("X-Protocol-Version", "$PROTOCOL_VERSION")
        return c
    }

    /** GET /api/v1/health; returns a short status message on success. */
    fun testConnection(): String = withErrors {
        val c = open(endpoint("/api/v1/health"))
        try {
            val code = c.responseCode
            val body = readBody(c, code)
            if (code != 200) throw httpError(code, body)
            val o = runCatching { JSONObject(body) }.getOrNull()
                ?: throw UploadException("Server reply is not protocol JSON", false, code)
            if (o.optString("status") != "ok" || o.optInt("protocol_version") != PROTOCOL_VERSION)
                throw UploadException("Server does not speak upload protocol v$PROTOCOL_VERSION", false, code)
            "Connected: protocol v$PROTOCOL_VERSION, authorized"
        } finally {
            c.disconnect()
        }
    }

    fun upload(
        captureId: String, pcap: File, meta: File, pcapDigest: FileDigest, metaDigest: FileDigest,
        onProgress: (sent: Long, total: Long) -> Unit, cancelled: () -> Boolean,
    ): UploadReceipt = upload(captureId, PrivateFile(pcap), PrivateFile(meta), pcapDigest, metaDigest, onProgress, cancelled)

    /**
     * Streams the pair in one multipart request with bounded buffers. Success only
     * after the receipt matches capture ID and both locally computed digests.
     */
    fun upload(
        captureId: String,
        pcap: CaptureFile,
        meta: CaptureFile,
        pcapDigest: FileDigest,
        metaDigest: FileDigest,
        onProgress: (sent: Long, total: Long) -> Unit,
        cancelled: () -> Boolean,
    ): UploadReceipt = withErrors {
        // Preflight: surface auth/TLS/protocol errors before streaming a large body (a
        // receiver rejecting early would otherwise show up as a broken pipe mid-upload).
        testConnection()
        val boundary = "mpc-" + java.util.UUID.randomUUID().toString().replace("-", "")
        val manifest = manifest(captureId, pcapDigest, metaDigest).toString().toByteArray(Charsets.UTF_8)
        val parts = listOf(
            Part("manifest", null, "application/json", manifest, null),
            Part("capture", pcapDigest.name, "application/octet-stream", null, pcap),
            Part("metadata", metaDigest.name, "application/octet-stream", null, meta),
        )
        val total = multipartLength(boundary, parts)
        val c = open(endpoint("/api/v1/captures"))
        try {
            c.requestMethod = "POST"
            c.doOutput = true
            c.setFixedLengthStreamingMode(total)
            c.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
            c.setRequestProperty("Idempotency-Key", captureId)
            c.outputStream.use { out -> writeMultipart(out, boundary, parts, total, onProgress, cancelled) }
            val code = c.responseCode
            val body = readBody(c, code)
            if (code != 200 && code != 201) throw httpError(code, body)
            verifyReceipt(body, captureId, pcapDigest, metaDigest, code)
        } finally {
            c.disconnect()
        }
    }

    class Part(val field: String, val filename: String?, val type: String, val bytes: ByteArray?, val file: CaptureFile?) {
        fun size(): Long = bytes?.size?.toLong() ?: file!!.length()
        fun header(boundary: String): ByteArray {
            val disp = if (filename != null) "form-data; name=\"$field\"; filename=\"$filename\"" else "form-data; name=\"$field\""
            return "--$boundary\r\nContent-Disposition: $disp\r\nContent-Type: $type\r\n\r\n".toByteArray(Charsets.UTF_8)
        }
    }

    companion object {
        /** v2: `<id>.pcap` (Linux SLL) + binary `<id>.meta` (docs/UPLOAD_PROTOCOL.md). */
        const val PROTOCOL_VERSION = 2

        fun sha256(f: File): FileDigest = sha256(PrivateFile(f))

        fun sha256(f: CaptureFile): FileDigest {
            val md = MessageDigest.getInstance("SHA-256")
            val buf = ByteArray(64 * 1024)
            var size = 0L
            f.open().use { inp ->
                while (true) {
                    val n = inp.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                    size += n
                }
            }
            return FileDigest(f.name, size, md.digest().joinToString("") { "%02x".format(it) })
        }

        fun manifest(id: String, p: FileDigest, m: FileDigest): JSONObject = JSONObject()
            .put("protocol_version", PROTOCOL_VERSION)
            .put("capture_id", id)
            .put("files", JSONObject()
                .put("capture", JSONObject().put("filename", p.name).put("size_bytes", p.size).put("sha256", p.sha256))
                .put("metadata", JSONObject().put("filename", m.name).put("size_bytes", m.size).put("sha256", m.sha256)))

        fun multipartLength(boundary: String, parts: List<Part>): Long =
            parts.sumOf { it.header(boundary).size + it.size() + 2 } + "--$boundary--\r\n".length

        fun writeMultipart(
            out: OutputStream, boundary: String, parts: List<Part>, total: Long,
            onProgress: (Long, Long) -> Unit, cancelled: () -> Boolean,
        ) {
            var sent = 0L
            var lastReport = 0L
            val buf = ByteArray(64 * 1024)
            fun emit(b: ByteArray, off: Int, len: Int) {
                if (cancelled()) throw UploadCancelled()
                out.write(b, off, len)
                sent += len
                if (sent - lastReport >= 256 * 1024 || sent == total) {
                    lastReport = sent
                    onProgress(sent, total)
                }
            }
            for (p in parts) {
                val h = p.header(boundary)
                emit(h, 0, h.size)
                if (p.bytes != null) {
                    emit(p.bytes, 0, p.bytes.size)
                } else {
                    // The file must not change after hashing: a size check catches truncation/growth.
                    var remaining = p.file!!.length()
                    p.file!!.open().use { inp ->
                        while (remaining > 0) {
                            val n = inp.read(buf, 0, minOf(buf.size.toLong(), remaining).toInt())
                            if (n < 0) throw IOException("file shrank during upload")
                            emit(buf, 0, n)
                            remaining -= n
                        }
                    }
                }
                emit("\r\n".toByteArray(), 0, 2)
            }
            val end = "--$boundary--\r\n".toByteArray()
            emit(end, 0, end.size)
            out.flush()
        }

        fun verifyReceipt(body: String, id: String, p: FileDigest, m: FileDigest, code: Int): UploadReceipt {
            val o = runCatching { JSONObject(body) }.getOrNull()
                ?: throw UploadException("Receipt is not valid JSON", true, code)
            val sha = o.optJSONObject("sha256")
            if (o.optInt("protocol_version") != PROTOCOL_VERSION || o.optString("capture_id") != id || !o.optBoolean("stored") ||
                sha == null || sha.optString("capture") != p.sha256 || sha.optString("metadata") != m.sha256)
                throw UploadException("Receipt does not match local capture/hashes", false, code)
            val rid = o.optString("receipt_id")
            if (rid.isEmpty()) throw UploadException("Receipt missing receipt_id", false, code)
            return UploadReceipt(rid, code, code == 200)
        }

        fun httpError(code: Int, body: String): UploadException {
            val detail = runCatching { JSONObject(body).optString("error") }.getOrNull().orEmpty().take(120)
            val msg = when (code) {
                400 -> "Server rejected the request (400)"
                401, 403 -> "Not authorized ($code): check the API token"
                409 -> "Server already holds a different capture with this ID (409)"
                413 -> "Capture is too large for the server (413)"
                422 -> "Server rejected metadata or digests (422)"
                429 -> "Server rate limit (429): retry later"
                in 500..599 -> "Server error ($code): retry later"
                in 300..399 -> "Unexpected redirect ($code)"
                else -> "Unexpected HTTP status $code"
            }
            val retry = code == 429 || code in 500..599
            return UploadException(if (detail.isNotEmpty()) "$msg — $detail" else msg, retry, code)
        }

        private fun readBody(c: HttpURLConnection, code: Int): String {
            val s = (if (code >= 400) c.errorStream else c.inputStream) ?: return ""
            return s.use { it.readBytes().take(64 * 1024).toByteArray().toString(Charsets.UTF_8) }
        }

        private inline fun <T> withErrors(block: () -> T): T = try {
            block()
        } catch (e: UploadException) {
            throw e
        } catch (e: UploadCancelled) {
            throw e
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            throw UploadException("TLS certificate does not match the server name", false)
        } catch (e: SSLHandshakeException) {
            throw UploadException("TLS certificate not trusted or handshake failed", false)
        } catch (e: SSLException) {
            throw UploadException("TLS error: connection not secure", true)
        } catch (e: UnknownHostException) {
            throw UploadException("Server not found (DNS)", true)
        } catch (e: ConnectException) {
            throw UploadException("Server unreachable", true)
        } catch (e: SocketTimeoutException) {
            throw UploadException("Connection timed out", true)
        } catch (e: IOException) {
            throw UploadException("Network error: ${e.javaClass.simpleName}", true)
        }
    }
}
