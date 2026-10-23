package dev.minipcap

import dev.minipcap.upload.FileDigest
import dev.minipcap.upload.UploadClient
import dev.minipcap.upload.UploadException
import dev.minipcap.upload.UploadSettings
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.security.MessageDigest

class UploadClientTest {
    @Test
    fun sha256MatchesReference() {
        val f = Files.createTempFile("d", ".bin").toFile()
        val data = ByteArray(200_000) { (it * 31).toByte() }
        f.writeBytes(data)
        val d = UploadClient.sha256(f)
        val ref = MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
        assertEquals(ref, d.sha256)
        assertEquals(data.size.toLong(), d.size)
    }

    @Test
    fun multipartLengthIsExactAndProgressReachesTotal() {
        val dir = Files.createTempDirectory("mp").toFile()
        val pcap = dir.resolve("a.pcap").apply { writeBytes(TestCapture.pcap(100)) }
        val meta = dir.resolve("a.meta").apply { writeText("{\"x\":1}") }
        val parts = listOf(
            UploadClient.Part("manifest", null, "application/json", "{}".toByteArray(), null),
            UploadClient.Part("capture", pcap.name, "application/octet-stream", null, dev.minipcap.core.PrivateFile(pcap)),
            UploadClient.Part("metadata", meta.name, "application/json", null, dev.minipcap.core.PrivateFile(meta)))
        val total = UploadClient.multipartLength("B0UND", parts)
        val out = ByteArrayOutputStream()
        var last = 0L
        UploadClient.writeMultipart(out, "B0UND", parts, total, { s, t -> last = s; assertEquals(total, t) }, { false })
        assertEquals(total, out.size().toLong())
        assertEquals(total, last)
        val text = out.toString(Charsets.ISO_8859_1.name())
        assertTrue(text.startsWith("--B0UND\r\nContent-Disposition: form-data; name=\"manifest\""))
        assertTrue(text.endsWith("\r\n--B0UND--\r\n"))
    }

    @Test
    fun cancellationStopsStreaming() {
        val dir = Files.createTempDirectory("mp").toFile()
        val big = dir.resolve("b.pcap").apply { writeBytes(ByteArray(2_000_000)) }
        val parts = listOf(UploadClient.Part("capture", big.name, "application/octet-stream", null, dev.minipcap.core.PrivateFile(big)))
        var n = 0
        try {
            UploadClient.writeMultipart(ByteArrayOutputStream(), "B", parts, 0, { _, _ -> }, { ++n > 5 })
            fail("expected cancellation")
        } catch (e: dev.minipcap.upload.UploadCancelled) {
        }
    }

    @Test
    fun receiptMustMatchIdAndBothDigests() {
        val p = FileDigest("x.pcapng", 10, "a".repeat(64))
        val m = FileDigest("x.meta.json", 5, "b".repeat(64))
        fun receipt(id: String = "id1", cap: String = p.sha256, meta: String = m.sha256, stored: Boolean = true) =
            JSONObject().put("protocol_version", UploadClient.PROTOCOL_VERSION).put("capture_id", id).put("receipt_id", "srv-1").put("stored", stored)
                .put("sha256", JSONObject().put("capture", cap).put("metadata", meta)).toString()
        assertEquals("srv-1", UploadClient.verifyReceipt(receipt(), "id1", p, m, 201).receiptId)
        assertTrue(UploadClient.verifyReceipt(receipt(), "id1", p, m, 200).replay)
        for (bad in listOf(receipt(id = "other"), receipt(cap = "c".repeat(64)), receipt(meta = "c".repeat(64)),
            receipt(stored = false), "not json", "{}")) {
            try {
                UploadClient.verifyReceipt(bad, "id1", p, m, 201)
                fail("accepted bad receipt: $bad")
            } catch (e: UploadException) {
            }
        }
    }

    @Test
    fun httpErrorsMapToActionableRetryClasses() {
        assertFalse(UploadClient.httpError(401, "").retryable)
        assertTrue(UploadClient.httpError(401, "").userMessage.contains("token"))
        assertFalse(UploadClient.httpError(409, "").retryable)
        assertFalse(UploadClient.httpError(413, "").retryable)
        assertFalse(UploadClient.httpError(422, "{\"error\":\"sha256 mismatch\"}").retryable)
        assertTrue(UploadClient.httpError(422, "{\"error\":\"sha256 mismatch\"}").userMessage.contains("sha256 mismatch"))
        assertTrue(UploadClient.httpError(429, "").retryable)
        assertTrue(UploadClient.httpError(503, "").retryable)
    }

    @Test
    fun onlyHttpsUrlsWithoutSecretsAreAccepted() {
        assertNull(UploadSettings.validateUrl("https://receiver.example.org"))
        assertNull(UploadSettings.validateUrl("https://192.168.1.10:8443/prefix"))
        assertNotNull(UploadSettings.validateUrl("http://receiver.example.org"))
        assertNotNull(UploadSettings.validateUrl("https://user:pw@receiver.example.org"))
        assertNotNull(UploadSettings.validateUrl("https://receiver.example.org/?token=x"))
        assertNotNull(UploadSettings.validateUrl("not a url"))
    }

    @Test
    fun manifestShape() {
        val o = UploadClient.manifest("id", FileDigest("id.pcapng", 3, "a".repeat(64)), FileDigest("id.meta.json", 4, "b".repeat(64)))
        assertEquals(2, o.getInt("protocol_version"))
        assertEquals("id.pcapng", o.getJSONObject("files").getJSONObject("capture").getString("filename"))
        assertEquals(4, o.getJSONObject("files").getJSONObject("metadata").getLong("size_bytes"))
    }
}
