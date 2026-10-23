package dev.minipcap

import dev.minipcap.upload.UploadClient
import dev.minipcap.upload.UploadException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.net.ServerSocket
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Cross-implementation test: the Kotlin client against the independent Python
 * reference receiver over real TLS (test CA). Skipped when python3/certs are absent.
 */
class UploadIntegrationTest {
    private val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "validation").isDirectory }
    private val srvDir = File(root, "validation/upload-server")
    private lateinit var proc: Process
    private lateinit var data: File
    private var port = 0
    private val token = "itest-" + UUID.randomUUID()

    @Before
    fun start() {
        assumeTrue(File(srvDir, "certs/server.key").exists())
        assumeTrue(runCatching { ProcessBuilder("python3", "--version").start().waitFor() == 0 }.getOrDefault(false))
        port = ServerSocket(0).use { it.localPort }
        data = Files.createTempDirectory("recv").toFile()
        val tok = File(data, "token.txt").apply { writeText(token) }
        proc = ProcessBuilder("python3", "-I", File(srvDir, "receiver.py").path, "--host", "127.0.0.1", "--port", "$port",
            "--cert", File(srvDir, "certs/server.pem").path, "--key", File(srvDir, "certs/server.key").path,
            "--data", File(data, "store").path, "--token-file", tok.path, "--max-bytes", "${64 shl 20}")
            .redirectErrorStream(true).redirectOutput(File(data, "server.log")).start()
        val cf = CertificateFactory.getInstance("X.509")
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("test-ca", File(srvDir, "certs/ca.pem").inputStream().use { cf.generateCertificate(it) })
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        HttpsURLConnection.setDefaultSSLSocketFactory(SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }.socketFactory)
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            if (runCatching { java.net.Socket("127.0.0.1", port).close() }.isSuccess) return
            Thread.sleep(100)
        }
        fail("receiver did not start")
    }

    @After
    fun stop() {
        if (::proc.isInitialized) proc.destroy()
    }

    private fun pair(id: String, pcapBytes: ByteArray): Pair<File, File> {
        val d = Files.createTempDirectory("pair").toFile()
        val p = File(d, "$id.pcap").apply { writeBytes(pcapBytes) }
        val m = File(d, "$id.meta")
        TestCapture.meta(m, id) // written by the app's own MetaWriter
        return p to m
    }

    @Test
    fun healthUploadReplayConflictAndAuth() {
        val base = "https://127.0.0.1:$port"
        assertTrue(UploadClient(base, token).testConnection().contains("protocol v2"))
        try {
            UploadClient(base, "wrong").testConnection()
            fail()
        } catch (e: UploadException) {
            assertEquals(401, e.httpStatus)
        }

        val id = UUID.randomUUID().toString()
        val bytes = TestCapture.pcap(20_000) // ~3.4 MB
        val (p, m) = pair(id, bytes)
        val pd = UploadClient.sha256(p)
        val md = UploadClient.sha256(m)
        var progressed = 0L
        val r1 = UploadClient(base, token).upload(id, p, m, pd, md, { s, _ -> progressed = s }, { false })
        assertEquals(201, r1.httpStatus)
        assertFalse(r1.replay)
        assertTrue(progressed > bytes.size)
        // Server holds byte-identical artifacts under the capture ID.
        val stored = File(data, "store/captures/$id")
        assertArrayEquals(bytes, File(stored, "$id.pcap").readBytes())
        assertArrayEquals(m.readBytes(), File(stored, "$id.meta").readBytes())

        // Retry of the same capture: idempotent replay with the same receipt.
        val r2 = UploadClient(base, token).upload(id, p, m, pd, md, { _, _ -> }, { false })
        assertEquals(200, r2.httpStatus)
        assertEquals(r1.receiptId, r2.receiptId)

        // Same capture ID with different content: 409, never overwritten.
        val (p2, m2) = pair(id, TestCapture.pcap(3))
        try {
            UploadClient(base, token).upload(id, p2, m2, UploadClient.sha256(p2), UploadClient.sha256(m2), { _, _ -> }, { false })
            fail()
        } catch (e: UploadException) {
            assertEquals(409, e.httpStatus)
        }
        assertArrayEquals(bytes, File(stored, "$id.pcap").readBytes())

        // Digest that does not match the content: 422 and no dataset.
        val id3 = UUID.randomUUID().toString()
        val (p3, m3) = pair(id3, TestCapture.pcap(5))
        val wrong = UploadClient.sha256(p3).copy(sha256 = "0".repeat(64))
        try {
            UploadClient(base, token).upload(id3, p3, m3, wrong, UploadClient.sha256(m3), { _, _ -> }, { false })
            fail()
        } catch (e: UploadException) {
            assertEquals(422, e.httpStatus)
        }
        assertFalse(File(data, "store/captures/$id3").exists())
    }

    @Test
    fun untrustedServerIsRejectedByClient() {
        // Default (system) trust only: the test CA is not trusted -> TLS failure, not success.
        HttpsURLConnection.setDefaultSSLSocketFactory(SSLContext.getDefault().socketFactory)
        try {
            UploadClient("https://127.0.0.1:$port", token).testConnection()
            fail()
        } catch (e: UploadException) {
            assertTrue(e.userMessage, e.userMessage.contains("TLS"))
        }
    }
}
