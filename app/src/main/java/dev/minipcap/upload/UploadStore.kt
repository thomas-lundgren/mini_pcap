package dev.minipcap.upload

import dev.minipcap.storage.SessionStore
import org.json.JSONObject
import java.io.File

enum class UploadStatus { NOT_UPLOADED, QUEUED, UPLOADING, SUCCEEDED, FAILED, CANCELED }

data class UploadRecord(
    val captureId: String,
    val status: UploadStatus = UploadStatus.NOT_UPLOADED,
    val attempts: Int = 0,
    val bytesSent: Long = 0,
    val bytesTotal: Long = 0,
    val receiptId: String? = null,
    val httpStatus: Int = 0,
    val lastError: String? = null,
    val captureSha256: String? = null,
    val metadataSha256: String? = null,
    val updatedMs: Long = 0,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("capture_id", captureId).put("status", status.name).put("attempts", attempts)
        .put("bytes_sent", bytesSent).put("bytes_total", bytesTotal)
        .put("receipt_id", receiptId ?: JSONObject.NULL).put("http_status", httpStatus)
        .put("last_error", lastError ?: JSONObject.NULL)
        .put("capture_sha256", captureSha256 ?: JSONObject.NULL)
        .put("metadata_sha256", metadataSha256 ?: JSONObject.NULL)
        .put("updated_ms", updatedMs)

    companion object {
        fun fromJson(o: JSONObject) = UploadRecord(
            captureId = o.getString("capture_id"),
            status = UploadStatus.valueOf(o.getString("status")),
            attempts = o.optInt("attempts"),
            bytesSent = o.optLong("bytes_sent"),
            bytesTotal = o.optLong("bytes_total"),
            receiptId = o.optString("receipt_id").takeUnless { o.isNull("receipt_id") },
            httpStatus = o.optInt("http_status"),
            lastError = o.optString("last_error").takeUnless { o.isNull("last_error") },
            captureSha256 = o.optString("capture_sha256").takeUnless { o.isNull("capture_sha256") },
            metadataSha256 = o.optString("metadata_sha256").takeUnless { o.isNull("metadata_sha256") },
            updatedMs = o.optLong("updated_ms"),
        )
    }
}

/** Local upload state, stored separately from the immutable sidecar. */
class UploadStore(private val dir: File) {
    private fun file(id: String) = File(dir, "$id.upload.json")

    @Synchronized
    fun get(id: String): UploadRecord =
        file(id).takeIf { it.exists() }?.let { runCatching { UploadRecord.fromJson(JSONObject(it.readText())) }.getOrNull() }
            ?: UploadRecord(id)

    @Synchronized
    fun update(id: String, f: (UploadRecord) -> UploadRecord): UploadRecord {
        val r = f(get(id)).copy(updatedMs = System.currentTimeMillis())
        SessionStore.writeAtomic(file(id), r.toJson().toString(2))
        return r
    }

    /** After process death an in-flight record cannot still be running. */
    @Synchronized
    fun reconcileInterrupted(id: String, jobPending: Boolean) {
        val r = get(id)
        if (!jobPending && (r.status == UploadStatus.UPLOADING || r.status == UploadStatus.QUEUED))
            update(id) { it.copy(status = UploadStatus.FAILED, lastError = "Interrupted (app or device restarted) — Retry") }
    }
}
