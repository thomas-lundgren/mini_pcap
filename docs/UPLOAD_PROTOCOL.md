# Upload Protocol — Version 1 (proposed client/receiver contract)

**State:** v1 implemented (Android client + reference receiver) and tested — see `docs/TEST_RESULTS.md`  
**Target:** Configurable HTTPS server for user-triggered upload of complete Android PCAPNG captures.  
**MVP policy:** Upload only after logging has stopped and both artifacts are finalized. No automatic upload.

## Endpoints (illustrative — implement matching client + reference receiver)

| Operation | Request | Success | Purpose |
|---|---|---|---|
| Test connection | `GET /api/v1/health` | `200` with `{"status":"ok","protocol_version":1}` | Reachability, TLS and configured authorization test |
| Upload pair | `POST /api/v1/captures` | `201` with receipt; `200` on idempotent replay | Transfer a completed capture + metadata as one logical transaction |

- Base URL configured in Android settings, e.g. `https://receiver.example.org`. Resolve endpoints relative to this URL (preserve any deployment prefix consistently).
- All requests optionally carry `Authorization: Bearer <token>`, according to configured server policy. Never put token in query string.
- For the MVP, a bearer token is recommended even on a private receiver. Do not send captures over production HTTP; validate TLS certificates and hostname.
- Other error responses: `400` malformed request, `401/403` unauthorized, `409` conflicting existing capture ID/hashes, `413` body too large, `422` invalid paired metadata/digests, `429` rate limit, `5xx` server problem. Client shows meaningful errors, never logs credentials.

## Upload request

`Content-Type: multipart/form-data` (generated streaming boundary). Parts:

1. `manifest`: JSON `application/json`, see below.
2. `capture`: binary `application/octet-stream`, filename `<capture_id>.pcapng`.
3. `metadata`: JSON `application/json`, filename `<capture_id>.meta.json`.

Headers: `Idempotency-Key: <capture_id>` (uniquely identifies logical upload for one receiver; same key for retries). Use a capture ID that includes sufficient randomness or is collision-resistant across devices, not a sequential time-only ID. `X-Protocol-Version: 1` is optional if manifest includes protocol version.

Example manifest:

```json
{
  "protocol_version": 1,
  "capture_id": "7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47",
  "files": {
    "capture": {
      "filename": "7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47.pcapng",
      "size_bytes": 123456,
      "sha256": "<64-lowercase-hex-digits>"
    },
    "metadata": {
      "filename": "7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47.meta.json",
      "size_bytes": 2048,
      "sha256": "<64-lowercase-hex-digits>"
    }
  }
}
```

*The example is schematic; placeholder hashes are not valid protocol input.* Hash files in a bounded-memory streaming pass. Freeze file length and content between hashing and upload using a completed-session lock or stable immutable storage; verify an unchanged pair if needed.

## Receiver transaction

1. Authenticate request and apply server-side body size/retention/quota limits. Validate allowed capture ID, file names and declared sizes. Never trust incoming filenames as filesystem paths.
2. Stream file parts to a staging directory under the receiver's control with bounded memory; reject unexpected fields, duplicate parts, invalid lengths and oversized payloads.
3. Verify computed SHA-256 for both parts, that metadata `capture_id` and `capture_file` agree with the manifest, and that metadata `status` is `complete`. (Additional PCAPNG structural validation is recommended.)
4. Resolve `Idempotency-Key`: if same capture exists with identical hashes, return the existing receipt (`200`). If identity exists with conflicting hashes, reject with `409`, never overwrite silently.
5. Only after both files validate, promote the pair into one visible dataset and commit the server-side registry transaction. Orphans in staging remain invisible and may be garbage-collected.
6. Return receipt *only* after committed storage succeeds. Expose limits and retention policy; operator chooses physical storage, authentication rotation, TLS terminator and backups.

## Receipt

`201 Created` on first ingest; `200 OK` for a verified duplicate replay:

```json
{
  "protocol_version": 1,
  "capture_id": "7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47",
  "receipt_id": "srv-000001",
  "stored": true,
  "sha256": {
    "capture": "<64-lowercase-hex-digits>",
    "metadata": "<64-lowercase-hex-digits>"
  }
}
```

Client verifies the response capture ID and both returned digest values against locally computed digests. A successful HTTP status alone is insufficient. Persist receipt and upload attempt state in a local record **separate from** the capture sidecar.

## Android UI and scheduling

- Settings: Upload server URL, token, Wi-Fi-only toggle, **Test connection**, save. Store token via an Android Keystore-backed solution. Show useful status for TLS, DNS, auth and unreachable receiver.
- Capture screen: **Upload latest** uses the newest complete session by recorded finalization order; never `.partial` files. For MVP, disable while recording (or offer Stop, then upload as two explicit steps).
- Saved sessions: show status and allow upload/retry of a specific completed capture, in addition to the newest one.
- User initiation only. Status `NOT_UPLOADED → QUEUED → UPLOADING → SUCCEEDED` or `FAILED/CANCELED`, with retry for transient failures. Cancellation does not alter capture files. Preserve progress notification if Activity is closed.
- For large user-requested transfers, evaluate `JobScheduler` user-initiated transfer (API 34+) and WorkManager (API 29–33) on target devices; Android 16+ job quotas make blindly selecting long-running WorkManager workers risky.
- Idempotent replay is **not** resumable byte-range transfer. MVP restarts the HTTP request after interrupted upload; resumable/chunked protocol is a later optimization.

## Minimum receiver tests

- Valid paired payload => `201`, saved exact byte-for-byte PCAPNG + sidecar; receipt digests verified.
- Identical retry => `200` same receipt, one logical dataset.
- Same capture ID with different hashes => `409`, no overwrite.
- Missing/mismatched metadata, bad hashes, tampered capture ID => `422/400`, no visible dataset.
- Missing/invalid token => `401/403`; invalid TLS certificate rejected at client.
- Interrupted request/staging failure => no published orphan, deterministic retry.
- Oversize => `413`; malformed filenames/path traversal rejected.
- Full-size streaming test with bounded memory, followed by device-side UI/background/cancel tests.

## Explicit exclusions

No streaming live packets, automated cloud sync, remote deletion, in-app server administration, credential sharing, or exposing packet captures through unauthenticated GET. Deployment/setup documentation is required for the chosen reference receiver, but a hosted production server is not assumed.
