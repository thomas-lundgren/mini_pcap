# Android Lightweight PCAPNG Logger — Agentic Implementation Plan

**Document version:** 1.2 (low-overhead native capture architecture + benchmark gates)  
**Created:** 2026-10-22  
**Project stage:** Planning — no implementation or device validation claimed  
**Primary target:** Android 10+ (API 29+), no root  
**Implementation language:** Kotlin for Android lifecycle/UI/UID API/uploads; C/C++ NDK for hot-path capture, flow cache, packet serialization and preferably forwarding integration. Select a proven forwarding engine after the M1 spike; record any deviation from native hot-path processing with performance evidence  
**Primary output:** `<capture_id>.pcapng` + `<capture_id>.meta.json`; optional on-demand HTTPS upload of the latest completed capture pair

## 0. Mission and acceptance definition

Build a lightweight, PCAPdroid-inspired Android network logger. Capture a configurable prefix of each IP packet with its time, original length, direction and Android application UID **where known**, or stable flow ID to support retrospective UID attribution. Persist a valid PCAPNG file continuously; on a controlled Stop operation, finalize a JSON sidecar mapping encountered UIDs to package identities, human-readable names, and configurable application/traffic **classes**. Support per-application filtering. Run as a user-visible foreground VPN service with an **ongoing notification showing capture status and a Stop logging action** that works when the main Activity is closed. Provide configurable remote upload-server settings and a user-triggered **Upload latest capture** action, transferring the finalized PCAPNG **together with its matching sidecar**, with progress and failure/retry handling.

**Performance is a first-class acceptance criterion:** quantify the incremental cost of logging *above* VPN forwarding, not only the combined VPN cost. A forwarding-only build, prefix-copy-only build, PCAPNG build and full-metadata build must be benchmarkable independently. The capture path must not allocate per packet, call Kotlin/JNI per packet, query Android UID APIs per packet, format strings, or perform synchronous filesystem I/O. All deviations require measured justification.

**Definition of done for MVP:** A selected real Android application can use the network normally through a no-root VPN capture, TCP and UDP can be attributed when the OS exposes a UID, captures open in Wireshark/tshark, the sidecar is joinable with packet UIDs, application filtering works, Stop in the notification consistently finalizes both files, and a user can configure an HTTPS server and upload the latest finalized capture pair with a verified server receipt. No unsupported assertion of measured accuracy or overhead.

### Immutable principles

1. Capture is passive from the application's perspective; never intentionally alter application payloads for measurement.
2. Never block packet forwarding on slow filesystem operations, UID/package lookups, UI, upload or telemetry. Capture may drop records under overload but must expose measured loss separately from forwarding errors.
3. Keep the packet hot path native and bounded: reuse buffers, parse only necessary headers, use cached flow identity, enqueue a truncated prefix and continue. No per-packet JNI, JVM allocation, log messages, system-service lookup, disk write or SHA-256.
4. Capture **at the VPN TUN boundary**, document that this is not the physical radio/air interface.
5. Treat unknown UIDs, dropped log records, malformed IP packets, and abnormal shutdown as explicit measurable states.
6. Keep the data pipeline and transport/forwarding engine replaceable.
7. Start small: no TLS interception, payload decoding, remote VPN server, DPI, accessibility/visibility service, or root-only features in MVP.
8. Use an **app-private spool** for active sessions; export two finalized artifacts via Android-compatible sharing/Storage Access Framework (SAF).
9. Upload only **complete, immutable, paired** artifacts; never send `.partial` files. A user action initiates transfer, not a capture Stop or periodic background upload.
10. Never silently discard local data after upload; remote completion is separate from local capture finalization.

## 1. Functional requirements and boundaries

| ID | Requirement | Priority | Acceptance evidence |
|---|---|---|---|
| FR-01 | User grants Android VPN permission and starts/stops capture | Must | Device start/stop video or test log |
| FR-02 | Continuous valid PCAPNG output, raw IPv4/IPv6 packet capture | Must | tshark parser + fixture tests |
| FR-03 | Timestamp every observed packet; store captured/original lengths | Must | Binary fixture assertions |
| FR-04 | Configurable snaplen: 64/128/256/512/full; default **256 B** | Must | Parameterized truncation tests |
| FR-05 | Per-packet UID for eligible TCP/UDP connections, unknown otherwise | Must | Known-test-app and ambiguous-UID cases |
| FR-06 | Uplink/downlink indicator for each logged packet | Must | Directional validation |
| FR-07 | UID → packages, app labels, configured class in JSON sidecar | Must | Sidecar schema validation, Wireshark correlation |
| FR-08 | Filter mode All / Include selected / Exclude selected | Must | Cross-app tests, empty-allowlist safeguard |
| FR-09 | Searchable installed-app selector and saved filter settings | Must | UI tests, package visibility review |
| FR-10 | Foreground notification: active status, duration, bytes/packets; **Stop logging** | Must | Android device test with UI closed |
| FR-11 | Stop drains logger, closes PCAPNG, writes sidecar, removes foreground service | Must | Stop stress test and idempotency test |
| FR-12 | No-root traffic forwarding with TCP/UDP/DNS, IPv4/IPv6 | Must | Connectivity and throughput tests |
| FR-13 | Crash recovery for partially finalized sessions | Must | Process-kill / disk-full recovery |
| FR-14 | Export/share capture and sidecar together | Must | Two-file share or zip export test |
| FR-15 | Counters for UID misses, capture-queue drops, storage failures | Must | Synthetic failure tests |
| FR-16 | Optional per-packet extra metadata extensibility | Design now; implement later | Stable internal `PacketMeta` schema |
| FR-17 | Configurable upload server URL and authorization credential, persistent across launches | Must | Settings + restart + TLS/auth validation tests |
| FR-18 | **Upload latest capture** from the application, choosing the newest **COMPLETE** session | Must | End-to-end with two finalized files and server receipt |
| FR-19 | Upload PCAPNG **and matching sidecar** as one logical transaction | Must | Receipt, matching capture ID, hashes and rejected partial tests |
| FR-20 | Upload progress, success/failure, cancellation and retry without duplicate server datasets | Must | UI + simulated interruption/resume tests |
| FR-21 | Explicit privacy/transfer safeguards, HTTPS certificate validation and protected secrets | Must | Negative security tests, no packet/credential data in logs |
| FR-22 | Test server connection and report configured server status | Must | Authenticated health check and specific failure messages |
| FR-23 | Reference upload receiver or mock server for integration testing | Must | Automated upload integration suite + protocol document |
| FR-24 | Native low-allocation packet hot path, not Kotlin-per-packet | Must | Allocation/JNI trace and source review; device profiling |
| FR-25 | Independently benchmark baseline, VPN-only, copy-only, writer, UID and full system | Must | Reproducible benchmark fixtures and results by variant |
| FR-26 | Buffered sequential writes from bounded preallocated capture queue; drops independently measured | Must | Slow-disk injection, queue-occupancy and log-loss tests |
| FR-27 | Flow ID on *every* record for retrospective UID join; async UID lookup and bounded caching | Must | First-packet and short-flow UID resolution tests |
| FR-28 | Minimal-rate notification/telemetry and no uploading during active capture | Must | Notification frequency traces and capture/transfer isolation |
| FR-29 | Expose capture-point semantics and separate log-vs-forward packet loss | Must | Paired VPN-only and full-pipeline measurement report |

### Non-goals for MVP

- Exactly reconstructing packets transmitted by the cellular modem or recording radio timestamps.
- Capturing traffic from apps routed outside the VPN by native application filters.
- Full network-stack implementation from scratch **unless** the forwarding spike proves it necessary.
- Inference of application categories from traffic content; `class` is configurable data, not an Android API property.
- Supporting VPN-over-VPN simultaneously. Android generally permits one active VpnService per user/profile.
- Live user-facing packet decoding, firewall rules, TLS decryption, or media-specific analysis.
- Automatic cloud backup, scheduled uploads, and deleting captures after successful upload.
- Streaming packets to the server during capture or uploading an active `.partial` capture.
- Server-side packet classification, dashboards, or a multi-tenant cloud platform (a minimal receiver is sufficient).

## 2. Architecture

```text
                 Kotlin / Android control plane
   App picker & VPN filters | notification Stop | settings
   UID resolver worker     | saved sessions    | uploader
                              |
                 JNI at START / STOP / sparse control only
                              |
            Native C/C++ (NDK) packet data plane
   VpnService TUN fd --read--> native timestamp + fast parse
                                |                |
                   immediate forwarding       capture tap
                   via validated native       cached flow UID
                   TCP/UDP adapter             + flow ID
                                |                |
                   protected sockets       copy <= snaplen
                                               |
                                     bounded preallocated queue
                                               |
                                      dedicated PCAPNG writer
                                      batched sequential I/O
                                               |
                                   <capture_id>.pcapng.partial

   Native flow table <---- async UID results from Kotlin worker
         |                              |
         +------> checkpoint registry -> sidecar at Stop

   Stop notification -> ordered native drain/finalize -> COMPLETE
   Upload latest -> *only after Stop* -> streaming HTTPS pair
```


**Capture point and implementation:** Transfer the TUN FD to native code once (using the SDK-supported file-descriptor ownership pattern, e.g. `ParcelFileDescriptor.detachFd()`), and pass control/configuration over JNI only at lifecycle boundaries or in bounded batches. **Do not cross JNI per packet.** For UL, record when a packet is read from TUN, before forwarding. For DL, record the IP packet that is written/injected into TUN, before write. Timestamp semantics must be explicit in metadata. If the forwarding engine synthesizes return packets or terminates TCP connections, disclose this in session metadata; these are not necessarily the same packet boundaries as on the mobile radio.

### Proposed package/module structure (adjust only with recorded rationale)

```text
app/
  ui/                 Capture screen, app picker, saved sessions
  service/            CaptureVpnService, NotificationController, StopReceiver
  settings/           CaptureConfig, app filters, persistence
  storage/            SessionStore, export/share, recovery
  upload/             UploadSettings, UploadCoordinator, HTTPS client, receipt store
capture-core/
  packet/             IP parser, 5-tuple, direction, snaplen
  attribution/        AndroidUidResolver, FlowUidCache, PackageRegistry
  pcapng/             PCAPNG writer, binary test fixtures
  sessions/           CaptureSession, writer queue, session state
native/                NDK C/C++ engine + native unit tests
  tun/                FD ownership, read/inject, timestamp, capture hooks
  flow/               Fast parser, normalized flow keys, flow-ID cache
  ring/               Reusable packet-prefix buffers, bounded queue
  writer/             PCAPNG block serializer, buffered output
  profiler/           Counters and benchmark toggles (disabled in hot path)
forwarding/
  api/                Forwarder interface, health metrics
  implementation/     Selected validated forwarding backend
validation/
  fixtures/           Synthetic IPv4/IPv6/TCP/UDP/ICMP packets
  scripts/            tshark checks, long-run scripts, ADB helpers
  upload-server/      Protocol mock/reference receiver for tests
docs/
  STATUS.md           Persistent agent handoff status
  DECISIONS.md        Architecture decision records
  TEST_RESULTS.md     Test commands, devices, logs, failures
  UPLOAD_PROTOCOL.md  Versioned upload request/response and receiver rules
  PERFORMANCE_PLAN.md Baselines, microbenchmarks, performance gates
AGENTS.md             Agent collaboration and stop conditions
```

### Internal interfaces (contracts, not mandatory exact Kotlin signatures)

```kotlin
data class CaptureConfig(
    val snaplen: Int?, // null = full IP packet
    val filterMode: FilterMode, // ALL, INCLUDE, EXCLUDE
    val selectedPackages: Set<String>,
    val captureUnknownUids: Boolean = true
)

// Control-plane API only. PacketMeta and prefix buffers must NOT travel
// via Kotlin/ByteArray/JNI once per packet during active capture.
interface NativeCaptureController {
    fun start(tunFd: Int, config: CaptureConfig, sessionPath: String) // JNI at session start
    fun requestStop(sessionId: String)
    fun getCounterSnapshot(): CaptureCounters // approx. 1 Hz, not packet-by-packet
    fun deliverUidResolutions(batch: List<FlowUidResolution>)
}

// Native ABI-neutral conceptual record; exact C struct and padding tested:
//   u64 time_monotonic_ns, u64 flow_id, u32 uid_or_unknown,
//   u32 original_length, u16 captured_length, u8 direction, u8 flags
// followed by snaplen-limited prefix in a preallocated pool slot.
// First packets carry flow_id even if UID resolution is pending.

interface ForwardingEngine {
    suspend fun start(tunFd: Int, config: ForwardingConfig)
    suspend fun stop()
    val stats: ForwardingStats
}

data class UploadServerConfig(
    val baseUrl: String,       // HTTPS only outside explicit debug fixtures
    val wifiOnly: Boolean = false,
    val authentication: AuthMode // token reference, NEVER secret in logs
)

interface CaptureUploadRepository {
    fun latestCompleted(): CapturePair? // persistent COMPLETE sessions only
    suspend fun upload(pair: CapturePair): UploadReceipt
}
```

`offer()` must be non-blocking with respect to disk writes. Forwarding MUST continue if the logger queue is congested. Count logger-side drops; do not silently drop application packets because the capture queue is full.

## 3. Android network and UID details

### VPN capture and forwarding

- Declare `VpnService` with `android.permission.BIND_VPN_SERVICE` and `android.net.VpnService` intent filter.
- Acquire consent using `VpnService.prepare()`; validate returned interface from `Builder.establish()`.
- Configure both IPv4 and IPv6 routes and DNS deliberately; measure DNS, QUIC/UDP, and TCP behavior, not just HTTP.
- Protect outgoing forwarding sockets using `VpnService.protect()` **before** connecting, to prevent recursive capture loops. Validate network transitions Wi-Fi↔cellular.
- A TUN descriptor does **not** automatically relay packets. Select and validate a user-space forwarding solution in the first spike.
- Prevent network blackholes: failures in forwarder startup must not leave a captured app routed to a nonworking VPN indefinitely; show error and tear down cleanly.

### UID attribution

- Android API 29+: `ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)` for TCP/UDP, called by the active VPN service.
- The `local` endpoint is always the **device/app socket** endpoint, even when handling a DL packet; normalize flow keys to remove UL/DL reversals.
- Maintain a bounded **native** bidirectional flow cache; expire TCP at close/timeout and UDP with inactivity timeout. Include IP version and protocol; account for socket reuse, fragments and new flow generations. Allocate a **session-unique 64-bit flow ID** when a new flow is recognized.
- Do not invoke `getConnectionOwnerUid()` on the packet thread. A bounded native-to-Kotlin request queue sends unresolved *new-flow events* to a worker; return batched resolution results to native cache. Deduplicate requests, impose retry/backoff and a negative cache; track queue overflow and resolver latency. A short flow may end before attribution becomes possible.
- Every PCAPNG packet record references its flow ID, including packets captured before UID resolution. The sidecar `flow_uid_map` can retrospectively join packets of a successfully resolved flow. Preserve `unknown` when unresolved; do not relabel unrelated flows or overwrite earlier UID attribution.
- Cache package information when newly resolved UIDs appear, but perform package/API resolution asynchronously outside native TUN and forwarding threads.
- On attribution misses, retain packet but mark `uid=null`, increment `uid_lookup_misses`, and apply bounded retry when sensible; never substitute the UID of the forwarding process.
- Handle unsupported ICMP, fragmented packets without transport headers, and malformed/unavailable connection state explicitly.
- Use `PackageManager.getPackagesForUid()` and package labels asynchronously. UIDs can map to multiple packages or different Android users/profiles. Keep **package list** rather than pretending it is one-to-one.
- Cache package/class info during capture, not just at stop; package visibility restrictions may prevent enumerating all apps and need transparent fallback.
- `class` is a configurable category such as `realtime_video`, `gaming`, `web`, `background_sync`, `system`, or `unknown`. Unassigned classes remain `unknown`. No inferred certainty.

### Application filter

- Primary mechanism: `VpnService.Builder.addAllowedApplication()` OR `addDisallowedApplication()` (never both). Unselected apps bypass the VPN in Include mode; excluded apps bypass it in Exclude mode.
- **All:** configure neither allowed nor disallowed list. **Include:** require at least one currently installed package before starting; Android's empty allowlist is effectively All, so do not silently fall back. **Exclude:** pass the selected disallowed packages.
- Native per-app lists are configured at VPN creation. Treat a change while recording as **Stop → finalize → re-establish new session**, not a hot update.
- Surface installed apps with search, icon, label, package name and UID where available. Handle shared UIDs and packages that disappear after selection.
- Request minimum package visibility for target deployment; `QUERY_ALL_PACKAGES` may require policy justification if distributed through Google Play. MVP distribution can be developer-installed but should still minimize permissions.
- Distinguish "bypass the VPN" from "application prevented from using the network." Filtering must not block excluded apps' normal traffic.

## 4. PCAPNG schema — version 1

- On session start write a **Section Header Block (SHB)** and **Interface Description Block (IDB)**; choose a verified raw-IP link type for packet data read from TUN (no fake Ethernet header). Validate mixed IPv4/IPv6 using tshark.
- Set IDB `snaplen` to the configured maximum and `if_tsresol=6` for microseconds in v1. Full capture may advertise the maximum expected IP size. Avoid claiming microsecond *accuracy* simply because the file stores microsecond *resolution*.
- Use **Enhanced Packet Blocks (EPBs)**; preserve original IP packet length and captured length independently. The prefix is the first `min(snaplen, actual_length)` bytes copied into a reused native slot; do **not** use an allocating Kotlin `packet.take(...)` implementation on the hot path.
- Assign timestamps on the native capture path using `clock_gettime(CLOCK_BOOTTIME)` or a proven clock equivalent to Android elapsed realtime; convert to Unix-epoch microseconds from recorded monotonic/wall-clock anchors in the writer. Record capture-point and timebase semantics in the sidecar; test wall-clock changes.
- **v1 compatibility-oriented metadata:** write one compact EPB `opt_comment` constructed by the **writer thread**, not the TUN thread: `f-<flow_id>` for every parsable flow; `u-<uid>;f-<flow_id>` when a cached UID is available. This retains a recognizable `u-<uid>` prefix where known, while enabling retrospective mapping via `flow_uid_map`. For non-flow IP/ICMP, reserve a null/0 flow ID convention and test it; do not invent app UIDs. A decoder must parse the documented grammar, not assume an entire comment equals `u-<uid>`.
- **Cost tradeoff:** comments add serialized bytes and writer CPU. Benchmark comments against a future compact custom binary option once a valid assigned PEN is available. Do **not** invent a PEN, and do not pay per-packet string-formatting costs on the capture/forwarding threads.
- Add EPB `epb_flags` for direction using the specification's inbound/outbound convention **after** confirming correct mapping with Wireshark. In the sidecar define `UPLINK=app→network`, `DOWNLINK=network→app`, relative to the phone.
- Keep a monotonic internal packet sequence number for debugging; don't claim external PCAPNG packet-id semantics unless implemented correctly.
- Validate block total lengths, option termination, 32-bit padding, endianness, snaplen behavior, and zero-length/truncated packets with binary fixtures.
- Future: custom PCAPNG options with a valid Private Enterprise Number (PEN), not a fabricated one; v1 comments are a compatibility-oriented first step.

**Caveat:** `opt_comment` is useful for inspection, and the `u-<uid>` prefix resembles PCAPdroid's convention, but a universal parser must not assume third-party readers interpret it as app metadata. Supply a host-side parser example using PCAPNG options and JSON lookup.

## 5. Sidecar file contract

Use a stable, globally collision-resistant ID (e.g. UUIDv4) for each capture session. Store files privately while active as `<capture_id>.pcapng.partial` and `<capture_id>.meta.partial.json`. On controlled stop flush writer and finalize to `<capture_id>.pcapng` and `<capture_id>.meta.json`. Maintain mapping snapshots/checkpoints for crash recovery. The sidecar is written by atomic replace (temp file + rename) on local app storage. Never claim the two files are atomically committed together; use a session manifest/state marker and recovery reconciliation.

```json
{
  "schema_version": 1,
  "capture_id": "7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47",
  "capture_file": "7e3419b2-5b66-47c1-bb3c-e7d4ebc2cd47.pcapng",
  "status": "complete",
  "started_utc": "2026-10-22T19:00:00Z",
  "ended_utc": "2026-10-22T19:05:00Z",
  "capture_point": "android_vpn_tun",
  "timestamp_unit": "microseconds_since_unix_epoch",
  "snaplen_bytes": 256,
  "filter": {
    "mode": "include",
    "packages": ["org.example.meet"]
  },
  "uid_map": {
    "10234": {
      "packages": ["org.example.meet"],
      "app_names": ["Example Meet"],
      "class": "realtime_video",
      "class_source": "user_config"
    }
  },
  "flow_uid_map": {
    "1042": {
      "uid": 10234,
      "resolution": "resolved_after_first_packet"
    }
  },
  "stats": {
    "packets_recorded": 123456,
    "capture_queue_drops": 0,
    "uid_lookup_misses": 321,
    "captured_bytes": 16000000,
    "storage_errors": 0,
    "forwarding_errors": 0,
    "uid_requests_queued": 62,
    "uid_request_queue_overflows": 0,
    "capture_ring_peak_bytes": 1048576
  },
  "capture_engine": "native_ndk",
  "benchmark_profile": "full_metadata"
}
```

The example is illustrative, not observed data. Add `appVersion`, `deviceApiLevel`, `writerVersion`, `forwarderName`, `clockAnchors`, `stopReason`, and `knownLimitations` in the full schema. Export JSON Schema and use stable null/unknown semantics; do not embed personally identifying device identifiers by default.

## 6. Foreground notification and **Stop logging** — must-have

### Notification behavior

Use a dedicated notification channel such as `capture_status`. Make this an **ongoing foreground-service notification** throughout capture; start only after a user-initiated Start and VPN consent flow.

| Capture state | Notification title | Body/action |
|---|---|---|
| STARTING | `Preparing packet capture` | `Setting up VPN…` |
| RECORDING | `PCAPNG logging active` | `01:23 • 45,820 packets • 8.1 MB` and **[Stop logging]** |
| STOPPING | `Stopping capture` | `Flushing packets and writing metadata…` (stop action disabled) |
| COMPLETED | `Capture saved` | `capture.pcapng + capture.meta.json` (optional ordinary completion notification) |
| ERROR | `Capture interrupted` | Short reason and recovery action/in-app details |

**Counters:** duration based on monotonic clock; total logged packet count; file bytes; optional captured UL/DL counts and dropped logger records. Throttle updates, e.g. once per second or less, rather than posting on every packet. Avoid raw packet contents or app identity in lock-screen text.

### Notification Stop action — exact contract

1. Notification action uses an **explicit, immutable `PendingIntent`** into a non-exported handler or directly to the service; include a session identifier to reject stale actions.
2. Deliver `ACTION_STOP_LOGGING` to `CaptureVpnService` (or dedicated internal component). Stopping does not depend on the Activity remaining alive.
3. Atomically transition `RECORDING → STOPPING` and disallow new packet writes to the capture queue; reject duplicate Stop actions.
4. Stop/close VPN forwarding and TUN cleanly, documenting any interruption to existing app connections. After the capture point is quiesced, drain and flush outstanding PCAPNG records.
5. Finalize the UID registry and sidecar; fsync files as appropriate, rename partial artifacts, and commit capture state `COMPLETE`.
6. Update UI and optional completion notification; call `stopForeground(STOP_FOREGROUND_REMOVE)` and `stopSelf()` once finalization ends. Surface an error/recoverable partial session if any step fails.
7. Tests must include Stop via notification when UI is backgrounded, phone is locked, multiple rapid taps, high packet load, and an expired/stale PendingIntent from an older session.

**Android permissions and caveats:** Android 13+ `POST_NOTIFICATIONS` affects whether foreground notifications are shown in the notification drawer. The foreground service may be started without notification permission, but the drawer Stop action may be unavailable if permission is denied; request permission in-app and **always provide an in-app Stop**. Android 14+ requires an applicable foreground service type and permissions; verify the valid VPN-specific configuration on target OS/SDK (VPN apps may qualify for `systemExempted`, subject to eligibility) and test actual device behavior rather than guessing. The OS's Android 13+ **Active apps → Stop** is a force-stop with **no callback**, and **cannot** be treated as a graceful Stop: rely on checkpoints and next-launch recovery for this case.

### State machine

```text
IDLE → PREPARING → STARTING → RECORDING → STOPPING → COMPLETE → IDLE
                   ↘ ERROR ←────────────┘
       RECORDING ──(OS force stop/process death)──> RECOVERABLE_PARTIAL
       RECOVERABLE_PARTIAL ──(next app launch)──> RECOVERED / FAILED
```

Persist session state transitions in `SessionStore`; reconcile incomplete `.partial` files on next app launch. Do not automatically resume VPN capturing after force-stop without explicit consent / valid Android lifecycle support.

## 7. Storage, performance and privacy policy

- Use one native writer owner with buffered output (initially 256 KiB–1 MiB batches); no per-packet `write()`, `flush()`, `fsync()`, JVM allocation, or JNI call. Flush on size/interval and synchronize on graceful Stop. Preserve a recoverable valid block prefix after forced termination.
- Queue metadata plus **only the first `min(snaplen, packet_length)` bytes** in reused native memory. Baseline a 4–16 MiB bounded pool/ring and size from measurement; fixed-prefix mode should not allocate per packet. Full-packet mode needs a separately bounded variable-size pool and an explicit memory/throughput warning. The forwarding path still uses the original entire IP packet.
- Timestamp on the native capture thread at each actual capture point with `clock_gettime(CLOCK_BOOTTIME)` (or proven equivalent) and convert from recorded monotonic↔UTC anchors on the writer thread. Never call wall-clock time APIs per packet. Store timestamp resolution separately from empirically verified accuracy.
- Keep native counters cheap, with a snapshot to Kotlin at about 1 Hz. Notification/status are not updated per packet; file uploads, hashes and export are disabled while recording in MVP.
- Implement a bounded MPSC queue or independent producer rings with a single writer; **select the simplest proven implementation** after contention benchmarks, not an untested lock-free algorithm. Producer enqueue must return immediately on saturation and increment an explicit capture-drop counter. No disk access/serialization in forwarding callbacks.
- Follow the separate **[`docs/PERFORMANCE_PLAN.md`](docs/PERFORMANCE_PLAN.md)**. Compare to VPN-only, not just the no-VPN baseline; report packet-size distributions and CPU time per packet.
- Capture queue bounded by packet count/bytes; count drops and record reason. Never silently block forwarding on disk congestion. An explicit gap marker is optional future work; v1 summary counters are mandatory.
- Snaplen is **IP-layer bytes**, not application payload bytes. Pcap size also includes EPB metadata/options/padding; expose real file size separately.
- On low space, stop recording cleanly and notify; do not exhaust entire device storage.
- App-private storage avoids reliance on broad storage permissions. Export via `FileProvider` + `ACTION_SEND_MULTIPLE` or a ZIP via SAF; use safe URIs and revoke grants.
- Explicit user-facing notice that packet prefixes may contain domain names, authentication material or content. Default 256 B is a size optimization, **not a privacy guarantee**; protect private captures and provide delete/export operations.
- Distinguish packet logging drops from network forwarding drops. Separate capture throughput benchmarks from network-performance baselines (VPN forwarding may alter connection behavior).
- Ensure tests include Doze/background state, display off, long captures, Wi-Fi↔cellular handover, no network, storage full, and CPU/memory thermals.

### Remote upload — product contract

- Settings page: **Upload server** (HTTPS base URL), **API token** (optional server-auth mode; never saved in plaintext logs or exported in sidecar), **Wi-Fi only** toggle, **Test connection** action, and displayed connectivity/auth outcome. No default public server and no background scanning/discovery.
- Capture screen and Saved captures: **Upload latest** button; state text such as `Latest complete: ...`, `Ready`, `Uploading 45%`, `Uploaded`, `Failed — Retry`. If a capture is still recording, do not upload that partial capture. For MVP, disable upload while VPN capture is running; future simultaneous upload requires validated `VpnService.protect()` for uploader sockets and independent bandwidth-impact measurements.
- Define "latest" as most recently finalized **COMPLETE** local session, sorted by reliable finalization timestamp and tie-broken by persisted session sequence/ID. Do not use file modified time or select a recently failed `.partial` session. Freeze capture ID and paths when upload starts, even if another session appears later.
- Upload **both** `<capture_id>.pcapng` and `<capture_id>.meta.json` in a **single multipart HTTPS request** with a manifest, stable `capture_id`, and SHA-256 digest for each artifact. Stream data with bounded buffers (no full-file read into RAM or mandatory ZIP duplication). Make the receiver commit a capture only when both files pass validation, and return a receipt. See [`docs/UPLOAD_PROTOCOL.md`](docs/UPLOAD_PROTOCOL.md).
- Keep a separate local upload record (`NOT_UPLOADED`, `QUEUED`, `UPLOADING`, `SUCCEEDED`, `FAILED`, `CANCELED`) with attempts, server response ID, byte progress, and last error. Do **not** change the immutable sidecar after upload. `SUCCEEDED` requires a validated HTTP success/receipt (not merely bytes sent). Persist upload state separately so retry after process death is possible.
- Make uploads explicitly user-triggered. Uploading is not part of Stop's synchronous finalization path: Stop saves files first. On transient network failure preserve the files and provide retry; never silently auto-upload a stopped capture.
- HTTPS with normal certificate verification by default. Reject `http://` in production; optional local plaintext testing, if needed, must be isolated to debug builds. Support an authorization header (`Bearer` token) when configured. Protect tokens using Android Keystore-backed storage or a similarly defensible platform mechanism, and do not log tokens, file content, or secret-bearing URLs.
- Schedule potentially large, user-requested transfer using the **platform-appropriate API**: investigate `JobScheduler` user-initiated data transfer jobs (API 34+) and WorkManager on API 29–33, with visibility/progress and cancel. For small transfers WorkManager may be suitable on all versions, but document Android 16+ background job quotas before selecting a single solution. Keep capture notification state independent from upload status.
- Notify the user of upload progress/completion if transfer continues after the Activity closes. Distinguish `Stop logging` from **Cancel upload**; canceling upload must not delete finalized captures.
- Receiver is configurable, not tied to a specific cloud provider. Deliver a reference/mock receiver with authenticated health endpoint and transactional ingest contract; production deployment and retention policies are operator responsibilities.

## 8. Implementation milestones and go/no-go gates

The coordinator may parallelize isolated discovery, writers, UI mock/tests and documentation, **but integration is serialized behind the stated gates**. Agents do not mark milestones complete without executing or witnessing tests and linking evidence.

### M0 — Repository bootstrap, specification and experiment scaffold

**Tasks**
- Create a runnable Android Kotlin/Gradle project; choose compatible current compile/target SDK, minSdk=29.
- Write `AGENTS.md`, `docs/STATUS.md`, `docs/DECISIONS.md`, `docs/TEST_RESULTS.md`.
- Add CI build + unit tests, AndroidManifest VPN declaration scaffold, lint, reproducible device/ADB instructions.
- Prepare native NDK build target and a feature-switchable profiling harness with a separate **VPN forwarding-only** variant (no capture/UID/writes), plus variants defined in `docs/PERFORMANCE_PLAN.md`.
- Capture a baseline measurement of device/network behavior without VPN **and** forwarding-only VPN, with packet rates and environmental controls recorded, for comparison.

**Gate:** Clean build on CI/dev host; debug APK installs; docs and source layout match agreed interfaces.

### M1 — Risk-reduction spike: forwarding and UID ownership (**critical gate**)

**Tasks**
- Evaluate **reuse versus implementation** of TCP/UDP forwarding: inspect PCAPdroid design (GPL-3.0-or-later obligations), candidate permissively licensed forwarding engines (e.g. tun2socks), their Android integration, resource use and packet-observation hooks. A tun2socks engine may need an additional local SOCKS/proxy component; do not mistake it for a complete relay.
- Record licensing decision before copying source or linking binaries. Avoid copying GPL-licensed code into a repository intended to remain proprietary unless licensing is explicitly acceptable.
- Make a minimal VpnService + chosen forwarding engine with a working TUN listener and protected outbound sockets.
- Exercise TCP HTTPS, UDP/QUIC, DNS, IPv4/IPv6 and bidirectional traffic. Observe availability with/without VPN.
- Spike UID attribution on real outgoing and incoming packets, including first UDP datagram, short TCP connection, cached lookups and failures; document OS/device restrictions.
- Decide whether to keep a forwarding-provided UID source alongside Android's official lookup, only when supported and measured.
- Prove TUN FD transfer to native engine, native forwarding hooks and socket protection; compare JNI crossings/packet and per-packet allocation between candidate integrations. Choose a forwarding solution with a native observation hook or establish measured proof that an alternate approach meets overhead goals.
- **Performance gate P0:** save no-VPN and forwarding-only baseline throughput, p50/p95/p99 RTT/jitter and CPU/packet. Document any traffic synthesis and known packet fidelity limitations before building higher layers.

**Gate:** Real-app traffic works acceptably; UID on test TCP/UDP flows demonstrably correct or limitations measured; no recursion; a supported licensing path exists. **If gate fails, STOP feature development and resolve architecture**.

### M2 — Standalone PCAPNG and metadata core (parallelizable with M1)

**Tasks**
- Implement **native** binary writer with SHB, IDB, EPB, timestamp options, direction flags, compact flow-ID/UID comment, snaplen; test on desktop host and Android ABI where possible.
- Construct EPB blocks off the forwarding thread, in reusable output buffers; detect overflow, integer/padding errors, endian issues and partial writes. Measure serialized bytes and CPU/packet for snaplen 64/128/256/512/full.
- Implement epoch/monotonic anchor conversion and deterministic timestamp injection for tests.
- Implement UID registry, `flow_uid_map` retrospective join, and sidecar serializer with JSON Schema and checkpoint API. Test first-packet-before-resolution, never-resolved and recycled-5-tuple cases.
- Build synthetic fixture packets covering IPv4/IPv6, TCP options, UDP, fragmented headers, tiny/malformed frames, snaplen 64/256/full.
- Validate output with `tshark -r <file>`, `capinfos`, and a separate parser to verify metadata/options and packet lengths.

**Gate:** PCAPNG accepted by Wireshark/tshark and all fixtures byte-accurate. Both files parse and UIDs join to sidecar. No device required for unit tests.

### M3 — End-to-end capture pipeline

**Tasks**
- Connect **native** TUN observer → minimum fast parser/native UID cache → preallocated prefix-copy queue → native PCAPNG writer; keep forwarding independent. Do not cross JNI for every packet.
- Add build-time benchmark switches (forward-only, prefix-copy, write, write+flowID, UID resolver, full) without changing actual packet routing. Use a bounded UID request queue serviced in Kotlin outside the packet thread.
- **Performance gate P1:** stress logging by pausing/throttling the writer; forwarding must continue, capture losses counted, memory bounded and no packet-path allocation/JNI observed. Benchmark deltas against P0 and record preliminary pass/waiver against provisional budgets.
- Normalize UL/DL flow tuples before UID lookups; do not log protected forwarding socket traffic as if it belonged to the client.
- Implement session IDs, app-private storage, capture counters, unknown UID handling, bounded queue and log-drop metrics.
- Detect disk-full and writer exceptions; implement checkpoint and recoverable-session records.

**Gate:** Device-generated TCP/UDP appear in real PCAPNG with sensible timestamps/directions and matching sidecar mappings; forwarding still works when writer is slowed intentionally.

### M4 — App filters and user-facing capture configuration

**Tasks**
- Build searchable installed-app selection with package/label/icon; show visibility limitations.
- Add All / Include / Exclude modes, saved package selection and snaplen control.
- Apply native filter before VPN `establish()`; verify only selected apps enter the TUN in Include mode and excluded apps bypass it in Exclude mode.
- Do not accept empty Include selection; define shared-UID behavior and missing package error handling.
- For changed filter during capture require a new capture session; make interrupt/restart consequences visible.

**Gate:** Two distinct test apps show correct inclusion/exclusion; bypassed apps keep network; filter settings are captured in sidecar.

### M5 — Notification status, one-tap Stop and finalization (**must-have gate**)

**Tasks**
- Implement foreground-service notification channel, permission flow, current status and counters.
- Implement explicit action PendingIntent and session-scoped `ACTION_STOP_LOGGING` handler independent of Activity.
- Make `stopCapture()` an idempotent state-machine operation with ordered quiesce → flush → close → metadata finalize → notification cleanup.
- Provide in-app Start/Stop, recoverable error screen and saved captures list.
- Test denied notification permission, background/locked-screen action, Activity killed/recreated, repeated Stop, VPN revoke, OS task-manager force-stop.

**Gate:** Notification Stop reliably creates a Wireshark-readable PCAPNG and correct sidecar under nominal and stress conditions. Forced termination correctly advertises/recover partial captures on next launch.

### M6 — Upload server configuration, upload latest and receiver contract (**must-have gate**)

**Tasks**
- Define and version the HTTPS receiver protocol in `docs/UPLOAD_PROTOCOL.md`, including an authenticated test endpoint, multipart fields, upload ID/idempotency and deterministic server receipts. Implement a minimal local reference receiver or strict mock; do not assume a pre-existing backend API.
- Implement Upload settings UI: server URL, optional token, Wi-Fi-only setting, **Test connection**, validation and secure credential storage. Ensure account secrets cannot leak into exports, logs, crash reports, or PCAPNG.
- Implement `latestCompleted()` selection using immutable finalization state and a lock/snapshot against simultaneous deletion; reject active, damaged and unmatched file pairs.
- Implement **Upload latest** from the capture page/saved sessions; include both files and manifest, compute streaming SHA-256, support upload progress, cancel, offline/retry and duplicate requests with persisted transfer status.
- Choose/test Android transfer scheduling on minSdk 29 and recent API levels. Large uploads must be resilient to Activity dismissal, screen lock and service shutdown. Recording Stop must not wait for upload.
- Verify response receipt before setting `SUCCEEDED`; server must validate hashes and commit the pair atomically. Preserve local files regardless of success or failure.
- Explicitly test Wi-Fi/cellular policy, TLS/certificate failures, 401/403, 413, 5xx, network interruption, unknown server, device reboot and resubmitting the same capture ID.

**Gate:** From the app, configure a receiver, test connection, stop a capture, tap **Upload latest**, and verify that the receiver has exactly the same PCAPNG and sidecar bytes (SHA-256) under the correct capture ID; UI shows a verified receipt, and retries cannot create inconsistent duplicates. All required negative tests are evidenced.

### M7 — Validation, performance tuning and release handoff

**Tasks**
- Run the test matrix below on target Android devices and at least one additional API level if available.
- Execute `docs/PERFORMANCE_PLAN.md` P2 battery/energy, CPU per packet, RAM, GC, JNI, sustained capture disk write and packet loss comparisons **vs no VPN, VPN-only and staged capture variants**; preserve raw results and raw device traces. Never treat packet/sec tests without packet-size distribution as sufficient.
- Optimize only measured bottlenecks. Track forward packet loss separately from capture-drop loss. Add 256 B versus 64/128/512/full tests, and 100% native-only vs any alternate path being considered.
- Check multi-hour captures, cancellation, export, server uploads (including large files), storage quota, error notifications and cleanup.
- Security review permissions, exported components, FileProvider scope, HTTPS/TLS/token storage, server authorization and retention, sensitive prefixes, cleanup and dependencies/licenses.
- Deliver installable APK, source, build instructions, PCAPNG + sidecar sample, tshark validation recipe, upload receiver contract/mock, limitations.

**Gate:** All mandatory tests and **performance gate P2** pass or deviations are documented and explicitly accepted. No `low-overhead` claim unless supported by side-by-side reproducible metrics. Final `docs/STATUS.md` contains verified evidence, not unsubstantiated claims.

## 9. Executable validation matrix

| ID | Scenario | Must assert |
|---|---|---|
| V01 | TCP HTTPS from one selected test app | Two directions captured; service continues to work |
| V02 | UDP/QUIC and DNS | Packet counts, UID lookup/miss and flow cache logic |
| V03 | IPv4 and IPv6 traffic | Both parse in tshark; no fake Ethernet headers |
| V04 | Snaplen=64, 256 and full | Captured length `min(original, snaplen)`; original stays intact |
| V05 | Same app UL/DL | Identical UID on bidirectional cached flow if resolved |
| V06 | Short-lived, missing/unsupported UID | Unknown explicit, no fabricated mapping |
| V07 | Native Include / Exclude | Selected apps only through VPN; bypassed apps remain connected |
| V08 | UI background / device locked | Foreground service and status remain usable |
| V09 | Notification Stop during high traffic | Exactly one finalization; no corrupted file; sidecar saved |
| V10 | Notification permission denied | In-app Stop available; no claim drawer action visible |
| V11 | Android Active apps force-stop | Next-launch recovery of partial artifacts; no false COMPLETE |
| V12 | VPN permission revoked | Graceful cleanup where callbacks run; recovery otherwise |
| V13 | Low disk / slow writer | Forwarder not blocked by logging; drop counters correct |
| V14 | Wi-Fi↔cellular and offline→online | Recoveries documented; no forwarding loop |
| V15 | Metadata classification / shared UID | Accurate packages array; stable unknown class mapping |
| V16 | Export both files | PCAPNG and JSON use matching capture ID and parse on host |
| V17 | Repeated rapid Start/Stop | No double close, duplicate sessions or stale notification action |
| V18 | Long-run performance (target ≥1 hour) | Measured CPU/RAM/bytes/drop rate; no unbounded growth |
| V19 | Persist upload server settings, Test connection | URL and auth state correct across restart; errors surfaced |
| V20 | Upload latest after normal Stop | Select latest COMPLETE, hash-verify both files on receiver |
| V21 | Active/incomplete, malformed or missing sidecar | Not uploaded; explicit actionable error without losing files |
| V22 | Offline, timeout, TLS failure, bad token, HTTP 413/500 | Correct states; safe retries; local capture preserved |
| V23 | Duplicate retry / lost HTTP response | Same capture ID and request idempotency; no conflicting server copies |
| V24 | Large transfer, Activity exit, phone lock, reboot | Progress/cancel/retry according to OS contract; no OOM |
| V25 | Wi-Fi-only and metered cellular | Enforce selected network policy; clear UI |
| V26 | Separate notification Stop and upload cancellation | Stop finalizes capture; cancel upload does not remove capture |
| V27 | Security and server negative tests | No cleartext production transfer, no bearer token leaks, rejects invalid hashes |
| V28 | P0 no-VPN / VPN-only baseline | Same device, workload and conditions; forwarding-only cost separately quantified |
| V29 | P1 prefix-only vs native writer vs full UID | CPU/packet, throughput, RTT distribution and write MB/s by stage |
| V30 | UID delayed resolution on first packets | Flow ID joins early packets via sidecar; unresolved stays explicit |
| V31 | No per-packet capture JNI/alloc/extra file syscalls/format | Source audit and profiling/trace; writer I/O occurs in batches; native TUN read syscalls are unavoidable |
| V32 | Queue exhaustion / 1–5 s synthetic writer stall | Forwarding still runs, capture drop count correct, memory within bound |
| V33 | 64/128/256/512/full snaplen sweep | CPU/packet and storage rate versus packet size mix measured |
| V34 | 10 min high-pps small-packet and 1 h mixed workload | Thermal/CPU/memory impact, drop rates, forwarding failure independently logged |
| V35 | Notification 1 Hz and upload off during logging | Notification updates decoupled from packet rate; no upload workload in MVP recording |
| V36 | P2 repeated paired runs | Provisional performance budget evaluated with confidence spread and environment recorded |

**Test harness:** versioned packet fixtures; instrumentation tests; ADB scripts for service lifecycle; host-side Python or tshark parser for PCAPNG EPB metadata; a small controlled TCP+UDP test app to provide a known UID; an isolated HTTP test receiver that checks multipart hashes, auth, idempotency and paired commits. Keep device/API details attached to results.

Suggested commands (only after implementation exists):

```bash
./gradlew test assembleDebug
./gradlew connectedAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell dumpsys notification --noredact
capinfos capture.pcapng
tshark -r capture.pcapng -T fields -e frame.time_epoch -e ip.src -e ipv6.src
```

Performance harness commands and required measurement fields are in `docs/PERFORMANCE_PLAN.md`; the coordinator must populate them with real executable project commands, not handwave benchmarks.

`capinfos` and `tshark` run on the host. Do not treat example commands as evidence of execution.

## 10. Agentic team workflow

**Main coordinator** (persistent): owns acceptance criteria, merges and priorities, risk register, and concise status. Does not redo deep analysis already completed and recorded by another agent. Must read `AGENTS.md`, `docs/STATUS.md`, `docs/DECISIONS.md` at each resumed session.

**Short-lived task agents (dispatch only as needed):**

| Agent | Narrow task | Required handoff |
|---|---|---|
| Android/VPN investigator | SDK/manifest/FGS/permissions/device constraints | APIs + reproducible device spike + uncertainties |
| Forwarding investigator | Candidate native engines, hooks, license, real forwarding test | Comparison matrix + P0 go/no-go evidence |
| Native capture engine implementer | TUN native FD, pooled prefix buffers, bounded queue, writer integration | Thread/lifetime design, hot-path audit, P1 benchmark traces |
| Performance/measurement agent | Reproducible no-VPN/VPN-only/variant workloads, profiling | Raw CPU/packet/RTT/queue/drop measurements, P0/P1/P2 reports |
| PCAPNG implementer | Writer + fixtures + validation script | Commit + binary compatibility results |
| UID/metadata implementer | Flow cache + resolver + JSON schema | Tests + failure/unknown cases |
| UI/notification implementer | App picker, state display, PendingIntent Stop | Instrumentation evidence + screenshots/logs |
| Upload/Android transfer implementer | Settings, session selection, transfer scheduling, progress/retry | End-to-end device evidence + dependency/capability notes |
| Server protocol implementer | Versioned receiver/mock, auth, staging, hashes, idempotency | Request/response fixtures + failure tests |
| Independent verification agent | Cross-module integration, perf and adversarial tests | Reproductions, regressions, severity-ranked findings |

### Agent work contract

1. Coordinator writes a **task brief**: scope, inputs, interfaces, expected artifacts, tests, explicit stop criteria. Avoid a vague request such as "build the entire logger".
2. Agents read only the relevant docs/source; do not carry unrelated histories in long-lived contexts.
3. Agents work on isolated branches/worktrees when possible. Contracts are defined before parallel coding.
4. Each agent must hand back a **concise report**: files/commits changed, tests actually run, test outputs, blockers, assumptions, risks, interface changes.
5. Coordinator verifies integration, records decisions in `DECISIONS.md`, and updates `STATUS.md`. Terminate task agents after handoff.
6. If blocked by an Android version restriction, license issue, or forwarding correctness, record it and stop dependent feature work. Do not silently "mock" a failed requirement and declare success.
7. At least one agent not involved in implementation reviews each high-risk area (VPN forwarding, native hot-path memory/thread safety, notification Stop, PCAPNG binary writer).
8. Upload agents must separately implement client and mock/receiver to a reviewed protocol, then cross-validate hashes/receipts. Do not mark HTTP 200 alone as end-to-end transfer success.
9. Maintain explicit `claimed/verified/not tested` terminology; never convert a proposed design into a completed milestone without evidence.
10. Before optimizing, obtain P0 and P1 profiling traces; agents may not introduce a custom lock-free queue, hand-built TCP stack or C++ micro-optimization unless measurements and tests justify it. Maintain native hot-path invariants as testable architectural constraints.

### Mandatory persistent progress (`docs/STATUS.md`)

Every work session starts by reading status and finishes with an update. Include milestone, state, evidence, known problems, next bounded tasks and explicit decisions. Example initial state below; live status belongs in separate file and is not replaced by chat memory.

```markdown
# Project Status
Updated: 2026-10-22
Current milestone: M0 — bootstrap
State: NOT STARTED
Completed (verified): none
In progress: none
Blockers: forwarding choice unverified; SDK/device validation not performed
Decisions pending: forwarding backend/license; packet UID encoding beyond v1 comment
Next tasks:
  - Create Android/NDK project and reproducible no-VPN/VPN-only P0 workload
  - Spike no-root forwarding + UID lookup on target device
  - Write PCAPNG binary fixture tests
  - Freeze upload request/receipt contract before parallel client/server work
Evidence: none yet
```

## 11. Risks and decision register (initial)

| Risk | Why important | Mitigation / decision gate |
|---|---|---|
| User-space forwarding breaks connectivity or changes timing | Invalidates measurement utility | M1 spike first; benchmark; document capture semantics |
| UDP attribution misses for early/brief flows | Wrong app classes | Cache/retries, unknown UID flag, measure hit rate |
| UID and package name are not 1:1 | Mapping can mislead | Multiple packages per UID, class provenance and caveat |
| Native filter change disrupts active flows | Unexpected app interruption | New capture session; user-facing confirmation |
| Android foreground notification permission denied | Stop action invisible in drawer | Ask permission, always expose in-app Stop |
| Android Task Manager Stop kills process without callback | Incomplete capture/sidecar | Checkpoints, recovery, status not falsely COMPLETE |
| Disk stalls and sustained high-rate writes | Packet loss/DoS | Bounded native ring + writer, loss counters, P1 stall test |
| Per-packet JNI/JVM/system API or allocation | CPU/GC jitter grows with packet rate | Native data plane, batch JNI control only, profiling and P1 review |
| Delayed UID lookup loses first-packet attribution | Early packets unjoinable | Every flow packet stores flow ID, sidecar flow→UID mapping and unknown semantics |
| Packet prefix buffer growth in full-capture mode | Memory OOM / forwarding jitter | Separate bounded pool and benchmark, warn user |
| Open-source forwarding license conflicts | Cannot ship/reuse implementation | License review and recorded decision at M1 |
| Unknown Android target/API behavior | Runtime exceptions or policy rejection | Device tests, correct FGS type, Play policy review |
| PCAPNG UID comments not machine standardized | Incompatible metadata reader | Versioned sidecar contract and host reader |
| Uploading active capture produces inconsistent pair | Corrupt/mismatched analytics | Upload only COMPLETE immutable pair, lock session snapshot |
| HTTPS/auth errors or leaked API token | Confidential capture disclosure | TLS validation, keystore-backed secret protection, negative tests |
| Network drops after upload but before receipt | Duplicate remote captures | Capture ID + idempotency/receipt replay, hash validation |
| Large mobile uploads drain data/battery | Poor UX and unpredictable runtime | Network preference, progress/cancel, platform scheduling, real measurements |
| Upload packet traffic interferes with ongoing VPN capture | Feedback loops and measurement distortion | MVP upload only when idle; protect sockets if enabled concurrently later |

## 12. Deliverables and closeout package

- Debug APK and reproducible build instructions.
- Versioned Kotlin/Android source with component contracts and unit/instrumentation tests.
- Sample `.pcapng` and matching `.meta.json` (synthetic or explicitly consenting test app), both validated.
- Optional host-side script for enumerating `timestamp,src,dst,proto,uid,app_class` from PCAPNG + JSON.
- `docs/STATUS.md`, `docs/DECISIONS.md`, `docs/TEST_RESULTS.md`, `docs/UPLOAD_PROTOCOL.md`, user README and known limitations.
- Working **Upload latest** app flow, persisted server settings, authenticated minimal receiver/mock, verified receipts and retry evidence.
- A clean summary of measured overhead, packet loss (if any), attribution hit rate and reliability rather than invented KPIs. Include raw P0/P1/P2 benchmark evidence and `docs/PERFORMANCE_PLAN.md`.

## 13. Verified reference points (checked 2026-10-22)

1. Android VPN setup/service lifecycle and `protect()`: https://developer.android.com/develop/connectivity/vpn and https://developer.android.com/reference/android/net/VpnService
2. Per-app VPN allow/deny lists and empty-allowlist behavior: https://developer.android.com/reference/android/net/VpnService.Builder
3. UID API behavior (API 29+, TCP/UDP only, INVALID_UID): https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,java.net.InetSocketAddress,java.net.InetSocketAddress)
4. Android foreground service type requirements (Android 14+; systemExempted active-VPN qualification): https://developer.android.com/about/versions/14/changes/fgs-types-required
5. Android 13+ notification permission behavior: https://developer.android.com/develop/ui/compose/notifications/notification-permission
6. Android Task Manager Stop kills app without lifecycle callbacks: https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping
7. Package visibility and `QUERY_ALL_PACKAGES`: https://developer.android.com/training/package-visibility/declaring
8. PCAPNG Enhanced Packet Blocks/flags/options; **Internet-Draft (not finalized RFC)**, September 2026: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-06.html
9. PCAPdroid design reference; **GPL-3.0-or-later**: https://f-droid.org/packages/com.emanuelef.remote_capture/ and https://github.com/emanuele-f/PCAPdroid
10. Android user-initiated transfer jobs (API 34+): https://developer.android.com/develop/background-work/background-tasks/uidt
11. Android data transfer scheduling options and constraints: https://developer.android.com/develop/background-work/background-tasks/data-transfer-options
12. WorkManager long-running uploads and Android 16 quota caveat: https://developer.android.com/develop/background-work/background-tasks/persistent/how-to/long-running
13. Android Network Security Configuration and HTTPS/cleartext defaults: https://developer.android.com/privacy-and-security/security-config
14. Android `ParcelFileDescriptor.detachFd()` native FD ownership: https://developer.android.com/reference/android/os/ParcelFileDescriptor#detachFd()
15. Android `VpnService.protect(int)` sockets: https://developer.android.com/reference/android/net/VpnService#protect(int)

---

**First coordinator instruction:** Execute M0 and the tightly scoped M1 forwarding/UID + **P0 baseline** spike first. In parallel, an independent packet-format agent may begin M2 using synthetic packets and a short-lived API agent can freeze `docs/UPLOAD_PROTOCOL.md`. **Do not start broad UI implementation before M1 is proven.** Prove the native capture path and **P1 performance gate at M3** before building broad UI. Complete upload integration at M6 before final **P2** validation M7. After each bounded task, reconcile tests and update `docs/STATUS.md`.
