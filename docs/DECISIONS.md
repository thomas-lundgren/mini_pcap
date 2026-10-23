# Architecture Decision Log

Format: Date · State · Problem · Options · Evidence · Decision · Consequences/rollback.
"Evidence" links to tests/source that were actually executed (see `docs/TEST_RESULTS.md`).

## ADR-001: Kotlin control plane, native C data plane
- Date: 2026-10-22 · State: **accepted**
- Problem: per-packet JVM/JNI work adds CPU and GC jitter that grows with packet rate.
- Options: Kotlin TUN loop; Kotlin forwarding + native capture; fully native data plane.
- Evidence: `native/src/{engine,capture}.c`; JNI only in `native/src/jni.c` (start/stop, ~1 Hz counters, batched UID buffers). Disassembly of the arm64 build: `mpc_capture_begin` calls only `mpc_parse_packet`, `mpc_flow_key_from_pkt`, `mpc_flow_lookup` (+ stack protector). Host test `no_alloc_on_tap` (200k tap calls, heap delta 0 bytes).
- Decision: Kotlin owns UI, VpnService lifecycle, notification, UID worker, sidecar and upload. Native owns TUN I/O, TCP/UDP forwarding, tap, flow table, ring and PCAPNG writer.
- Consequences: data-plane bugs are C bugs → host unit/integration tests are mandatory (`validation/scripts/check_native.sh`).

## ADR-002: Flow ID on every record; v1 EPB comment grammar
- Date: 2026-10-22 · State: **accepted**
- Decision: session-unique 64-bit `flow_id` (sequential from 1) per normalized 5-tuple *generation*; a new generation starts on a client SYN after FIN/RST or after 60 coarse-seconds idle. The writer thread formats `f-<flow>` or `u-<uid>;f-<flow>`; **no comment ⇒ flow_id 0** (non-TCP/UDP, non-initial fragment, malformed, flow table full). UID in the comment is the UID cached at capture time; earlier packets are joined through sidecar `flow_uid_map`.
- Evidence: `native/tests/test_capture.c` fixture checked by the independent parser (`validation/scripts/pcapng_tool.py check-fixture`) and by tshark (`frame.comment`). Device run: 133,443 packets with `u-`, 610 joined via `flow_uid_map`, 23 unknown.
- Consequences: third-party readers see the comments as plain text; machine readers must use the grammar + sidecar. A binary option needs an assigned PEN (not available; not invented).

## ADR-003: Bounded SPSC ring + single writer thread, batched I/O
- Date: 2026-10-22 · State: **accepted (provisional sizes)**
- Problem: forwarding must never wait for storage.
- Options: MPSC queue; per-producer rings; single SPSC ring.
- Decision: the engine is single-threaded, so there is exactly one producer → one SPSC ring of fixed slots (`32 B header + snaplen`), 8 MiB default, mmap'd and pre-touched at start. Full ring ⇒ record dropped and counted (`capture_queue_drops_*`), packet still forwarded. Writer formats EPBs into a 1 MiB buffer and calls `write()` only when full, every 1 s, or at Stop; `fsync` only at Stop. Writer idles in `poll(eventfd, 20 ms)`; the producer signals only when ≥¼ ring is used.
- Evidence: `test_ring` (2M items, ordering), `test_capture` stall test (500 ms stall: producer finished 5000 packets in <1 ms, drops counted, written+dropped=offered); device P1 stall runs (see TEST_RESULTS).
- Rollback: ring size/flush interval are parameters (`ring_bytes`, `writer_buf_bytes`).

## ADR-004: Benchmark gates and variants
- Date: 2026-10-22 · State: **accepted**
- Decision: variants B–F are a runtime switch in the same engine (`MPC_VARIANT_*`): B tap off; C tap + parse + flow + copy, writer discards; D + PCAPNG file, UID off; E + UID worker; F = E + 1 Hz notification + 10 s sidecar checkpoints. A = no VPN. `validation/perf/bench.py` runs identical workloads with Include-mode limited to `com.android.shell`.

## ADR-005: Forwarding engine = vendored lwIP fork (heiher/lwip, BSD-3-Clause) + own socket relay
- Date: 2026-10-22 · State: **accepted** (M1 gate evidence on Pixel 9 Pro)
- Problem: a TUN fd does not forward; we need TCP/UDP termination with a native capture hook, permissive license.
- Options considered:
  - PCAPdroid/zdtun — GPL-3.0: incompatible with an unrecorded licensing decision; **not used, no code copied**.
  - tun2socks (Go) — extra runtime + SOCKS hop; capture hook would need patching inside Go.
  - hev-socks5-tunnel (MIT) — proven on Android but needs a SOCKS5 server hop; read only as an integration reference.
  - Hand-written TCP stack — excluded by plan unless justified.
  - **lwIP fork used by hev-socks5-tunnel** (`NETIF_FLAG_PRETEND_TCP/UDP` accept traffic for any address), BSD-3-Clause, vendored unmodified at commit `e6d5fc6` (`third_party/lwip/VENDORED.md`).
- Decision: single-threaded epoll loop (`native/src/engine.c`): TUN read → UL tap → lwIP; lwIP output → DL tap → TUN write. Accepted TCP pcbs are relayed to non-blocking sockets (back-pressure through `tcp_recved`/`tcp_sndbuf`), UDP sessions per app socket to unconnected UDP sockets.
- Evidence: host `test_engine` (UDP echo, TCP handshake/data/FIN, refused → RST, idempotent stop); device: Android marked the VPN VALIDATED, UDP/TCP/DNS/QUIC/IPv6 traffic in captures, nettool TCP ~150–180 Mbit/s.
- Consequences/limitations: TCP is terminated locally (SYN-ACK synthesized before upstream connect; downlink segmentation chosen by lwIP); ICMP is not forwarded; lwIP uses `malloc` per pbuf (forwarding cost, counted in B).

## ADR-006: Loop prevention by excluding the app's own UID (instead of per-socket `protect()`)
- Date: 2026-10-22 · State: **accepted**
- Problem: relay sockets must bypass the VPN; `VpnService.protect(fd)` would be a JNI call into Java for every new flow from the forwarding thread.
- Decision: All mode = `addDisallowedApplication(self)`; Exclude = self + selected; Include never contains self. Relay sockets of the app UID therefore use the underlying network. No JNI on the forwarding thread at all.
- Evidence: device `dumpsys connectivity` shows VPN UIDs `{0-10709, 10711-20709, 20711-99999}` (own UID 10710 excluded); captures contain no relay traffic; uploads from the app also bypass the VPN.
- Consequences: the app's own traffic is never captured (documented in sidecar `filter.self_excluded`). Rollback: add a `protect()` callback if a future mode must include the app itself.

## ADR-007: Foreground service type `systemExempted` (fallback `specialUse`)
- Date: 2026-10-22 · State: **accepted**
- Evidence: on Android 17 the consented VPN service runs with `types=0x00000400` (systemExempted). `specialUse` with a subtype property is declared as a fallback if the platform rejects systemExempted.

## ADR-008: Upload = protocol v1 over HttpsURLConnection + JobScheduler (UIDT on API 34+)
- Date: 2026-10-22 · State: **accepted**
- Decision: no third-party HTTP client; streaming multipart with exact `Content-Length`; SHA-256 computed in a streaming pass before sending; auth preflight `GET /health` before the body so 401/403 are reported clearly; success only after receipt capture ID + both digests match. API 34+: user-initiated data transfer job (`setUserInitiated`, `RUN_USER_INITIATED_JOBS`); API 29–33: regular network-constrained job. Wi-Fi-only → `NETWORK_TYPE_UNMETERED`. Never scheduled during capture, never automatically. Token encrypted with an AndroidKeyStore AES-GCM key.
- Evidence: JVM tests incl. cross-implementation test against the Python receiver; device run: 32.4 MB pair uploaded, server SHA-256 identical, identical retry → 200 same receipt, bad token → 401 message.
- Open: Android 16+ job quotas for very long uploads not measured; resumable upload not implemented (full restart on retry, idempotent).

## ADR-009: Minimal package visibility; no AndroidX
- Date: 2026-10-22 · State: **accepted**
- Decision: `<queries>` for launcher activities only (no `QUERY_ALL_PACKAGES`); UIDs of non-visible packages appear with `note: package_not_visible_or_uninstalled`. Framework-only UI (no AndroidX) and an in-app read-only `CaptureFileProvider` serving only finalized `*.pcapng`/`*.meta.json`.

## ADR-010: Network configuration of the VPN
- Date: 2026-10-22 · State: **accepted**
- Decision: MTU 1500 (packet sizes comparable to Wi-Fi/cellular); IPv4 address `10.111.0.2/32`; IPv6 `fd00:6d70:6300::2/128` and `::/0` **only if the underlying network has a global IPv6 address** (otherwise Android blocks IPv6 for VPN apps, avoiding Happy-Eyeballs delays into a dead path); DNS servers copied from the underlying network (link-local and unusable v6 filtered; fallback 8.8.8.8). `setMetered(false)` so metering follows the underlying network.

## ADR-011: Session storage, recovery and "latest"
- Date: 2026-10-22 · State: **accepted**
- Decision: app-private `files/captures/`: `<id>.pcapng.partial` → `<id>.pcapng`, sidecar checkpoint `<id>.meta.partial.json` every 10 s (variant F) → final `<id>.meta.json` (temp+fsync+rename), `<id>.state.json` per session, persisted `session`/`finalize` counters. "Latest" = highest `finalize_seq` among COMPLETE sessions with both files (never mtime). Next-launch recovery (App.onCreate) truncates the PCAPNG to the last complete block, writes a `status: recovered` sidecar from the last checkpoint, marks RECOVERED (not uploadable as "latest"). STOPPING sessions with a complete sidecar already written are completed.
- Evidence: `SessionStoreTest` (6 tests); device force-stop test recovered 102,567 records.

## ADR-012: Move finalized pairs to Download/MiniPcap for USB offload
- Date: 2026-10-23 · State: **accepted** (requested by the user: store many captures, copy them off over USB)
- Decision: capture still writes only to app-private storage (`.partial` never leaves it). After Stop
  (and at every app start) `ExportJobService` (a regular JobScheduler job, so the copy survives the
  Activity/VPN service ending) moves each finalized COMPLETE or RECOVERED pair to MediaStore Downloads
  `Download/MiniPcap/` (API 29+, no storage permission): insert both entries hidden (`IS_PENDING=1`),
  copy + fsync, read back and compare SHA-256 with the source, publish (sidecar first), commit
  `<id>.export.json` = EXPORTED, then delete the private copies. One copy per capture afterwards.
  `.state.json`/`.upload.json`/`.export.json` stay private. A crash before commit rolls back on the next
  run (hidden entries deleted, private pair intact, move retried); a crash after commit only deletes the
  leftover private copies. Upload/share use the moved files; a capture being moved is locked against
  upload and vice versa. Setting "Move finished captures to Download/MiniPcap" (default on); off keeps
  pairs private until the user picks **Move to Download/MiniPcap**. Delete removes both locations.
- Consequences: moved captures are visible over USB/MTP and `adb pull`, and readable by apps with
  all-files access (privacy notice updated). Files deleted/renamed outside the app make that capture
  "missing" for upload/share. A move needs free space for one extra copy plus 64 MiB; otherwise it fails
  and the pair stays private. Moving is disk I/O concurrent with a new capture (not benchmarked).
- Evidence: `CaptureMoverTest` (8 tests with an in-memory destination); device tests in TEST_RESULTS §4.

## ADR-013: Self-describing packets: tags v2, context records, late UID binding
- Date: 2026-10-23 · State: **superseded by ADR-014** (never released) · superseded the v1 comment grammar
- Context: the user's intent is per-packet metadata beyond app identity: positioning, motion and radio
  measurements (signal strength, serving and neighbor cells, radio technology), with packets
  separable by app without an external join.
- Decision:
  1. **Tags v2** in `opt_comment`: `u=<uid>;f=<flow>;c=<ctx>` (keys in this order, each optional).
     Extensible by adding keys; readable/filterable in Wireshark. The reader also accepts v1.
  2. **Context records** in the same PCAPNG on interface 1 `ctx0`, `LINKTYPE_WIRESHARK_UPPER_PDU`
     (252): exported-PDU tags `json` dissector + Info text (unpadded, big endian), then JSON. Wireshark
     4.2 decodes them with its JSON dissector (verified with tshark). `type: context` records
     (location, motion, network, cellular serving+neighbors, wifi; ~1 Hz, each section with status and
     age) are referenced by packets as `c=<seq>`; `type: app` records (uid → packages/names/class) are
     written when a UID is first resolved, so the file names its apps without the sidecar.
  3. **Context assignment in the writer by timestamp:** packet gets the latest STATE record with
     `ts <= packet ts`; the record is always written before the first packet referencing it. The
     forwarding-thread tap is unchanged (no per-packet cost added there).
  4. **Late UID binding:** the writer holds records up to `uid_hold_ms` (500 ms default for E/F) and
     fills a UID that arrived meanwhile (writer-side direct-mapped flow→uid cache fed by a second SPSC
     ring from the UID worker). Holding is bypassed when the ring is ≥ 50 % full or at Stop, so it can
     never cause capture drops; `records_uid_late_bound` / `records_hold_bypassed` count it.
  5. Kotlin `ContextSampler` (own HandlerThread): LocationManager (fused if available, else GPS) at
     the interval, GNSS status, linear acceleration/gyro/rotation/pressure aggregated per interval,
     `requestCellInfoUpdate` + `getAllCellInfo` (serving = registered, others = neighbors) for
     LTE/NR/WCDMA/GSM/TD-SCDMA/CDMA, `SignalStrength`, data network type + display override (NSA),
     WifiManager link info. Permissions (fine/coarse location, phone state) requested at Start when
     context is on; refused → section `status: permission_denied`, capture still starts. FGS type
     `location` added when permitted (needed for background location on Android 11+/14+).
  6. Sidecar `schema_version` 2: `comment_grammar` v2, `interfaces`, `context` summary.
- Alternatives rejected: full values in every packet (≈80–120 B/packet, 2–3 GB/h at soak rates, and
  Kotlin data on the hot path); custom binary EPB options under a PEN (not decoded by stock
  Wireshark; deferred until a benchmark justifies it, PERFORMANCE_PLAN §2).
- Consequences: per-packet comment grows by ~4–8 B; ring occupancy grows by hold × packet rate
  (bypass at 50 %); context adds ~1–3 KB/s of file data; battery cost of location + 50 Hz sensors.
  Measurements are snapshots, not per-packet measurements (documented in sidecar
  `known_limitations`).
- Evidence: native `test_pcapng` (v2 grammar, Upper PDU layout), `test_capture` (fixture with
  contexts: c= assignment and ordering; late binding 2/5 records bound with a 300 ms hold, none after
  the hold), `check_native.sh` (independent reader + tshark decode contexts as JSON). Device and
  performance validation: **NOT TESTED** (phone not connected).

## ADR-014: PCAP with Linux SLL direction + asynchronous binary metadata sidecar
- Date: 2026-10-23 · State: **accepted (device validation pending)** · supersedes ADR-013 and the
  PCAPNG/JSON output of ADR-002/ADR-003/ADR-011; specification from the user ("Packet Capture and
  Asynchronous Metadata Architecture")
- Decision:
  1. **Packets:** `<id>.pcap`, classic PCAP, nanosecond magic `0xA1B23C4D`, `LINKTYPE_LINUX_SLL`
     (113). SLL packet type 4 OUTGOING = uplink, 0 HOST = downlink; ARPHRD_NONE; protocol 0x0800/0x86DD;
     PCAP lengths include the 16-byte SLL header. No per-packet metadata beyond direction/time/lengths.
     Timestamps: CLOCK_BOOTTIME at the tap, converted with one session anchor (stored in the meta
     header) so the monotonic time is exactly recoverable and wall-clock steps cannot reorder packets.
  2. **Header floor (user requirement):** every record keeps at least the IP + transport header
     (packet parser computes `hdr_len`: IPv4/IPv6 + extension headers + TCP data offset / UDP 8 /
     ICMP 8), capped at 192 bytes; e.g. IPv6 + TCP with 12 B options = 72 B. Snaplen choices: headers
     only (`MPC_SNAPLEN_HEADERS`), 128 (default), 256, 512, full. Ring slots hold max(snaplen, 192).
  3. **Metadata:** `<id>.meta`, binary, little endian, versioned (docs/META_FORMAT.md v1.0): 64-byte
     header (magic, version, session UUID, PCAP clock anchor) + 8-byte-aligned records
     `{u16 type, u16 flags, u32 length, i64 monotonic ns, payload}`; unknown types skipped by length;
     presence bitmaps mark unavailable values; flags carry the timestamp source (logger, sensor,
     location fix, modem, packet). Records: SESSION_INFO, CLOCK_SYNC, SESSION_END, CAPTURE_STATS,
     DROPPED_EVENTS, SENSOR_STATUS, LOCATION, GNSS_STATUS, MOTION_SAMPLE, RADIO_STATE, CELL_IDENTITY,
     CELL_MEASUREMENT, SIGNAL_STRENGTH, NETWORK_STATE, WIFI_STATE, UID_MAPPING, FLOW_MAPPING.
  4. **Writer:** Kotlin `MetaWriter`: pool of preallocated 4 KiB buffers + bounded queue + one writer
     thread with a 64 KiB staging buffer, flush ~1 s, fsync at Stop. Producers never block (pool
     empty → drop counted, `DROPPED_EVENTS`); only SESSION_INFO / SESSION_END / start-stop CLOCK_SYNC
     wait (≤ 2 s) for a buffer. Encoders are inline (no lambda/record objects per motion sample).
  5. **Collectors**, each independent: Clock (start, 60 s, time/timezone broadcasts, stop), Location
     (fused/GPS with min time/distance, fix timestamp, GNSS status ≤ 1 Hz), Motion (accelerometer +
     optional gyroscope, sensor timestamps, modes all / max rate / threshold, 200 ms batching),
     Radio (TelephonyCallback per listener: signal strengths, data connection state/type, data
     activity, display override, service state, cell info; periodic `requestCellInfoUpdate`; serving
     identity separate from measurements; dedupe by modem timestamp; API 29–30 PhoneStateListener),
     Network (default network callback, Wi-Fi link poll), Apps (UID worker → FLOW_MAPPING with native
     first-packet time and 5-tuple; PackageRegistry → UID_MAPPING).
  6. **Flow attribution after the fact:** the UID request now carries the flow's first-packet
     timestamp (56-byte request). The analyzer matches packet 5-tuple + time to the FLOW_MAPPING
     with the latest `first_seen_ns` ≤ packet time (5-tuple reuse → new generation). Late-binding hold
     and per-packet tags of ADR-013 are removed from the writer.
  7. **Analyzer** `analyzer/mpcanalyze.py` (stdlib): validate, dump, summary, timeline (CSV/JSON),
     context-at, export-pcapng; state = latest valid; samples = latest with age and stale flag;
     position interpolated only between fixes ≤ max gap; motion window statistics.
  8. **Storage/upload:** `<id>.pcap(.partial)` + `<id>.meta(.partial)`; session `format` field keeps
     legacy (`.pcapng` + `.meta.json`) sessions shareable/movable (not uploadable). Recovery truncates
     both files to the last complete record and appends SESSION_END(recovered). Upload protocol v2:
     metadata part is the binary file; receiver validates magic, session id, framing, final
     SESSION_END complete, and PCAP linktype 113.
- Consequences: no per-packet app/context in the PCAP itself (by design; `export-pcapng` produces an
  enriched copy); per-packet record overhead drops from ~68 B (PCAPNG EPB + options) to 32 B (PCAP
  header + SLL); metadata size depends on motion rate (50 Hz accel+gyro ≈ 4.3 KB/s).
- Evidence: native `test_pcap`, `test_capture` (first-seen timestamps in UID requests, header floor
  40/72/48 B with snaplen 32 and headers-only), `check_native.sh` (independent reader + tshark
  `sll.pkttype`, exact monotonic recovery); JVM `MetaWriterTest` (framing, recovery, drops, oversize,
  **Kotlin-written session decoded and correlated by the Python analyzer**), `SessionStoreTest`,
  `UploadIntegrationTest` (Kotlin client ↔ Python receiver v2); receiver 14/14. Device:
  **NOT TESTED** (phone not connected).

### Pending decisions
- Provisional P2 budgets (coordinator sign-off after reviewing P0/P1 numbers in `docs/TEST_RESULTS.md`).
- Whether recovered captures may be uploaded (would need protocol support for `status: recovered`).
- Production distribution: package visibility needs, Play policy for VPN/FGS types.
