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

### Pending decisions
- Provisional P2 budgets (coordinator sign-off after reviewing P0/P1 numbers in `docs/TEST_RESULTS.md`).
- Whether recovered captures may be uploaded (would need protocol support for `status: recovered`).
- Production distribution: package visibility needs, Play policy for VPN/FGS types.
