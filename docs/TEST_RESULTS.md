# Test Results

All entries below were executed in this repository on 2026-10-22 (UTC+2 local) by the
implementing agent (Claude). Anything not listed here is **NOT TESTED**.

**Environment**
- Host: Ubuntu 24.04.4, x86_64, gcc 13, cmake 3.28/ninja, OpenJDK 17.0.20, Python 3.12.3,
  tshark/capinfos 4.2.2 (user-local install from Ubuntu packages, `~/.local/opt/wireshark`).
- Android build: AGP 8.13.2, Gradle 8.13, Kotlin 2.3.21, compileSdk 36, targetSdk 35, minSdk 29, NDK 27.2.12479018.
- Device: Google Pixel 9 Pro (`caiman`), Tensor G4, Android 17 (API 37), arm64-v8a, Wi-Fi 5 GHz
  (11ac, RSSI ≈ −54 dBm) to the same LAN as the host (192.168.1.131 ↔ 192.168.1.121), USB-powered.
- Commits: native core `a7c5de4`, app `9f190f6`, receiver/tests `12671d1`, upload fixes (see `git log`).

## 1. Native host tests (M2 gate) — PASS

Command: `./validation/scripts/check_native.sh`

| Test | What it asserts | Result |
|---|---|---|
| `test_pcapng` | SHB/IDB/EPB byte layout, option padding/termination, lengths, comment grammar incl. `u-0`, max values | OK |
| `test_flow` | IPv4/IPv6 (+ext hdr) parsing, non-initial fragments, malformed/truncated input, UL/DL normalization → same flow, new generation after FIN+SYN, SYN retransmit ≠ new flow, TCP≠UDP keys, 180-entry expiry vs reference (backward-shift delete), load-factor limit | OK |
| `test_ring` | SPSC 2M items under concurrency: order + integrity, `produced + dropped == offered`, full ring never blocks | OK (e.g. produced=1,848,156 dropped=151,844) |
| `test_capture` | 12-packet fixture (TCP v4, UDP v6, ICMP, fragment, 3-byte junk, zero-length, FIN→SYN generation, UID delivered after 2nd packet, INVALID_UID); writer stall 500 ms; `/dev/full` storage error; **zero heap allocation over 200k tap calls** | OK — `stall: offered=5000 written=128 dropped=4872 producer_ms=0.37`; `tap: 200000 records, heap in-use delta=0 bytes` |
| `test_engine` | Engine with a SOCK_SEQPACKET pair as TUN: UDP echo via lwIP pretend sessions (2 datagrams, 1 session), TCP SYN→SYN-ACK→data echo→FIN both ways, connect to closed port → RST to app, second session refused (EBUSY), idempotent stop, TUN closed by engine; counters reconcile (`records_written == pkts_ul + pkts_dl`) | OK |
| Python independent parser | `pcapng_tool.py check-fixture`: every record's direction, lengths, flow ID, UID, µs timestamp; retrospective join of flow 1's first two packets via `flow_uid_map` | OK |
| tshark cross-check | `frame.packet_flags_direction` (0x2 UL / 0x1 DL), `frame.len`/`cap_len`, `frame.comment`, `frame.time_epoch` ±1.5 µs for all 12 records; `capinfos` reads Raw IP, µs resolution, snaplen 64 | OK |

## 2. JVM unit tests — PASS (26/26)

Command: `./gradlew testDebugUnitTest`

| Class | Tests | Notes |
|---|---|---|
| `SessionStoreTest` | 6 | latest = highest finalize sequence (not creation/mtime); skips active/recovered/unpaired; truncation of a mid-block-killed file; force-stop recovery from checkpoint → `recovered`; STOPPING + complete sidecar → COMPLETE; forwarding-only session without file → FAILED |
| `CaptureMoverTest` | 8 | (2026-10-23) move to an in-memory Downloads stand-in: copy + fsync + read-back SHA-256 → publish → private deleted, "latest" finds moved pair; corrupted read-back → rollback, private kept; system cancel → rollback, retried; no space / name conflict fail safely; only finalized COMPLETE/RECOVERED pairs eligible; reconcile rolls back an interrupted move and finishes a committed one; stale hidden entries replaced; shared files deleted outside the app → pair reported missing |
| `SidecarTest` | 3 | (2026-10-23, ADR-013) schema_version 2, v2 comment grammar, `interfaces`, `context` summary; context Info-column text |
| `SidecarTest` (before ADR-013) | 2 | contract keys, UTC timestamps, null UIDs, stats aggregation, class rules parsing |
| `UploadClientTest` | 7 | streaming SHA-256 vs reference, exact multipart length, progress reaches total, cancellation, receipt must match ID + both digests, HTTP error mapping/retryability, HTTPS-only URL validation |
| `UploadIntegrationTest` | 2 | **Kotlin client ↔ Python receiver over TLS (test CA)**: health 200 / bad token 401; 1.6 MB upload 201 with byte-identical server files; identical retry 200 same receipt; same ID different content 409 without overwrite; wrong digest 422 and no dataset; untrusted CA → TLS error |

## 3. Reference receiver tests — PASS (14/14)

Command: `python3 -I validation/upload-server/test_receiver.py` (certs from `make_certs.sh`)

health auth (200/401×3); valid upload byte-exact + receipt digests; identical retry 200 same receipt, one dataset;
conflicting same ID → 409 no overwrite; bad digest / foreign capture_id / `status: recording` / wrong `capture_file` /
non-JSON sidecar / non-PCAPNG capture → 422, no dataset, no staging leftovers; missing / duplicate / unexpected /
out-of-order parts → 400; path-traversal filename and non-UUID ID → 400; missing/wrong token → 401; oversize → 413
(or reset); interrupted body → no orphan, retry 201; lost response after commit → retry 200 with original receipt;
48 MB streamed upload with bounded receiver memory; untrusted certificate and hostname mismatch rejected by client.

## 4. Device functional tests (Pixel 9 Pro, Android 17)

| ID | Scenario | Result | Evidence |
|---|---|---|---|
| M1 | VPN establish + forwarding | PASS | `dumpsys connectivity`: `VPN CONNECTED … IS_VALIDATED`, routes 0.0.0.0/0 + ::/0, DNS 192.168.1.1, UIDs `{0-10709, 10711-20709, 20711-99999}` (own UID 10710 excluded) |
| V01/V03 | TCP HTTPS + IPv4/IPv6 in a real capture | PASS | 160 s All-apps capture: 134,076 packets; tshark protocol hierarchy shows IPv4+IPv6 TCP/TLS, HTTP, QUIC (289), DNS (60), ICMPv6; no Ethernet headers (Raw IP) |
| V02 | UDP/DNS/QUIC | PASS | nettool UDP 200 pps & 1000 pps: 0 % loss; DNS and QUIC flows in capture |
| V04 | snaplen | PASS (256, 128 on device; 64 in fixtures) | `capinfos`: inferred snaplen 256; independent parser: `cap_len ≤ snaplen`, `orig_len` intact |
| V05/V30 | UID on both directions; early packets joined | PASS | 122 flows: 113 resolved on first lookup (p50 1 ms, p95 4 ms, max 19 ms), 9 `unresolved_invalid_uid`; packets: 133,443 with `u-` comment, 610 resolved via `flow_uid_map`, 23 unknown |
| V06 | short-lived/unsupported UID stays unknown | PASS | unresolved flows mostly UDP/53 system DNS; `uid: null`, never the logger's UID |
| FGS | foreground service type | PASS | `dumpsys activity services`: `isForeground=true types=0x00000400` (systemExempted) |
| FR-10 | notification status ~1 Hz with Stop action | PASS (content) | `dumpsys notification`: title `PCAPNG logging active`, text `00:13 • 242 packets • 44.5 KB`, `actions=1`, `vis=PRIVATE` with public version |
| V09 (partial) | Stop → finalize | PASS | in-app/debug `ACTION_STOP_LOGGING` (session-scoped intent, Activity finished): `.pcapng` + `.meta.json`, `status: complete`, `stop_finalize_ms: 36`, 0 capture drops |
| V08/notification tap | Stop by **tapping** the notification action | **NOT TESTED** | blocked: a system BiometricPrompt from another app (Authenticator) was overlaying the shade; not dismissed by the agent |
| V11 | Android force-stop (no callbacks) → next-launch recovery | PASS | `am force-stop` during capture; relaunch → state `RECOVERED`, PCAPNG 102,567 records valid (0 bytes truncated), sidecar `status: recovered` from last checkpoint |
| V16 | both files parse on host with matching capture ID | PASS | `pcapng_tool.py validate` + `validate-sidecar` OK; tshark/capinfos read file |
| M6/V20 | Upload latest after Stop | PASS | 32,380,580-byte multipart; receipt `srv-000001`; receiver SHA-256 `154d08af…c4c2` / `2f671c35…7982` == phone `sha256sum` |
| V21 | upload during recording | PASS | schedule refused ("Stop logging before uploading"), no job pending |
| V22 | TLS failure / bad token | PASS | untrusted server cert → "TLS certificate not trusted…" (no HTTP request sent); bad token → preflight `401` → "Not authorized (401): check the API token" |
| V23 | duplicate retry | PASS | second upload → HTTP 200, same receipt `srv-000001`, one dataset on server |
| V07 | Include / Exclude | PASS (shell UID as test app) | `device_lifecycle.py`: Include(com.android.shell) → +2001 tun0 pkts for a 2000-pkt workload; Exclude → +32 tun0 pkts (other apps), bypassed shell kept UDP 0 % loss and 183.5 Mbit/s TCP |
| V09 | Stop under TCP download + duplicate Stop | PASS | one finalization, COMPLETE, 70,410 records, 0 drops, finalize 179 ms, PCAPNG + sidecar valid |
| V17 | 5 rapid Start/Stop cycles | PASS | 5 sessions, all COMPLETE, VPN down at end |
| ADR-012 | existing captures auto-moved to `Download/MiniPcap` on first launch of the new build | PASS | 7 pairs; private dir keeps only state/upload/export records; `adb pull /sdcard/Download/MiniPcap/` (14 files) → every SHA-256 equals `export.json`, `pcapng_tool.py validate` ok; MediaStore rows `is_pending=0`, owner `dev.minipcap` |
| ADR-012 | Force-stop **during** a move of a 1,001,010,344-byte capture (snaplen 0, 40 s TCP download at 180.7 Mbit/s) | PASS | record EXPORTING with private pair intact at force-stop; relaunch → hidden entries rolled back, move redone in 5.3 s, no `(1)` duplicates; host pull (37.9 MB/s over USB) SHA-256 `9eadd385…9ab2` = record, PCAPNG valid (942,538 records), sidecar `complete` |
| ADR-012 | Upload latest from the moved location | PASS | receipt `srv-000003`; receiver SHA-256 of both files == phone record |
| ADR-012 | Auto-move off → stays private; manual move | PASS | after Stop only private files; debug `move` → EXPORTED, pair in `Download/MiniPcap` |
| ADR-012 | Delete from the UI (both locations), files deleted from a PC, MTP browsing from a desktop file manager | **NOT TESTED** on device (delete/missing logic unit-tested only; MediaStore indexing verified, MTP itself not) |
| V27 | token not in logs | PASS (app) | token string absent from app logs; one occurrence was adbd logging the *test harness* command line (documented debug-hook caveat) |

## 5. Performance (P0 / P1)

**Run:** `python3 -I validation/perf/bench.py --host 192.168.1.131 --repeats 3 --variants A,B,C,D,E,F --stall`
(commit after `Fix UDP relay drops…`, 2026-10-22 22:0x–22:30 UTC). Raw per-run JSON, sidecars and
`SUMMARY.md`: `validation/perf/results/Pixel_9_Pro/2026-10-23/`. Pixel 9 Pro / Android 17 / Tensor G4,
USB-powered, battery ~44 %, thermal status 0 throughout; Wi-Fi 5 GHz LAN to host nettool server;
Include mode with `com.android.shell` only; snaplen 256; MTU 1500. 3 repeats, variant order rotated.
Deviations from PERFORMANCE_PLAN: 3 s warm-up instead of 60 s; 15 s/10 s workloads; personal phone
with background apps (system-wide CPU is noisy); no external power meter.

**Superseded:** the first run (`…/2026-10-22_run1_invalid-cpu-accounting/`, see its `NOTE.md`) had a
CPU-accounting script bug and exposed a real forwarding defect (relay UDP `sendto` EAGAIN → 6–10 % loss at
5k pps in all VPN variants). Fixed by 1 MiB relay UDP socket buffers; verified `udp_send_errors = 0`.

### Cost 1 + 2: baseline (A) and VPN forwarding penalty (B vs A), medians of 3

| workload | A result | B result | B app CPU (engine thread) | notes |
|---|---|---|---|---|
| UDP 5000 pps × 100 B, 15 s | loss 0.020 %, RTT p50 7.18 / p99 16.7 ms | loss 0.019 %, p50 7.48 / p99 16.3 ms | 5.03 s (4.39 s) ≈ 29 µs/pkt | +0.3 ms RTT p50 |
| UDP 2000 pps × 1200 B | loss 0 %, p50 6.19 / p99 16.3 ms | loss 0 %, p50 6.19 / p99 15.9 ms | 4.58 s (3.98 s) ≈ 66 µs/pkt | per-wakeup cost dominates at low rates |
| TCP up 10 s | 110.8 Mbit/s, 105k pkts (wlan0) | 115.4 Mbit/s, 152k pkts (tun0) | 1.68 s ≈ 8 µs/pkt | TUN sees +45 % packets (stack re-segmentation/ACKs) |
| TCP down 10 s | 179.5 Mbit/s | 177.1 Mbit/s | 3.11 s ≈ 12 µs/pkt | |
| 200 short TCP conns | conn+RR p50 10.1 ms | p50 8.2 ms | 0.42 s | local SYN-ACK by lwIP shortens handshake as seen by app |

System-wide busy CPU B−A: +1.2 … +8.0 s per workload (noisy: spread across repeats is of the same order).
Throughput is Wi-Fi-limited in both A and B.

### Cost 3: incremental capture cost (C/D/E/F vs B), medians of 3

| workload | B → F app CPU | F−B | engine thread B → F | writer thread (F) | UID worker (F) | throughput/RTT F vs B |
|---|---|---|---|---|---|---|
| UDP 5k pps small | 5.03 → 5.19 s | +0.16 s (+3 %) | 4.39 → 4.40 s | 0.10 s ≈ 0.7 µs/record | 0.02 s | loss 0.023 % (one run 3.4 %, see below); p99 15.5 ms |
| UDP 2k pps large | 4.58 → 4.82 s | +0.24 s (+5 %) | 3.98 → 4.11 s | 0.07 s ≈ 1.2 µs/record | 0.01 s | unchanged |
| TCP up | 1.68 → 1.76 s | +0.08 s (+5 %) | 1.26 → 1.30 s | 0.12 s | 0.01 s | 120.5 vs 115.4 Mbit/s |
| TCP down | 3.11 → 3.27 s | +0.16 s (+5 %) | 2.78 → 2.76 s | 0.16 s | 0.01 s | 165.0 [158–183] vs 177.1 [148–179] Mbit/s |
| 200 short TCP conns | 0.42 → 0.49 s | +0.07 s | 0.31 → 0.24 s | 0.01 s | 0.15 s (≈0.75 ms/flow) | unchanged |

Stage view (engine thread, µs/pkt, UDP 5k): B 29.3, C 29.5, D 31.3, E 28.6, F 29.4 — differences are within
the min–max spread of repeats; the measurable logging work is the writer thread (0.5–1.2 µs/record), the UID
worker (~1 lookup per flow) and the 1 Hz status thread (~5 ms/s). Every capture run: **0 capture-queue drops,
0 relay/TUN errors**; ring peak reached its 16,384-slot capacity only during the stall tests.

UDP-5k outlier: F run 3 lost 3.4 % with p99 137 ms while the forwarder recorded 0 `udp_send_errors`,
0 `tun_write_errors`, 0 capture drops and ~2,560 fewer packets on tun0 — consistent with a burst on the
Wi-Fi path (1 of 15 VPN UDP-5k runs; none of 3 A runs). **Unexplained**, not attributed to logging.

### P1 writer stall under 5k pps UDP (V32, variant D)

| stall | app loss | RTT p99 | packets observed | records written | capture drops |
|---|---|---|---|---|---|
| 1 s | 0.063 % | 16.1 ms | 119,976 | 119,976 | 0 (ring absorbed it) |
| 5 s | 0.043 % | 16.3 ms | 119,986 | 86,267 | 33,719 (= observed − written) |

Forwarding is unaffected by a stalled writer; drops are counted exactly and only in capture counters.

### P1 hot-path audit (V31)
- Source + arm64 disassembly: `mpc_capture_begin` calls only parser/flow-table functions; no JNI, allocator,
  logging, formatting or file I/O on the forwarding thread. Writer `write()` calls: ~175 per 600k records (≈1 MiB batches).
- Host test: 200,000 tap calls (incl. new flows) → heap in-use delta 0 B, mmap delta 0 B.
- JNI crossings during capture: ~1 Hz counter snapshot + batched UID poll/deliver (≤256 flows/batch); none per packet.
- Not done: Perfetto trace / simpleperf profile of the engine thread.

### V18/V34 endurance soak (60 min, variant F)
`python3 -I validation/perf/soak.py --host 192.168.1.131 --minutes 60` (raw: `validation/perf/results/soak/<date>/`
`samples.jsonl`, `sidecar.json`, `summary.json`). Each minute: UDP 2000 pps × 200 B for 40 s, 10 s TCP download,
50 short TCP connections. Result: **23,579,096 records, 0 capture-queue drops, 0 storage errors, 0 relay send
errors**, 6.22 GB PCAPNG read completely by `capinfos` (3657.8 s, Raw IP, snaplen 256); RSS 194→198 (max)→165 MB,
native heap PSS 12.8–18.0 MB, threads 33–34 (no growth); flows 3,128 created / 3,071 expired, 3,108 with UID;
UDP loss median 0.021 %, max 0.091 %; TCP ≥ 132 Mbit/s; 0 failed short connections; thermal status 0; app CPU
1,025 s over 3,658 s; Stop/finalize 2.56 s for the 6.2 GB file. FD count not measured (shell cannot list the
app's `/proc/<pid>/fd`). Note: `capture_ring_peak_slots` is an upper bound (computed with the producer's
cached tail) — it reached capacity without any drop.

### Gate verdicts (agent assessment; **coordinator/independent review not yet performed**)
- **P0:** forwarding works for TCP/UDP/DNS/QUIC/IPv4/IPv6 on the target phone; VPN penalty quantified above.
  Not covered: Wi-Fi↔cellular handover, cellular network, second device.
- **P1:** PASS on the measured criteria (no per-packet JNI/alloc on the tap, stall isolation, bounded memory,
  B/C/D/E data on one workload set). Incremental logging cost ≈ +3–5 % process CPU vs B at 2k–5k pps and
  ~110–180 Mbit/s TCP, throughput/RTT changes within run-to-run spread. Provisional P2 budgets still need sign-off.
- No "minimal overhead" claim is made: independent review and P2 (energy, thermal, cellular, snaplen sweep) are open.

## ADR-013 tags v2 + context records (2026-10-23)

| Check | Result | Evidence |
|---|---|---|
| Wireshark decodes Upper-PDU JSON records without plugin | PASS | prototype with tshark 4.2.2: unpadded tags decode (`json.member_with_value`), padded tags do not; Info column shows tag 36 text |
| `test_pcapng` | PASS | v2 grammar incl. max-length `u=2147483647;f=18446744073709551615;c=4294967295` (< 64 B); Upper PDU byte layout |
| `test_capture` fixture | PASS | 3 context records (STATE 1, INFO 2, STATE 3) + 12 packets: packets 1–6 `c=1`, 7–12 `c=3`; `ctx_records_written` 3; hold off → `records_uid_late_bound` 0 |
| `test_capture` late binding | PASS | hold 300 ms: UID delivered 20 ms after flow 1's first 2 packets → both written with `u=10234` (late-bound 2/5); flow 2 resolved after 600 ms → earlier packet stays `f=2` only; no hold bypass |
| `check_native.sh` | PASS | independent reader: contexts match, every packet's `c=` equals the latest STATE record before it in the file; tshark: 12 packets + 3 JSON context records |
| JVM / lint | PASS | 26/26; lint 0 errors |
| Device: sampler output (location, cells, NR NSA, Wi-Fi), permissions flow, FGS location type | **NOT TESTED** | phone not connected |
| Performance: hold memory, comment size, context file growth, battery | **NOT TESTED** | needs P1 rerun (variants E/F) and soak |

## Not tested yet

Notification-action *tap* (blocked by another app's biometric overlay), V10 notification permission denied,
V12 VPN revoked by another VPN, V14 Wi-Fi↔cellular handover and cellular networks, V13 low disk on device
(host `/dev/full` test only), V15 shared-UID classification on device, V24 reboot during upload, V25 metered
cellular policy, V33 snaplen sweep, P2 energy/thermal, second Android API level, Perfetto/simpleperf traces,
independent review. Downloads move (ADR-012): UI delete on device, files removed from a PC, MTP
browsing, low space during a move, API 29–32 MediaStore path, capture disk-I/O impact of a concurrent move.
