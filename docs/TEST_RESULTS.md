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

## 2. JVM unit tests — PASS (17/17)

Command: `./gradlew testDebugUnitTest`

| Class | Tests | Notes |
|---|---|---|
| `SessionStoreTest` | 6 | latest = highest finalize sequence (not creation/mtime); skips active/recovered/unpaired; truncation of a mid-block-killed file; force-stop recovery from checkpoint → `recovered`; STOPPING + complete sidecar → COMPLETE; forwarding-only session without file → FAILED |
| `SidecarTest` | 2 | contract keys, UTC timestamps, null UIDs, stats aggregation, class rules parsing |
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
| V27 | token not in logs | PASS (app) | token string absent from app logs; one occurrence was adbd logging the *test harness* command line (documented debug-hook caveat) |

## 5. Performance (P0 / P1)

See section filled from `validation/perf/results/Pixel_9_Pro/2026-10-22/` below.

## Not tested yet

V07 Include/Exclude with two distinct apps (only `com.android.shell` Include verified via benchmarks), V10 notification
permission denied, V12 VPN revoked by another VPN, V14 Wi-Fi↔cellular handover, V13 low disk on device, V15 shared-UID
classification on device, V17 rapid start/stop stress, V18/V34 1-hour soak, V24 reboot during upload, V25 metered
cellular policy, V33 snaplen sweep, P2 energy/thermal, second Android API level.
