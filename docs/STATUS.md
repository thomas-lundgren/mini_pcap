# Project Status — MiniPcap (Android packet logger with asynchronous metadata)

**Updated:** 2026-10-23 — release v0.2.0 published (signed APK, SHA-256 16f5256d…335c, built from `8b8cf44`)
**Milestone:** M0–M6 implemented and device-tested on one phone; P0/P1 measured; M7/P2 partially (soak only)
**State:** IN PROGRESS — needs independent review, P2 battery/thermal/cellular, and the untested items below.
Evidence: `docs/TEST_RESULTS.md` (commands, device, raw paths). Decisions: `docs/DECISIONS.md`.

## Milestone tracker

| Milestone | Status | Evidence / gap |
|---|---|---|
| M0 Bootstrap + harness | DONE | Gradle/NDK build (`./gradlew assembleDebug testDebugUnitTest`), host native build, `bench.py`/`nettool`; no CI configured (local only) |
| M1 Forwarding + UID + P0 | DONE (1 device) | lwIP fork BSD-3 + socket relay (ADR-005); VPN VALIDATED; TCP/UDP/DNS/QUIC/IPv4/IPv6; UID 113/122 flows first lookup; P0 table in TEST_RESULTS §5. Gap: cellular, handover, 2nd device |
| M2 Native packet writer + metadata | DONE (format replaced by ADR-014) | `check_native.sh`: PCAP (SLL) fixtures checked by the analyzer reader and tshark; metadata format cross-checked Kotlin → Python |
| M3 Native pipeline + P1 | DONE (P1 agent verdict PASS, review pending) | tap 0 allocs; stall 5 s → 0.04 % app loss, drops counted; logging ≈ +3–5 % process CPU vs B |
| M4 App filter UI | DONE (basic) | All/Include/Exclude, searchable picker (launcher apps), snaplen; V07 verified with shell UID. Gap: two real third-party apps |
| M5 Notification + Stop | DONE | systemExempted FGS, 1 Hz text, session-scoped Stop intent, idempotent stop (V09, V17), force-stop recovery (V11). physical notification tap verified on the release build (TEST_RESULTS "Release build on device"). Gap: permission-denied, VPN revoke |
| M6 Upload | DONE | receiver + 14 tests; Kotlin↔Python cross test; device upload SHA-256 identical, replay 200, 409, 401 preflight, refused while recording |
| USB offload (ADR-012) | DONE (1 device) | finalized pairs moved to `Download/MiniPcap` with read-back SHA-256 check; force-stop mid-move recovered; upload from moved files. Gap: UI delete, MTP, API 29–32 |
| ADR-015 layered structure + review hardening | DONE (host) | 4 sub-agent reviews, fixes + tests; coverage matrix docs/TEST_COVERAGE.md |
| ADR-014 PCAP (SLL) + binary `.meta` + analyzer | IMPLEMENTED, host-tested (phases 1–4) | direction in SLL, header floor (≥ IP + transport header), asynchronous collectors (GPS, motion, radio, network, apps), `mpcanalyze.py`. Phase 5: release build device-tested end to end (all collectors, 506k packets, 0 drops); device performance rerun NOT TESTED |
| M7 / P2 | PARTIAL | 60-min soak PASS (23.6M records, 0 drops, bounded memory); no energy, thermal-stress, snaplen sweep, cellular, second API level, security review |

## Verified accomplishments (this session)
- Native data plane: `native/src/{engine,relay_tcp,relay_udp,capture,flow,ring,pcap,packet,jni}.c`; host tests 6/6 suites.
- Android app (Kotlin, no AndroidX), layered packages (ADR-015): capture session lifecycle, metadata
  writer + collectors, flow-owner worker, recovery, move to Downloads, Keystore token, UIDT upload, UI.
- Reference receiver `validation/upload-server/receiver.py` (stdlib, TLS, idempotent, transactional).
- Performance harness and two benchmark runs (first superseded, see NOTE.md there).
- Fixed defects found by device testing: tagged-pointer handle treated as error (native session leak on
  start "failure"), relay UDP drops under bursts, upload 401 surfacing, ERROR sessions not recovered.
- Move of finalized pairs to `Download/MiniPcap` for USB offload (ADR-012), 8 new JVM tests, device-verified.

## Known problems / risks
1. Occasional UDP burst loss (1/15 VPN runs, 3.4 %, p99 137 ms) with zero forwarder/capture errors — unexplained.
2. TCP is terminated locally: SYN-ACK precedes upstream connect; captured TCP packet boundaries are lwIP's.
3. ICMP not forwarded. App's own traffic never captured (self-exclusion, ADR-006).
4. Short UDP flows (system DNS) often stay `unresolved` (socket gone before lookup).
5. Per-packet forwarding cost at low packet rates is high (29–66 µs/pkt engine CPU at 2–5k pps) — forwarding
   (B) cost, not logging; candidates: batching TUN reads/writes, pbuf pool instead of malloc. Not optimized
   (plan: optimize only after profiling).
6. Moved captures in `Download/MiniPcap` are outside app-private storage (USB, all-files-access apps);
   a move needs one capture's size + 64 MiB free; a move running during a new capture adds disk I/O (not measured).
7. Debug-only automation hook on the launcher activity (ignored in release builds).
8. Personal test phone: system-wide CPU numbers noisy; no power meter.

## Next bounded tasks
- [ ] Independent review of engine.c (TCP relay state machine, fd/pcb lifetime) and capture.c (ring/writer).
- [ ] Physical notification-tap Stop test; permission-denied (V10); VPN revoke by another VPN (V12).
- [ ] P2: energy/thermal (battery stats or meter), cellular + Wi-Fi↔cellular handover, snaplen sweep (V33),
      second Android version (API 29–33 path for upload jobs).
- [ ] Perfetto/simpleperf profile of `mpc-engine` before any forwarding optimization.
- [ ] Coordinator sign-off on provisional P2 budgets using TEST_RESULTS §5.
- [ ] Host test gap: downlink IP-fragmented (chained pbuf) packets through the engine.
- [ ] Rerun P0/P1 on device: earlier B–F CPU numbers predate the TCP relay busy-loop fix.
- [ ] ADR-014 on device (phase 5): run `validation/scripts/device_meta_check.py`; Wi-Fi + cellular walk with GPS/radio/motion on; check SLL direction
      in Wireshark, every record type in `mpcanalyze.py dump`, cell refresh rates, NSA override,
      permission-denied paths, FGS location type on Android 17; motion modes and rates; rerun P1 + soak
      (writer cost, `.meta` growth and drops at 50/200 Hz motion, battery).
- [ ] Downloads move: UI delete on device, MTP browse from a desktop, API 29–32 device, capture drops while a large move runs.
- [ ] CI (GitHub Actions or similar) running native tests, JVM tests and receiver tests.

## New session handoff
Read `IMPLEMENTATION_PLAN.md` → `AGENTS.md` → this file → `docs/DECISIONS.md` → `docs/PERFORMANCE_PLAN.md`
→ `docs/TEST_RESULTS.md`. Host tools: tshark is user-local in `~/.local/opt/wireshark` (wrapper in `~/.local/bin`).
Device workflow: `adb install -r …`, wait ~5 s, `adb shell appops set dev.minipcap ACTIVATE_VPN allow`,
then use `am start -S -n dev.minipcap/.ui.MainActivity --es cmd …` (see README).
Port 8443 on the dev host is used by an unrelated service; the reference receiver was run on 9443.
