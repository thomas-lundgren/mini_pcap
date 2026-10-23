# Project Status — Android Lightweight PCAPNG Logger

**Updated:** 2026-10-23
**Milestone:** M0–M6 implemented and device-tested on one phone; P0/P1 measured; M7/P2 partially (soak only)
**State:** IN PROGRESS — needs independent review, P2 battery/thermal/cellular, and the untested items below.
Evidence: `docs/TEST_RESULTS.md` (commands, device, raw paths). Decisions: `docs/DECISIONS.md`.

## Milestone tracker

| Milestone | Status | Evidence / gap |
|---|---|---|
| M0 Bootstrap + harness | DONE | Gradle/NDK build (`./gradlew assembleDebug testDebugUnitTest`), host native build, `bench.py`/`nettool`; no CI configured (local only) |
| M1 Forwarding + UID + P0 | DONE (1 device) | lwIP fork BSD-3 + socket relay (ADR-005); VPN VALIDATED; TCP/UDP/DNS/QUIC/IPv4/IPv6; UID 113/122 flows first lookup; P0 table in TEST_RESULTS §5. Gap: cellular, handover, 2nd device |
| M2 Native PCAPNG + sidecar | DONE | `check_native.sh`: fixtures byte-checked, independent Python parser + tshark agree; `flow_uid_map` join |
| M3 Native pipeline + P1 | DONE (P1 agent verdict PASS, review pending) | tap 0 allocs; stall 5 s → 0.04 % app loss, drops counted; logging ≈ +3–5 % process CPU vs B |
| M4 App filter UI | DONE (basic) | All/Include/Exclude, searchable picker (launcher apps), snaplen; V07 verified with shell UID. Gap: two real third-party apps |
| M5 Notification + Stop | DONE except tap test | systemExempted FGS, 1 Hz text, session-scoped Stop intent, idempotent stop (V09, V17), force-stop recovery (V11). Gap: physical tap on notification action, permission-denied, VPN revoke |
| M6 Upload | DONE | receiver + 14 tests; Kotlin↔Python cross test; device upload SHA-256 identical, replay 200, 409, 401 preflight, refused while recording |
| USB offload (ADR-012) | DONE (1 device) | finalized pairs moved to `Download/MiniPcap` with read-back SHA-256 check; force-stop mid-move recovered; upload from moved files. Gap: UI delete, MTP, API 29–32 |
| M7 / P2 | PARTIAL | 60-min soak PASS (23.6M records, 0 drops, bounded memory); no energy, thermal-stress, snaplen sweep, cellular, second API level, security review |

## Verified accomplishments (this session)
- Native data plane: `native/src/{engine,capture,flow,ring,pcapng,packet,jni}.c`; host tests 5/5 suites.
- Android app (Kotlin, no AndroidX): VPN service, UID resolver, package registry, sidecar + checkpoints,
  recovery, FileProvider share, settings with Keystore-encrypted token, JobScheduler/UIDT upload, UI.
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
- [ ] Downloads move: UI delete on device, MTP browse from a desktop, API 29–32 device, capture drops while a large move runs.
- [ ] CI (GitHub Actions or similar) running native tests, JVM tests and receiver tests.

## New session handoff
Read `IMPLEMENTATION_PLAN.md` → `AGENTS.md` → this file → `docs/DECISIONS.md` → `docs/PERFORMANCE_PLAN.md`
→ `docs/TEST_RESULTS.md`. Host tools: tshark is user-local in `~/.local/opt/wireshark` (wrapper in `~/.local/bin`).
Device workflow: `adb install -r …`, wait ~5 s, `adb shell appops set dev.minipcap ACTIVATE_VPN allow`,
then use `am start -S -n dev.minipcap/.ui.MainActivity --es cmd …` (see README).
Port 8443 on the dev host is used by an unrelated service; the reference receiver was run on 9443.
