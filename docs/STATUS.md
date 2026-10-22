# Project Status — Android Lightweight PCAPNG Logger

**Updated:** 2026-10-22  
**Milestone:** M0 — project bootstrap  
**State:** NOT STARTED  
**Implementation evidence:** None; document preparation only. Native capture and performance requirements are **proposals, NOT TESTED**.

## Milestone tracker

| Milestone | Status | Evidence / blocker |
|---|---|---|
| M0 Bootstrap + baseline harness | NOT STARTED | Android/NDK project and P0 harness not created |
| M1 Forwarding + UID + P0 | NOT STARTED | Highest-risk gate; no device or overhead measurement |
| M2 Native PCAPNG + sidecar core | NOT STARTED | Fixtures and writer not created; flow-ID join untested |
| M3 Native capture pipeline + P1 | BLOCKED | Depends on M1/P0 and M2; no profiling |
| M4 App filtering UI | BLOCKED | Depends on M1 |
| M5 Notification and Stop logging | BLOCKED | Depends on lifecycle + writer contracts |
| M6 Upload server + latest capture | BLOCKED | Depends on complete artifact storage and app UI |
| M7 P2 validation/release | BLOCKED | Depends on upload and capture integration; no benchmarks |

## Verified accomplishments

- Initial requirements and implementation architecture recorded in `IMPLEMENTATION_PLAN.md`.
- Added proposed upload-server settings, on-demand latest-complete upload, and receiver protocol. **Design only; not implemented or tested.**
- Agent handoff rules recorded in `AGENTS.md`.
- Added native hot-path constraints, retrospective flow-ID attribution, P0/P1/P2 gates and controlled benchmark variants in `docs/PERFORMANCE_PLAN.md`. **Design only, not implemented.**

## Key open decisions

1. Forwarding engine and licensing approach, including native observation hook and FD ownership.
1a. Native capture queue design: MPSC vs per-producer ring, capacity and full-packet buffer policy.
1b. Performance budget sign-off after P0, including logging overhead above VPN-only.
1c. Flow-ID/UID comment grammar and sidecar `flow_uid_map` version compatibility.
2. Target device and full Android API-level validation matrix.
3. Whether production distribution requires an all-installed-app picker and broader package visibility.
4. Direction flag interpretation validated against chosen PCAPNG parser.
5. Upload receiver implementation/deployment target, token provisioning and retention policy.
6. Transfer scheduling choice by Android API version and on-device validation.

## Next bounded tasks

- [ ] Create Kotlin + NDK Android/Gradle project with `VpnService` skeleton, native core and CI build.
- [ ] Create performance harness variants A/B/C/D/E/F and run P0 no-VPN versus VPN-only on a physical target phone. Preserve device, packet-rate, CPU/packet, RTT and throughput baseline.
- [ ] Run a concrete Android forwarding and UID lookup spike on a physical device; record TCP, UDP, v4/v6 results and license decision.
- [ ] In parallel, build standalone **native** PCAPNG writer fixtures and sidecar/`flow_uid_map` join tests.
- [ ] Design native reusable packet buffers and async UID worker contract, but do not call P1 passed without a measured device run.
- [ ] Freeze `docs/UPLOAD_PROTOCOL.md` as client/receiver contract before parallel implementation.
- [ ] Add mock HTTPS receiver fixtures and negative tests during M6.
- [ ] Update `docs/TEST_RESULTS.md` with commands and reproducible outputs.

## New session handoff

Read `IMPLEMENTATION_PLAN.md` → `AGENTS.md` → this status → `docs/DECISIONS.md` → `docs/PERFORMANCE_PLAN.md`. Do not mark a milestone as DONE without a test command and reproducible evidence. Update this document before exiting each session.
