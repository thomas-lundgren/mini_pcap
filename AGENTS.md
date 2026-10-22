# Agent Instructions — Android Lightweight PCAPNG Logger

Read `IMPLEMENTATION_PLAN.md`, `docs/PERFORMANCE_PLAN.md`, `docs/STATUS.md`, and `docs/DECISIONS.md` **before** continuing work. Treat these files as the authoritative handoff between sessions; do not repeat earlier investigations without a new specific reason.

## Mission
Ship a **measured low-overhead**, no-root Android VpnService packet logger with filtered app capture, truncated PCAPNG packets, per-packet UID where resolved (or stable flow ID for retrospective UID mapping) and direction, UID→app/class JSON sidecar, a foreground notification with capture status and a working **Stop logging** action independent of the Activity, plus a configurable HTTPS upload server and an in-app **Upload latest** action for the finalized PCAPNG + sidecar pair.

## Priorities and performance gates
1. **M0/P0 setup:** build the Android/NDK project and reproducible network-workload harness; measure **A: no VPN**, then **B: VPN forwarding-only** on the same physical device.
2. **M1/P0 GO/NO-GO:** prove no-root TCP/UDP/IPv4/IPv6 forwarding, UID feasibility, protected sockets, a licensed forwarding integration with native capture hooks; record the *VPN penalty* before any claim about logging cost.
3. **M2:** implement and independently validate a **native** PCAPNG writer and JSON sidecar with `flow_uid_map` fixtures.
4. **M3/P1 GO/NO-GO:** integrate native TUN observer, preallocated prefix queue, native writer, async flow-UID cache; benchmark copy-only/writer/UID variants and writer stalls without blocking forwarding.
5. **M4:** add Android-native app filter UI (All/Include/Exclude).
6. **M5:** foreground notification status (~1 Hz), session-scoped **Stop logging**, idempotent drain/finalization/recovery.
7. **M6:** secure server settings, latest completed pair selection, user-triggered upload, progress/retry/receipt; no upload during recording.
8. **M7/P2:** repeat controlled CPU/packet, loss, throughput, latency, memory, GC/JNI and 1-hour endurance benchmarks, and validate lifecycle, upload and recovery.

**Mandatory reading:** [`docs/PERFORMANCE_PLAN.md`](docs/PERFORMANCE_PLAN.md) is the authoritative performance/benchmark contract. P0 and P1 gates precede broad UI work. Do not replace benchmarking with subjective claims that native code will be fast.

## Agent rules
- Coordinator delegates narrowly scoped, short-lived tasks; always request exact commits/files, actual test commands and output, unsolved issues. End sub-agent context after concise handoff.
- No fabricated measurements or claims that tests passed. Label unexecuted work `NOT TESTED`.
- Do not copy PCAPdroid/other third-party source or binaries without a recorded licensing decision.
- Never compromise packet forwarding to make a logging test pass; logging failures have separate metrics. **Report three costs separately:** baseline networking, VPN-forwarding-only penalty, and incremental capture/UID/PCAPNG overhead.
- **Hot path must remain native:** no per-packet JNI/Kotlin `ByteArray` allocation, Android API UID lookup, PCAPNG formatting, logging, filesystem write/fsync, upload or UI action. JNI is lifecycle/batched control; native buffers are bounded/reused; forwarding never waits for a writer.
- A successful claim of "minimal overhead" requires P0/P1/P2 raw evidence, same device/workload, packet rates and size distributions, and an independent review. Do not invent optimization results or hard-code assumptions about CPU impact.
- For each parsable flow store a stable 64-bit `flow_id` in EPB metadata; writer-created v1 comments use `f-<id>` if UID pending or `u-<uid>;f-<id>` when cached. Sidecar `flow_uid_map` retroactively resolves early packets, and `uid_map` maps UIDs to package arrays/classes. Direction remains in EPB flags after parser validation; unknown stays unknown.
- Read `docs/UPLOAD_PROTOCOL.md` before upload-related work. Never upload `.partial` files, send a PCAPNG without the matching sidecar, or mark success without verified receipt/hash validation.
- Upload is user-triggered and independent of logging Stop; keep remote credentials out of logs/files and preserve local artifacts after failures.
- Distinguish notification action **Stop logging** (graceful) from Android OS Task Manager **Stop** (no callbacks): recover from `.partial` files on next launch.
- Freeze client/receiver protocol before separate short-lived agents implement either side; independently test duplicates, interrupted transfer and auth errors.
- Update `docs/STATUS.md` and `docs/TEST_RESULTS.md` at end of each session; add architecture decisions to `docs/DECISIONS.md`. Performance tasks must supply a short per-stage B/C/D/E/F overhead summary with raw trace paths and environment metadata.
- Avoid introducing a generic analytics stack, broad permissions, TLS interception, or other out-of-scope features.

## Task completion format
**Scope:** …  
**Files/commit:** …  
**Tests executed / results:** …  
**Risks/unknowns:** …  
**Changes to contracts:** …  
**Performance variant / measured overhead:** … (or `NOT TESTED`)  
**Gate verdict and evidence:** … (or `NOT TESTED`)  
**Status update written:** yes/no

## Stop condition
If real Android forwarding fails, a viable low-overhead native capture path cannot be verified, UID attribution is unsupported in the chosen design, or a dependency's license is incompatible, stop dependent implementation and report the concrete blocker to the coordinator.
