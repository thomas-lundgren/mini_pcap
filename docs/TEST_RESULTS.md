# Test Results

No tests have been executed; implementation has not begun.

When running a test, record:
- UTC time, operator or agent, commit hash
- Android device model/API/build and network type, or host/tool version
- Exact commands and test fixture identifiers
- Expected result, observed result, pass/fail and supporting output
- Reproduction steps for failures and links to attached logs

## Upload verification (planned, **NOT TESTED**)
- Configure URL/token, test connection and save/reload settings.
- Capture, notification Stop, **Upload latest**, SHA-256 check on both server artifacts and local manifest.
- Repeat same upload key, simulate lost response/interrupted body, reject conflicting same-ID payload.
- Negative cases: TLS mismatch, 401/403, 413, 422, 5xx, offline/roaming, cancel, low storage.
- Verify capture files remain on device and token never appears in logs or packet content.
- Validate Android 29/34/36+ transfer lifecycle or explicitly list untested versions.

## Low-overhead performance evidence (planned, **NOT TESTED**)

Authoritative procedure: `docs/PERFORMANCE_PLAN.md`. No benchmark results, performance claims or test artifacts exist yet.

| Gate | Status | Required result |
|---|---|---|
| P0 (M1) | NOT TESTED | Direct/no VPN A versus native VPN forwarding-only B, device and controlled workload |
| P1 (M3) | NOT TESTED | C prefix copy, D native writer, E UID, JNI/alloc audit, writer stall and drop isolation |
| P2 (M7) | NOT TESTED | F full app, G snaplen sweep, packet size mix, 1-hour soak, battery/thermal conditions |

Capture exact device and network setup, build commit, sample size, packet rate/size distribution, directional counts, p50/p95/p99 RTT and jitter, process/per-thread CPU time, file bytes, JNI/GC evidence, queue occupancy, logger drops **and** forwarding drops. Report paired deltas vs **VPN-only**, not only vs no-VPN baseline. Include raw traces, no estimates masquerading as measurements.

Additional planned correctness tests: native FD cleanup across Stop/restart, no per-packet JNI/capture allocations, first flow packet arriving before async UID attribution, flow-key reuse, non-flow/fragmented IP packets, and valid PCAPNG after partial write/crash recovery.
