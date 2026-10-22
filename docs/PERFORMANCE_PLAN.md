# Low-Overhead Capture: Architecture, Benchmarks and Acceptance Gates

**Status:** PROPOSED — design only; no device implementation or performance results exist.  
**Owner:** Performance/measurement agent, reviewed independently by coordinator and native-capture agent.  
**Applies to:** Android API 29+, native `VpnService`/TUN data plane, PCAPNG snaplen capture, UID attribution, UI notification, upload.

## 1. Purpose and primary invariant

**Minimize incremental capture overhead over the unavoidable no-root Android VPN forwarding cost.** Always report the three distinct costs:

1. **Baseline networking cost** without the VPN.
2. **Additional VPN forwarding cost** compared with baseline (may dominate and may modify packet boundaries and timing).
3. **Additional logging/attribution cost** compared with VPN-only forwarding on the *same* device, network and workload.

Do not claim that packets observed at the TUN boundary are identical to radio-interface packets. Preserve app connectivity; never slow forwarding to avoid losing capture records. If logging cannot keep up, account for dropped **log records**, not app packets, and provide counters.

## 2. Hot-path design contract

The native path, conceptually:

```text
Native TUN read / downlink forwarder packet-ready
  -> take monotonic timestamp at observation point
  -> bounds-check minimal IPv4/IPv6+L4 header fields
  -> normalized bidirectional flow lookup (cached UID/flow ID)
  -> reuse queue slot, copy only min(snaplen, IP length) bytes
  -> non-blocking enqueue OR count capture drop
  -> continue forwarding immediately

Writer thread (independent):
  -> dequeue prefix+fixed metadata -> serialize SHB/IDB/EPB
  -> append `f-<id>` and optionally `u-<uid>` comment when available
  -> batch sequential file writes; periodic flush, sync on Stop

Kotlin worker / control (out of packet path):
  -> async lookup of UID once per new flow, bounded retries
  -> batch responses to native flow cache
  -> package/class resolution; ~1 Hz counters and notification
  -> finalized capture upload only when recording has stopped
```

**MUST NOT occur on a packet-processing/forwarding thread:** per-packet JNI callback, Kotlin `ByteArray` construction, Java GC-triggering capture allocations, framework UID/package lookup, PCAPNG block formatting, file write/fsync, hash computation, UI callback, logcat formatting or server upload.

**Native packet path should** reuse a bounded queue/pool (initially test 4/8/16 MiB capacity), minimize parser work, avoid unnecessary packet-body copying, use a cached flow-key hash, and perform one captured-prefix copy. TUN/user-space forwarding may still require unavoidable full-packet copying and read/write syscalls: this project must not claim *zero copies* or *zero syscalls*.

Use an existing, licensed and proven forwarding implementation if possible; optimizing packet capture is not a reason to invent a new TCP/IP stack. The module should be replaceable. Favor simple correct SPSC/per-producer rings or a tested bounded MPSC over unproven lock-free complexity. If full-packet mode is requested, use a separate bounded pool with well-documented memory constraints.

### Flow/UID consistency without blocking

Assign a session-unique 64-bit `flow_id` when possible. Write that ID in every record of that flow, **including packets captured before UID resolution**. Queue unresolved new-flow UID requests asynchronously (deduplicated, bounded), and build a `flow_uid_map` in the sidecar. Initial records can retrospectively inherit the UID and app class in offline processing. If OS UID attribution never succeeds, keep the mapping unknown; do not assign the logger's UID or assume the app from a port. Normalized flow IDs must not be reused across later distinct flow generations on socket/tuple reuse.

A packet that cannot be classified into a flow (e.g. some ICMP or non-initial fragments) must still be captured with explicit unknown/missing-flow metadata. The reader must not infer a fake UID. The v1 EPB comment grammar is specified in `IMPLEMENTATION_PLAN.md`; build it in the writer, not on the forwarding thread. A native binary option under an assigned PEN may be explored *later* and must be benchmarked before changing the format.

### Time semantics

Timestamp UL at native TUN read observation and DL just before native TUN inject/write. Prefer a native monotonic source consistent with Android's elapsed realtime (`CLOCK_BOOTTIME`), with recorded monotonic/UTC anchors. Transform timestamps away from the packet-processing thread. Microsecond PCAPNG resolution is a file encoding property, **not** proof of timestamp accuracy. Validate clock rollback/slew cases separately.

## 3. Required experimental variants (same forwarding code)

| Variant | Configuration | Isolates |
|---|---|---|
| A | Direct network, no VPN | Device/network baseline |
| B | VPN forwarding only; capture tap disabled | Forwarding penalty |
| C | B + native timestamp/parse/prefix copy + drain-to-null queue | Packet observer + memory-copy overhead |
| D | C + native PCAPNG writer, UID resolution OFF, compact flow ID ON | Serialization/disk cost |
| E | D + bounded async UID resolution and flow cache | UID attribution incremental cost |
| F | Full app capture, 1 Hz notification, sidecar checkpoints | End-to-end implementation cost |
| G | F snaplen sweep 64, 128, 256, 512 and full | Data-volume sensitivity |

Build all variants behind development-only compile-time/runtime switches; they must run the *same forwarding engine* and traffic workload. A sink/queue variant is meaningful only if its producer/consumer lifetime and queue-copy semantics match production.

## 4. Workload and device matrix

- **Devices:** main target phone, plus at least one distinct Android API level when available. Record model, SoC, OS/API, build, charging mode, battery level and power/thermal state.
- **Networks:** controlled local Wi-Fi first (avoid changing RF conditions), then cellular 5G/LTE as available with recorded signal/network context. The wired/remote test server and app must be constant across variants.
- **UDP traffic:** small IP packets to drive 5k/10k/20k packets/s where test hardware/network permits, and larger 1200–1500 B packets. Avoid assuming a phone can sustain all requested rates; report achieved rates, loss and load. Include uplink and downlink.
- **TCP traffic:** single and multiple flows (HTTPS or iperf-like); report goodput, connection time and retransmissions if measurable. Test short connection churn and concurrent UDP.
- **Real-time traffic:** WebRTC/QUIC sample with variable bitrate and p50/p95/p99 one-way packet spacing/RTT where clocks permit; record application-level jitter and stalls, without claiming causality solely from TUN timestamps.
- **Metadata stress:** many short TCP/UDP flows, ambiguous/missing UID, high connection churn, package-resolution latency. Specifically verify first packet captured before UID lookup completes.
- **Stalls:** pause/throttle PCAPNG consumer for 1–5 s at fixed packet load, and inject disk-full errors. Measure capture loss/queue watermarks and whether forwarding continues.
- **Duration:** at least 60 s warmup, 3 paired repeats (randomized A/B/C/D/E/F order where practical), 10 min small-packet stress, and a 1 hour mixed soak. Record temperature/throttling; discard or label distorted comparisons.

## 5. Measurements and units

| Metric | Mandatory reporting |
|---|---|
| Traffic | attempted/achieved packets/s, wire/IP byte rate, packet-size distribution, direction, concurrent flows |
| Forwarding | app goodput, p50/p95/p99 RTT and/or jitter, forwarding loss, failures, packet boundary changes |
| CPU | process CPU-time / million forwarded packets, per-thread CPU time, load/thermal state, CPU utilization |
| GC/JNI/allocations | per-packet JNI crossings in capture path (target 0); per-packet logger heap allocations (target 0), JVM GC counts |
| Writer | PCAPNG output MB/s and bytes/packet, number and size of file write syscalls, write stall time |
| Memory | native heap/RSS peak, writer queue average/peak occupancy and pool allocation count |
| Capture correctness | offered/accepted/written/dropped logger records by direction and reason; all counts reconciled |
| Attribution | UID lookup requests / unique flows, cache hit rate, `INVALID_UID` misses, resolution latency, flow-ID joins |
| UX/background | notification update frequency (target about 1 Hz), Stop finalization latency, recoverability after kill |
| Power | energy/battery drain with controlled measurement conditions; relative comparison only if meter/conditions defensible |

**Counter definitions** must be stable. For example, a log-record drop is a failed enqueue after packet observation, *not* a network packet that failed forwarding. Writer failures must be counted separately. In event of excessive load, do not contaminate clock or network thread with per-packet logging to collect metrics. Prefer simple counters sampled periodically and system-level traces (e.g. Perfetto) when available.

Raw output naming suggestion: `validation/perf/<device>/<date>/<variant>-<workload>-runN.{json,trace}`. Do not commit sensitive captures or tokens into public repositories.

## 6. Gates and proposed budgets

### P0 — Forwarding feasibility / before broad coding (M1)

- Run direct A and forwarding-only B on a real phone.
- Validate TCP, UDP, DNS, IPv4 and IPv6 (where available), sockets protected against VPN recursion and Wi-Fi↔cellular transitions.
- Publish the **forwarding penalty** separately from logging, plus measured packet fidelity caveats and dependency license decision.
- If forwarding fails or makes target workloads unusable, STOP dependent development.

### P1 — Native pipeline and backpressure (M3)

- Profiling/code audit confirms no capture-specific per-packet JNI, Kotlin allocation, framework UID lookup, filesystem syscall, string formatting or hash computation.
- Writer is independent; synthetic 1–5 s writer stall keeps network forwarding operational, queue memory bounded, capture losses **counted**, and no deadlock.
- Store repeatable B/C/D/E data (all variants on the same workload). Verify UID flow-ID retrospective mapping, PCAPNG parse correctness, and no detectable unbounded allocations.
- Coordinator records provisional quantitative budgets and accepts any deviations before feature expansion.

### P2 — Release performance (M7)

**Proposed targets for controlled, non-thermally-throttled workloads; these are hypotheses, NOT achieved results and can be revised based on P0 evidence:**

| Quantity, relative to VPN-only B | Provisional target |
|---|---|
| Mean TCP/UDP goodput in full F | No more than 5% regression at same packet mix |
| p95 latency under controlled load | Less than 1 ms extra RTT versus B, when measurement resolution supports it |
| Forwarding loss | No material increase versus B under nonsaturated conditions; report confidence intervals |
| Capture record loss (sustainable 10-min test) | Target zero at demonstrated sustainable rate; report exact offered/written/lost counts |
| Logging-specific JNI and Java allocations | Zero *per packet* by implementation and profile |
| Memory footprint | Bounded within configured pools; no leak growth in 1-hour soak |
| Notification and upload | UI updates ~1 Hz; no active-session upload in MVP |

CPU overhead should be reported as **additional CPU-ms / million packets** for F−B and as percent of B for the *same achieved packet rate*. Avoid a fixed unvalidated absolute CPU budget before measuring P0. A high baseline VPN penalty must not be hidden by a small logging penalty. Do not call a failing workload a pass merely because the absolute throughput was low.

P2 must provide raw traces, summary table including median/spread across repeats, source commits, device/OS/network conditions, and a concise verdict: **PASS**, **FAIL**, or **WAIVED** with named reviewer and rationale. Never mark as PASS based on expected calculations or simulated packets alone.

## 7. Agent task breakdown

**Coordinator:** Freeze variant flags and reporting schema early, prioritize P0 before UI work, prevent performance scope creep; sign off each gate.

**Forwarder/native agent:** Benchmark candidate forwarding backends and FD/JNI integration; supply no-log forwarding baseline; preserve correct socket protection and throughput.

**Capture/PCAPNG agent:** Build bounded reusable queue/pools, native writer and epoch conversion; supply binary writer tests; instrument *sparse* queue counters; compare C/D/E.

**UID agent:** Implement asynchronous UID worker, deduplicated lookup requests, flow cache/flow ID, sidecar join and tests for first packet, unresolved and tuple reuse.

**Measurement agent (independent):** Own deterministic workloads, experiment scheduler, Perfetto/ADB collection, variant pairing, packet-level integrity checker, bottleneck attribution and independent P0/P1/P2 reports.

**Review agent:** Inspect memory ownership, threading, FD lifecycle, counter reconciliation, parser bounds, short-lived-flow UID join and PCAPNG compatibility; attempt to disprove claimed speedups with A/B tests.

## 8. Session handoff checklist

Record in `docs/STATUS.md` and `docs/TEST_RESULTS.md`:

- Variant, commit SHA, app/NDK/forwarder versions, device and API level.
- Exact build/run/workload commands, seed, traffic rate/packet sizes/direction, network path, repeats and test duration.
- Raw output artifact paths, calculations and interpretation, any thermal/CPU frequency effects.
- Gate P0/P1/P2 verdict with named accepting reviewer, unresolved risks, next bounded action.
- Any changes to code/data contracts including `flow_id`, `uid_map`, `flow_uid_map` and comment grammar.

**Explicit exclusions:** No unsupported “zero-copy packet capture” claims, no new root permission for MVP, no active-session upload, no forced app/network packet dropping to satisfy logger performance numbers, no claims about physical radio packet timestamps.
