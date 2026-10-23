# Agent Instructions — MiniPcap (Android packet logger with asynchronous metadata)

Read, in this order, **before** continuing work: `docs/STATUS.md` → `docs/DECISIONS.md` (latest ADRs win;
ADR-014 defines the file formats, ADR-015 the code structure) → `docs/META_FORMAT.md` →
`docs/PERFORMANCE_PLAN.md` → `docs/TEST_COVERAGE.md` → `docs/UPLOAD_PROTOCOL.md` (for upload work).
`IMPLEMENTATION_PLAN.md` is the original plan; where it conflicts with an accepted ADR, the ADR wins.
Treat these files as the authoritative handoff between sessions; do not repeat earlier investigations
without a new specific reason.

## Mission
Ship a **measured low-overhead**, no-root Android `VpnService` packet logger:
- per-app capture (All / Include / Exclude) into a **PCAP** file where every packet carries its
  timestamp, original and captured length, and **direction** (Linux SLL packet type);
- **asynchronous, timestamped metadata** in a compact binary `.meta` file: position, motion, radio
  (technology, serving and neighbor cells, signal), network/Wi-Fi state, app attribution
  (UID → packages, flow → UID), clock sync and loss diagnostics, each source at its own rate;
- a **post-processing analyzer** that correlates both files by timestamp;
- a foreground notification with status and a **Stop logging** action independent of the Activity;
  crash-safe files with next-launch recovery; move to Downloads for USB offload; and user-triggered
  HTTPS **Upload latest** of the finalized pair.

Fundamental rule: **keep packet capture simple and fast.** Everything except timestamp, direction,
lengths and packet bytes is recorded once, as an independent event, and reconstructed afterwards.

## Priorities and performance gates
1. **P0:** measure **A: no VPN** and **B: VPN forwarding-only** on the same physical device before any
   claim about logging cost.
2. **P1:** benchmark variants: **B** forwarding only; **C** tap + ring into a null sink; **D** + PCAP
   writer and `.meta` (no collectors, no flow lookups); **E** + flow-owner worker (FLOW_MAPPING,
   UID_MAPPING); **F** + measurement collectors (the only variant in release builds); **G** F with a
   snaplen sweep. Writer stalls never block forwarding.
3. **P2:** CPU per packet, loss, throughput, latency, memory, allocation, metadata queue behavior,
   battery/thermal and 1-hour endurance; lifecycle, recovery and upload on device.
[`docs/PERFORMANCE_PLAN.md`](docs/PERFORMANCE_PLAN.md) is the authoritative benchmark contract. Do not
replace benchmarking with subjective claims that native code will be fast.

## Contracts (change only with an ADR and updated tests)
- **Packet file** `<id>.pcap`: classic PCAP, nanosecond magic, `LINKTYPE_LINUX_SLL` (113). SLL packet type
  **4 OUTGOING = uplink, 0 HOST = downlink**; PCAP lengths include the 16-byte SLL header; timestamps are
  CLOCK_BOOTTIME at the capture point converted with the session anchor stored in the meta header.
  The SLL header exists only in the file, never on the wire.
- **Header floor:** every record keeps at least the complete IP + transport header (TCP incl. options,
  UDP, ICMP; IPv6 extension headers included), cut at max(configured length, 192 bytes). Unparsable
  packets keep the configured length (40 bytes in headers-only mode).
- **Metadata file** `<id>.meta`: [`docs/META_FORMAT.md`](docs/META_FORMAT.md) is the contract. Little
  endian, versioned, 8-byte-aligned typed records with monotonic timestamps and timestamp-source flags;
  unknown types are skipped by length; unavailable values are marked absent (presence bits), never
  estimated; `SESSION_END` is always the last record. New record types or trailing fields are minor
  versions; changing a field's meaning needs a new major version.
- **Attribution:** each TCP/UDP flow announced by the packet path gets at most one `FLOW_MAPPING`
  (5-tuple + exact first-packet time → UID, or unresolved with its reason), normally exactly one.
  Gaps are counted, never hidden: `flow_table_full`, `uid_request_queue_overflows` (an announcement
  that did not fit is retried on the flow's next packet; a flow without one stays unannounced),
  `DROPPED_EVENTS`, and a flow worker that misses the 3 s join at Stop. `UID_MAPPING` names apps. No
  per-packet app data in the PCAP; the analyzer reports a flow without a mapping as unknown and never
  lets a new connection inherit another's app.
- **Pair integrity:** never upload, move or share `.partial` files; never send a packet file without its
  matching metadata file; a session is COMPLETE only when both files are complete (metadata ends with
  `SESSION_END` complete). At finalization the metadata file is renamed before the packet file (with
  rollback). Only COMPLETE sessions are uploaded (never RECOVERED ones, never while recording), and
  success requires a verified receipt with both SHA-256 digests (protocol v2,
  [`docs/UPLOAD_PROTOCOL.md`](docs/UPLOAD_PROTOCOL.md)).
- **Older sessions** (`SessionFormat.LEGACY`: `.pcapng` + `.meta.json`, app ≤ 0.1.0) stay shareable
  and movable but are never uploaded; an interrupted legacy session is marked FAILED, not recovered.
- **Counters:** `MPC_COUNTERS` in `native/include/mpc/capture.h` is the single source of counter names;
  shared native/Kotlin record layouts are checked at start (`NativeCore.checkLayout`).

## Architecture rules
- **Packet path is native and bounded:** no per-packet JNI, Kotlin allocation, Android API call, text
  formatting, logging, file write/fsync, upload or UI action on the forwarding thread. JNI is lifecycle
  and batched control only; buffers are preallocated and reused; forwarding never waits for the writer;
  under pressure the tap drops capture records (counted per direction), never forwarded packets.
- **Metadata path never blocks capture:** collectors encode records into pooled buffers and hand them to
  one writer thread; no blocking and no per-sample allocation on high-rate sources (motion); pool
  exhaustion drops the record and is reported (`DROPPED_EVENTS`). Missing permissions, sensors or APIs
  are reported (`SENSOR_STATUS`), never faked. Prefer source timestamps (sensor, location fix, modem);
  otherwise mark the timestamp as logger time.
- **Correlation belongs to the analyzer** (`analyzer/mpcanalyze.py`, standard library only): states use
  the latest valid value, samples carry their age and a stale flag, positions are interpolated only
  between fixes that are close in time. Input files are never modified.
- **Layered packages, acyclic dependencies** (ADR-015): a package imports only packages in lower layers:
  [`core`, `capture`, `meta`, `notify`] < [`meta.apps`, `meta.collect`] < `session` < `storage` <
  [`upload`, `service`] < `ui`. The root `App` sits outside the layers.
  Keep format/codec code pure JVM so it is testable without a device. Native: `engine.c` (loop, TUN I/O +
  tap, gateway, lifecycle), `relay_tcp.c`, `relay_udp.c`, `capture.c` (flow table, ring, writer),
  `pcap.c`, `packet.c`, `flow.c`, `ring.c`, `jni.c`; internals shared only via `src/engine_internal.h`.
- One recording's lifecycle lives in `session/CaptureSession`; Stop and start failure share one
  teardown order (collectors → native stop → flow worker → app lookups); then Stop writes `SESSION_END`
  and commits the files, while a failed start abandons and deletes both files. Distinguish the
  notification's **Stop logging** (graceful) from Android's Task Manager **Stop** (no callbacks):
  recover from `.partial` files on the next launch, off the main thread.

## Agent rules
- Coordinator delegates narrowly scoped, short-lived tasks; always request exact commits/files, actual
  test commands and output, and unsolved issues. Sub-agent reviews are read-only unless told otherwise.
- No fabricated measurements or claims that tests passed. Label unexecuted work `NOT TESTED`.
  Distinguish host results from device results.
- Do not copy PCAPdroid or other third-party source or binaries without a recorded licensing decision.
- Never compromise packet forwarding to make a logging test pass; logging failures have separate
  metrics. **Report three costs separately:** baseline networking, VPN-forwarding-only penalty, and
  incremental capture + metadata overhead.
- A claim of "minimal overhead" requires P0/P1/P2 raw evidence on the same device and workload (packet
  rates and size distributions) and an independent review. Do not invent optimization results.
- Upload is user-triggered and independent of Stop; keep credentials out of logs and files; keep local
  files after failures.
- **Debug-only hooks stay debug-only:** automation commands (`ui/DebugCommands`), the writer-stall
  action, the variant selector and the test CA (`app/src/debug`) must remain behind
  `BuildConfig.DEBUG` or the debug source set; release builds always run variant F.
- **Tests travel with code:** every behavior change updates or adds a host test (native suites,
  JVM, receiver, analyzer) and the row in `docs/TEST_COVERAGE.md`; performance-relevant changes rerun
  `bench_capture`/`MetaWriterPerfTest` and, on device, the affected `bench.py` variants (device P0/P1
  numbers so far come from the previous PCAPNG build; the rerun for the current format is NOT TESTED
  until done). Host commands:
  `validation/scripts/check_native.sh`, `./gradlew testDebugUnitTest lintDebug`,
  `python3 -I validation/upload-server/test_receiver.py`, `python3 -I analyzer/test_mpcanalyze.py`.
- Update `docs/STATUS.md` and `docs/TEST_RESULTS.md` at the end of each session; record architecture
  decisions in `docs/DECISIONS.md`. Performance tasks supply a short per-variant B/C/D/E/F overhead
  summary with raw result paths and environment metadata.
- Avoid a generic analytics stack, broad permissions, TLS interception or other out-of-scope features.
  Measurement permissions (location, phone state) are requested only for enabled sources.

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
If real Android forwarding fails, a viable low-overhead native capture path cannot be verified, flow
attribution or a required measurement source is unsupported in the chosen design, metadata collection
measurably degrades forwarding, or a dependency's license is incompatible: stop dependent
implementation and report the concrete blocker to the coordinator.
