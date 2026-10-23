# Test coverage

Each requirement maps to the tests that cover it. **Host** = runs on the development machine (CI-able);
**Device** = needs a phone (scripts exist, results in `TEST_RESULTS.md`). Status as of 2026-10-23.

## How to run

```bash
./validation/scripts/check_native.sh                  # native unit tests + PCAP checked by the analyzer reader and tshark
./native/build-host/bench_capture 2000000 /tmp        # native capture-path performance (report + regression guard)
./gradlew testDebugUnitTest                           # JVM: format, writer, recovery, export, upload, analyzer cross-check, performance
python3 -I validation/upload-server/test_receiver.py  # upload receiver protocol
python3 -I analyzer/test_mpcanalyze.py                # analyzer correlation + scaling (MPC_PERF_PACKETS=… to size)
python3 -I validation/scripts/device_meta_check.py --host <ip>    # device: end-to-end acceptance (all collectors)
python3 -I validation/perf/bench.py --host <ip> --repeats 3 --stall  # device: P0/P1 overhead
python3 -I validation/perf/soak.py --host <ip> --minutes 60          # device: endurance
```

## Functional coverage

| Requirement (spec §) | Host tests | Device | Status |
|---|---|---|---|
| PCAP opens in Wireshark, UL/DL per packet (§3, AC 1) | `test_pcap` (byte layout, SLL types, protocol); `check_native.sh` (independent reader + tshark `sll.pkttype`, lengths, ns time) | `device_meta_check.py` (both directions) | Host PASS; device NOT TESTED |
| Truncation keeps direction and lengths; transport header always kept (§2.1, AC 2) | `test_packet` (hdr_len for IPv4/IPv6, TCP options, UDP, ICMP, ext headers incl. AH, fragments, truncation); `test_capture` header floor (snaplen 32 + headers-only: 40/72/48 B); analyzer `validate` + `test_header_floor_validation` | `device_meta_check.py` (validate) | Host PASS |
| Downlink chained buffers parsed contiguously | — (engine change; `test_engine` covers unchained paths) | NOT TESTED | gap |
| Packet time = entry into the capture path; monotonic time recoverable (§6) | `check_native.sh` (exact boot_ns from PCAP time); `test_capture` (first-seen = packet ts) | — | Host PASS |
| Binary metadata format, versioning, unknown types skipped (§5) | `MetaWriterTest` (framing, unknown type, oversize, critical records), `test_unknown_types_and_trailing_fields_are_skipped`; format cross-checked Kotlin → Python | `device_meta_check.py` | Host PASS |
| Asynchronous, independent sources; missing data explicit (§4, AC 3, 4, 7) | `MotionFilterTest` (all / max rate / threshold); analyzer `before_first_fix`, `no_data`, stale flags | `device_meta_check.py` (SENSOR_STATUS per source, record kinds, accel rate) | Host PASS; device NOT TESTED |
| Location, GNSS, radio (identity, measurements, signal, technology), Wi-Fi, network collectors (§4.1–4.5) | encoders via `MetaWriterTest` cross-check (LTE/NR cells, location, motion) | `device_meta_check.py` | collectors **NOT TESTED** on device |
| Timestamp sources, clock sync, wall-clock changes (§6, AC 5) | `MetaWriterTest` (anchors), analyzer time conversions + `context-at` formats | NOT TESTED (time-change broadcast) | partial |
| App attribution reconstructable (§4.4, AC 6) | `test_capture` (every flow announced, retry after queue overflow: 5000/5000); analyzer flow generations, unmapped generation not inherited, Kotlin→Python cross test | `device_meta_check.py` (> 95 % of TCP/UDP packets attributed) | Host PASS |
| Metadata never blocks packets; losses counted (§8, AC 8) | `MetaWriterPerfTest` (no blocking, 0 alloc/record), `exhaustedPoolDropsAreCountedNeverBlock`, `test_capture` stall + storage error (written + dropped = offered) | `bench.py --stall` | Host PASS |
| Clean Stop: matching, complete files (AC 9) | `MetaWriterTest` (SESSION_END last, close result), `SessionStoreTest` (finalize/recovery states) | `device_meta_check.py`, `device_lifecycle.py` | Host PASS; device NOT TESTED (new build) |
| Recovery after interruption (§8) | `SessionStoreTest` (partial PCAP/meta, half records, idempotent), `test_truncated_meta_is_readable_but_invalid` | force-stop test (V11) | Host PASS; device NOT TESTED (new build) |
| Analyzer: context for a timestamp, interpolation guards, out-of-order records, staleness (§7, AC 10) | `test_mpcanalyze.py` (14), `MetaWriterTest.analyzerReconstructsContextFromKotlinWrittenFiles` | — | Host PASS |
| Upload of the pair, protocol v2 (§9) | `UploadClientTest`, `UploadIntegrationTest` (Kotlin ↔ Python receiver over TLS), `test_receiver.py` (14, incl. meta session id / end status / truncation) | V20–V23 | Host PASS; device NOT TESTED (new build) |
| Move to Downloads, verification, crash safety | `CaptureMoverTest` (8) | ADR-012 device checks (previous build) | Host PASS |

## Performance coverage

| What | Test | Host result (this machine) | Device |
|---|---|---|---|
| Tap cost per packet, writer throughput, drop accounting per snaplen mode | `bench_capture` | 70–90 ns/packet; headers-only 74 B/record, 4.0 M records/s end to end; every packet accounted for | `bench.py` P1 (previous build: +3–5 % CPU) — rerun NOT TESTED |
| No allocation on the tap | `test_capture` `no_alloc_on_tap` (mallinfo2, 200k packets) | 0 bytes | — |
| Metadata producer allocation and throughput | `MetaWriterPerfTest` | ~1.5 B/record (motion), ~1.6 M records/s | — |
| Analyzer scaling | `test_mpcanalyze.py` `AnalyzerPerformance` | ~60–70 k packets/s, flat memory (streamed) | — |
| Endurance, memory, file growth | `soak.py` | — | previous build PASS (60 min); new build NOT TESTED |
| Battery / thermal with collectors | — | — | NOT TESTED (needs device + meter) |
