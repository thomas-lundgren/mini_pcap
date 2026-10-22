# Mini PCAP Logger (Android, no root)

On-device packet logger built on `VpnService`. A native (NDK) data plane forwards all
TCP/UDP traffic of the selected apps through an on-device user-space stack (lwIP) and
records a truncated prefix of every IP packet at the TUN boundary into PCAPNG, with
direction, a per-flow ID and the owning app UID where Android reports it. A JSON sidecar
maps UIDs to packages/classes and resolves early packets of each flow retrospectively.
A foreground notification shows status and has a **Stop logging** action; a finalized
capture pair can be uploaded on demand to a configurable HTTPS receiver.

Status, evidence and open items: [`docs/STATUS.md`](docs/STATUS.md),
[`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md), [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Layout

```
app/                    Kotlin: VpnService, notification, UID worker, sidecar, recovery, upload, UI
native/                 C: engine.c (lwIP + socket relay + tap), capture.c (flow table, ring, writer),
                        pcapng.c, packet.c, flow.c, ring.c, jni.c; tests/ (host); tools/nettool.c
third_party/lwip/       vendored heiher/lwip @ e6d5fc6 (BSD-3-Clause)
validation/scripts/     check_native.sh (M2 gate), pcapng_tool.py (independent reader + sidecar join)
validation/upload-server/  receiver.py (reference receiver), test_receiver.py, make_certs.sh
validation/perf/        bench.py (P0/P1 orchestrator), summarize.py, build_nettool.sh
```

## Build

Requirements: JDK 17, Android SDK (platform 36, build-tools), NDK 27.2.12479018, SDK CMake 3.22.1.

```bash
./gradlew assembleDebug testDebugUnitTest      # APK + JVM tests (incl. upload cross-test)
./validation/scripts/check_native.sh             # native host tests + PCAPNG validation (tshark)
python3 -I validation/upload-server/test_receiver.py
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Host tools used by validation: `tshark`/`capinfos` (Wireshark ≥ 4.2), Python 3.10+, gcc/cmake/ninja.

## Use

1. Open the app, choose **All / Include / Exclude** apps and bytes per packet (default 256 B),
   tap **Start logging** and accept the VPN dialog (and the notification permission).
2. Stop from the notification (**Stop logging**) or in the app. Both files appear under
   *Saved captures*; tap one to share the pair or upload it.
3. Settings: HTTPS server URL, optional API token (stored encrypted), Wi-Fi-only, **Test**.
   **Upload latest** sends the newest *complete* capture + sidecar (never during recording).

Reading a capture on a computer:

```bash
tshark -r <id>.pcapng -T fields -e frame.time_epoch -e frame.packet_flags_direction -e ip.src -e ipv6.src -e frame.comment
python3 validation/scripts/pcapng_tool.py join <id>.pcapng <id>.meta.json --csv   # timestamp,src,dst,proto,...,uid,packages,app_class
```

Direction: `epb_flags` outbound (0x2) = uplink app→network; inbound (0x1) = downlink.
Comment grammar: `f-<flow>` or `u-<uid>;f-<flow>`; no comment = no flow ID.

## Reference receiver

```bash
cd validation/upload-server
./make_certs.sh <receiver-LAN-IP>      # TEST CA + server cert; copies CA into the debug build
python3 -I receiver.py --port 9443 --cert certs/server.pem --key certs/server.key --data data --token-file token.txt
```

Debug builds additionally trust that test CA (`app/src/debug/res/xml/network_security_config.xml`);
release builds trust system CAs only and are HTTPS-only.

## Benchmarks (debug build)

```bash
validation/perf/build_nettool.sh && native/build-nettool-host/nettool server 5201 &
adb shell appops set dev.minipcap ACTIVATE_VPN allow
python3 -I validation/perf/bench.py --host <host-LAN-IP> --repeats 3 --stall
python3 -I validation/perf/summarize.py validation/perf/results/<device>/<date> --md summary.md
```

Debug builds accept automation extras on the launcher activity (`--es cmd start|stop|stall|upload|server`);
release builds ignore them. The `server` command puts the token on the adb command line (visible in
adbd's log) — use it only with throwaway test tokens.

## Known limitations

- Capture point is the VPN TUN, not the radio. TCP is terminated locally by lwIP: SYN-ACK is
  synthesized before the upstream connect, and downlink segmentation/ACK timing are the stack's.
- ICMP is not forwarded (ping fails while capturing). Apps excluded from the VPN are not captured;
  the logger always excludes itself.
- UID attribution uses `getConnectionOwnerUid` after the first packet; very short UDP flows (e.g.
  system DNS) can end before the lookup and stay `unresolved`.
- Only one VPN can be active; starting another VPN stops the capture (`stop_reason: vpn_revoked`).
- Recovered (force-stopped) captures are kept locally with `status: recovered` and are not
  selected by *Upload latest*.
