# MiniPcap — per-app packet logger for Android (no root)

MiniPcap records the network traffic of selected Android apps into standard **PCAPNG** files that
open directly in Wireshark. Every packet carries its direction and the app that sent or received it,
and a small JSON sidecar maps those apps to package names. It runs as an on-device VPN, so no root
and no computer are needed while capturing.

---

## Quick start

You need an Android 10+ phone.

1. Download `minipcap-<version>.apk` from the [latest release](https://github.com/thomas-lundgren/mini_pcap/releases/latest)
   and open it on the phone (allow installing from that source), or run `adb install minipcap-<version>.apk`.
   To build it yourself instead, see [Building from source](#building-from-source).
2. Open **MiniPcap** on the phone. Choose which apps to capture (**All**, **Include** or **Exclude**).
3. Tap **Start logging** and accept the VPN and notification prompts.
4. Use your apps as usual. The notification shows elapsed time, packets and file size.
5. Tap **Stop logging** in the notification (or in the app).
6. Copy the capture to your computer and open it:

   ```bash
   adb pull /sdcard/Download/MiniPcap/ .
   wireshark MiniPcap/<capture-id>.pcapng
   ```

   Or connect the phone with USB file transfer and copy `Download/MiniPcap/` with your file manager.

That's it. The sections below explain what is in the files and what else the app can do.

---

## Contents

- [What you get](#what-you-get)
- [Using the app](#using-the-app)
- [Output files](#output-files)
- [Analysing captures](#analysing-captures)
- [Uploading to a server](#uploading-to-a-server)
- [How it works](#how-it-works)
- [Performance](#performance)
- [Privacy](#privacy)
- [Limitations](#limitations)
- [Building from source](#building-from-source)
- [Testing and benchmarks](#testing-and-benchmarks)
- [Repository layout](#repository-layout)
- [License](#license)

## What you get

- **Per-app capture without root:** an Android `VpnService` carries the traffic of the apps you pick;
  other apps bypass it untouched.
- **Standard PCAPNG output:** raw IP packets with microsecond timestamps, truncated to a prefix you
  choose (64–512 bytes, or full packets).
- **App attribution per packet:** each packet's comment holds a flow ID and, once Android reports it,
  the owning app's UID. Packets seen before the UID was known are resolved afterwards via the sidecar.
- **Direction on every packet:** uplink (app → network) or downlink (network → app), in the standard
  PCAPNG flags field.
- **Control from the notification:** a status line updated every second and a **Stop logging** button
  that works with the app closed.
- **Crash-safe files:** if Android kills the app mid-capture, the next launch recovers everything
  written up to that point.
- **Easy offload:** finished captures are moved to `Download/MiniPcap/` for USB copying, or can be
  shared, or uploaded to your own HTTPS server.

## Using the app

### Choosing what to capture

| Setting | Meaning |
|---|---|
| **All** | Every app's traffic goes through the capture (except MiniPcap itself). |
| **Include** | Only the apps you select. Everything else bypasses the VPN. |
| **Exclude** | Everything except the apps you select. |
| **Bytes per packet** | How much of each IP packet to keep: 64, 128, **256** (default), 512 or full. The original length is always recorded. |

### Starting and stopping

Start from the app. While recording, a notification shows the elapsed time, packet count and file size,
with a **Stop logging** action. Stopping flushes and closes the files, usually in under a second (2.6 s for a 6 GB capture).

If the app is force-stopped or killed instead, the capture is marked **recovered** on the next launch:
the PCAPNG file is cut back to its last complete packet and the sidecar is rebuilt from the most recent
checkpoint (written every 10 seconds).

### Where captures are stored

While recording, files live in the app's private storage. When a capture finishes, MiniPcap **moves**
the pair to `Download/MiniPcap/`. The copy is checked with SHA-256 before the private one is deleted, so
each capture exists in one place. You can turn this off in **Settings → Storage** to keep captures
private, and move individual ones later from **Saved captures**.

Tap a capture in **Saved captures** to share the pair, upload it, move it, or delete it.

## Output files

Each capture is a pair with the same ID:

```
Download/MiniPcap/
├── 5b19ce96-9849-4644-9447-069c49759071.pcapng      packets
└── 5b19ce96-9849-4644-9447-069c49759071.meta.json   apps, flows, statistics
```

### `<id>.pcapng`

- Link type `LINKTYPE_RAW` (101): packets start at the IPv4/IPv6 header, there is no Ethernet header.
- Timestamps have microsecond resolution.
- **Direction** is stored in the packet flags: *outbound* (0x2) means uplink and *inbound* (0x1) means
  downlink.
- **Comments** identify the flow and, when known, the app:
  - `u-10234;f-17` means UID 10234, flow 17
  - `f-17` means flow 17, with the UID not yet known when the packet was written (look it up in the sidecar)
  - no comment means the packet is not part of a TCP/UDP flow (e.g. ICMPv6 or a fragment)

#### How per-packet metadata is stored

There are no separate metadata blocks. Each packet is one standard **Enhanced Packet Block** (EPB),
and its metadata is carried inside that block as two standard PCAPNG **options** after the packet
bytes:

| Option | Code | Content |
|---|---|---|
| `opt_comment` | 1 | app and flow as text: `u-10234;f-17`, or `f-17` while the UID is unknown |
| `epb_flags` | 2 | 4-byte value; the low bits hold the direction: 2 = outbound (uplink), 1 = inbound (downlink) |

Layout of one EPB for a 60-byte captured packet with comment `u-10234;f-17`. Fields are little-endian
and padded to 4 bytes:

```
offset  size  field
     0     4  block type = 0x00000006 (EPB)
     4     4  block length = 120
     8     4  interface id = 0
    12     8  timestamp in µs since 1970 (high 32 bits, then low 32 bits)
    20     4  captured length = 60
    24     4  original length (e.g. 1400, before truncation)
    28    60  packet bytes (IP header + start of payload)
    88     4  option header: code 1 (comment), length 12
    92    12  "u-10234;f-17"
   104     4  option header: code 2 (flags), length 4
   108     4  0x00000002 (outbound = uplink)
   112     4  option header: code 0 (end of options)
   116     4  block length = 120 (repeated so readers can walk backwards)
```

Packets that are not part of a TCP/UDP flow have no comment option, and the flags option is omitted
when the direction is unknown. With both options present, the metadata costs about 28 bytes per packet.

Information that applies to the whole file is written once at the start:

- **Section Header Block:** phone model, Android version and app version.
- **Interface Description Block:** link type 101 (raw IP), the maximum bytes kept per packet,
  microsecond timestamps (`if_tsresol` = 6) and the interface name `tun0`.

Because only standard options are used, any PCAPNG reader understands the file without a plugin.
Wireshark shows the comment as `frame.comment` and the direction as `frame.packet_flags_direction`.
Anything that would be wasteful to repeat per packet is in the sidecar instead: UID → app names and
class, and UIDs found after a flow's first packets were already written. That is why some packets
carry only `f-17`: look up flow 17 in `flow_uid_map` to get the app.

The writer is `mpc_pcapng_epb` in [`native/src/pcapng.c`](native/src/pcapng.c). It formats the comment
directly into the block on the writer thread, never on the packet-forwarding path. An independent
reader is [`validation/scripts/pcapng_tool.py`](validation/scripts/pcapng_tool.py).

### `<id>.meta.json` (sidecar)

The most useful parts:

```jsonc
{
  "capture_id": "5b19ce96-…",
  "status": "complete",                 // or "recovered" after a force-stop
  "started_utc": "2026-10-23T04:06:02.472Z",
  "snaplen_bytes": 256,
  "filter": { "mode": "include", "packages": ["org.example.app"] },
  "uid_map": {                          // UID -> apps and class
    "10234": { "packages": ["org.example.app"], "app_names": ["Example"], "class": "web" }
  },
  "flow_uid_map": {                     // flow ID -> UID, including packets written before the UID was known
    "17": { "uid": 10234, "resolution": "resolved_after_first_packet", "resolve_latency_ms": 3 },
    "18": { "uid": null,  "resolution": "unresolved_session_ended" }
  },
  "stats": { "packets_recorded": 250, "capture_queue_drops": 0 }
}
```

It also records clock anchors, the forwarding engine version, the stop reason, native counters and
known limitations. App classes come from **Settings → App classes** (`package=class` lines), with
Android system UIDs classified automatically.

## Analysing captures

In Wireshark or `tshark`:

```bash
# time, direction, addresses and app/flow comment for every packet
tshark -r <id>.pcapng -T fields -e frame.time_epoch -e frame.packet_flags_direction \
       -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e frame.comment
```

The bundled reader joins packets with the sidecar, so every row gets the app even when the comment only
has a flow ID. It uses only the Python standard library:

```bash
python3 validation/scripts/pcapng_tool.py join <id>.pcapng <id>.meta.json --csv > packets.csv
#  columns: timestamp_us, src, dst, proto, sport, dport, direction, orig_len, cap_len, flow_id, uid, uid_source, packages, app_class
python3 validation/scripts/pcapng_tool.py validate <id>.pcapng   # structural check
```

## Uploading to a server

MiniPcap can send the newest finished capture and its sidecar to an HTTPS server you control. Upload is
always started by you, never automatic, and is disabled while recording.

1. Run a receiver. A reference implementation (Python standard library only) is included:

   ```bash
   cd validation/upload-server
   ./make_certs.sh <your-computer-LAN-IP>    # test CA + server certificate (debug builds trust this CA)
   python3 -I receiver.py --port 9443 --cert certs/server.pem --key certs/server.key \
          --data data --token-file token.txt
   ```

2. In **Settings**, enter `https://<your-computer-LAN-IP>:9443`, optionally an API token (stored
   encrypted with the Android Keystore), and tap **Test**.
3. Tap **Upload latest**. Progress appears in a notification. Success is shown only after the server's
   receipt confirms the SHA-256 of both files. Retrying the same capture is safe and returns the same
   receipt.

The wire protocol is specified in [`docs/UPLOAD_PROTOCOL.md`](docs/UPLOAD_PROTOCOL.md). Release builds
accept only HTTPS with system-trusted certificates.

## How it works

```
 selected apps ──► TUN (VpnService) ──► native engine (C, single thread) ──► sockets ──► network
                                              │  lwIP user-space TCP/IP stack + socket relay
                                              │
                                              ├─ tap: copy packet prefix + flow ID into a
                                              │       preallocated lock-free ring (never blocks)
                                              ▼
                                       writer thread (C) ──► <id>.pcapng   (1 MiB batches)
                                              ▲
 Kotlin UID worker ── getConnectionOwnerUid() ┘  once per new flow, batched, off the packet path
 Kotlin service ── notification, Stop, sidecar, recovery, move to Downloads, upload
```

- **Forwarding:** traffic from the TUN interface goes into a vendored [lwIP](third_party/lwip/VENDORED.md)
  stack that terminates TCP/UDP locally and relays it over ordinary sockets. MiniPcap excludes itself
  from the VPN, so its own sockets go straight to the network.
- **Capture:** each packet is tapped where it crosses the TUN interface. The packet path never calls
  into Java, allocates memory, formats text or touches the disk. It copies the prefix into a ring
  buffer and moves on. If the writer falls behind, records are dropped and counted, and forwarding is
  never slowed down.
- **App attribution:** new flows are handed in batches to a Kotlin worker, which asks Android for the
  owning UID once per flow (with retries) and writes the answer back into the native flow table.
  Later packets carry the UID directly, and the sidecar covers the earlier ones.

Design decisions and their reasons are recorded in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Performance

Measured on a Pixel 9 Pro (Android 17) over Wi-Fi, with three repeats per configuration. Full method,
raw data and environment are in [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) and
[`validation/perf/results/`](validation/perf/results/).

| Workload | No VPN | VPN, no capture | VPN + full capture |
|---|---|---|---|
| UDP 5,000 packets/s | 0.020 % loss, 7.18 ms median RTT | 0.019 %, 7.48 ms | 0.023 %, 7.63 ms |
| TCP download | 180 Mbit/s | 177 Mbit/s | 165 Mbit/s (runs 158–183) |
| TCP upload | 111 Mbit/s | 115 Mbit/s | 120 Mbit/s |

- **Capture cost:** about **+3–5 % app CPU** above VPN forwarding alone. The writer thread spends
  0.5–1.2 µs per packet, and UID lookups run about once per connection.
- **Slow storage:** with the writer frozen for 5 seconds under load, app traffic lost 0.04 % and every
  dropped capture record was counted.
- **One-hour soak:** 23.6 million packets, no capture drops, memory flat (RSS 160–198 MB), and 3,108
  of 3,128 flows attributed to an app.

These numbers come from one device and one network. Battery use, cellular networks and other Android
versions have not been measured yet. See [`docs/STATUS.md`](docs/STATUS.md).

## Privacy

Packet prefixes can contain domain names, cookies, tokens or message content. The 256-byte default
keeps files small but is **not** a privacy guarantee. While recording, files stay in app-private
storage. After the move, files in `Download/MiniPcap/` can be copied by anyone with the unlocked phone
and a USB cable, and read by apps with all-files access. Turn the move off if that matters, and delete
captures you no longer need. MiniPcap does not intercept TLS and sends nothing anywhere unless you
press **Upload**.

## Limitations

- **Capture point:** packets are recorded at the VPN interface, not the radio. TCP is terminated
  locally, so handshake timing and downlink segmentation are the on-device stack's, not the server's.
- **ICMP is not forwarded:** `ping` fails while capturing. MiniPcap's own traffic and excluded apps are
  never captured.
- **Unresolved apps:** very short UDP flows (e.g. some system DNS queries) can end before Android
  reports their UID, so they stay `unresolved`.
- **One VPN at a time:** starting another VPN ends the capture (`stop_reason: vpn_revoked`).
- **Recovered captures:** captures saved after a force-stop are kept and can be moved or shared, but
  **Upload latest** only picks complete ones.

## Building from source

**Requirements**
- JDK 17
- Android SDK with platform 36, NDK `27.2.12479018` and SDK CMake 3.22.1
- `local.properties` with `sdk.dir=…` (Android Studio creates it)

**Build and install**

```bash
./gradlew assembleDebug                      # app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleRelease                    # signed if ~/.android/minipcap-release.properties exists
```

Release signing reads `storeFile`, `storePassword`, `keyAlias` and `keyPassword` from
`~/.android/minipcap-release.properties`, or from the path in `-Pminipcap.signing=<file>`. Without
that file the release APK is unsigned. The debug and release builds use different keys, so switching
between them requires uninstalling the app.

The app targets API 35 and runs on Android 10 (API 29) and newer. The debug build also trusts the
test CA from `make_certs.sh` and accepts automation commands from `adb` (see below). Release builds do
neither.

## Testing and benchmarks

**Tests**

```bash
./gradlew testDebugUnitTest                          # JVM tests, incl. Kotlin client ↔ Python receiver over TLS
./validation/scripts/check_native.sh                 # native C tests + PCAPNG checked by an independent reader and tshark
python3 -I validation/upload-server/test_receiver.py # receiver protocol tests
```

The native tests need gcc, cmake and ninja. The PCAPNG checks also use `tshark`/`capinfos`
(Wireshark ≥ 4.2) and Python 3.10+.

**Benchmarks**

These compare no VPN, VPN-only and each capture stage on the same device (debug build):

```bash
validation/perf/build_nettool.sh && native/build-nettool-host/nettool server 5201 &
adb shell appops set dev.minipcap ACTIVATE_VPN allow
python3 -I validation/perf/bench.py --host <computer-LAN-IP> --repeats 3 --stall
python3 -I validation/perf/summarize.py validation/perf/results/<device>/<date> --md summary.md
python3 -I validation/perf/soak.py --host <computer-LAN-IP> --minutes 60
```

**Debug automation**

Debug builds accept commands such as:

```bash
adb shell am start -n dev.minipcap/.ui.MainActivity --es cmd start
```

The commands are `start`, `stop`, `stall`, `upload`, `server`, `move` and `automove`. The `server`
command puts the token on the adb command line, where adbd logs it, so use it only with throwaway
test tokens.

## Repository layout

```
app/                       Android app (Kotlin): VPN service, notification, UID worker, sidecar,
                           recovery, move to Downloads, upload, UI
native/                    C data plane: engine.c (lwIP + socket relay + tap), capture.c (flow table,
                           ring, writer), pcapng.c, packet.c, flow.c, ring.c, jni.c
  tests/                   host unit tests        tools/nettool.c   workload generator for benchmarks
third_party/lwip/          vendored lwIP fork (heiher/lwip @ e6d5fc6, BSD-3-Clause)
validation/scripts/        pcapng_tool.py (independent reader / sidecar join), check_native.sh,
                           device_lifecycle.py
validation/upload-server/  reference HTTPS receiver, its tests, test-certificate script
validation/perf/           benchmark and soak scripts, recorded results
docs/                      STATUS, TEST_RESULTS, DECISIONS, PERFORMANCE_PLAN, UPLOAD_PROTOCOL
```

## License

MIT, see [`LICENSE`](LICENSE). The vendored lwIP code in `third_party/lwip/` keeps its own
BSD-3-Clause license ([`third_party/lwip/LICENSE`](third_party/lwip/LICENSE)).
