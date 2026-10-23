# MiniPcap metadata sidecar format (`<session>.meta`), version 1.0

A recording session produces two files with the same session ID:

| File | Content |
|---|---|
| `<session>.pcap` | Classic PCAP, nanosecond timestamps (magic `0xA1B23C4D`), link type `LINKTYPE_LINUX_SLL` (113). Every record = 16-byte SLL header + IP packet prefix. |
| `<session>.meta` | This format: a header followed by timestamped, typed, variable-length binary records written asynchronously as measurements arrive. |

Nothing in the metadata is repeated per packet. A post-processing analyzer
(`analyzer/mpcanalyze.py`) correlates packets and metadata by timestamp.

## 1. Conventions

- All integers and floats are **little endian**. Floats are IEEE 754 (`f32`, `f64`).
- `str` = `u16` byte length + UTF-8 bytes (no terminator).
- `str[]` = `u16` count + that many `str`.
- Optional fields are governed by a **presence bitmap** (`u32`, bit *n* = field *n* present).
  Absent fields are still stored (as zero) to keep layouts fixed, but **must be treated as
  unavailable, never as 0**. The writer never estimates a value it did not receive.
- Android "unavailable" sentinels (`CellInfo.UNAVAILABLE` etc.) are never written; the presence bit is
  cleared instead.

## 2. Clocks

- **Monotonic time** = `CLOCK_BOOTTIME` in nanoseconds = Android `SystemClock.elapsedRealtimeNanos()`.
  It does not jump with wall-clock changes and includes deep sleep. Every record timestamp uses it.
- **PCAP time**: the native writer converts each packet's monotonic capture time to Unix time with one
  anchor pair taken at session start: `pcap_ns = anchor_realtime_ns + (boot_ns − anchor_boottime_ns)`.
  The same anchor is stored in the meta header, so the analyzer recovers each packet's exact
  monotonic time: `boot_ns = pcap_ns − anchor_realtime_ns + anchor_boottime_ns`. Wall-clock changes
  during the session therefore cannot reorder or shift packets.
- **CLOCK_SYNC records** pair monotonic and wall-clock time periodically and on Android time-change
  broadcasts, so wall-clock adjustments are visible.
- Packet timestamps are taken when the packet enters the capture path (TUN read for uplink, just
  before TUN write for downlink), not when it is written to disk.

## 3. File header (64 bytes)

| Offset | Type | Field |
|---|---|---|
| 0 | 8 bytes | magic `"MPCMETA\0"` |
| 8 | u16 | version major = 1 (a reader must reject other majors) |
| 10 | u16 | version minor = 0 (a reader must accept higher minors) |
| 12 | u32 | header length = 64 (records start here; future headers may be longer) |
| 16 | 16 bytes | session ID (UUID, RFC 4122 byte order) = the PCAP/meta file stem |
| 32 | i64 | `anchor_boottime_ns` used for PCAP timestamps |
| 40 | i64 | `anchor_realtime_ns` used for PCAP timestamps |
| 48 | i64 | session start, monotonic ns |
| 56 | u32 | flags (0) |
| 60 | u32 | reserved (0) |

## 4. Record header (16 bytes)

| Offset | Type | Field |
|---|---|---|
| 0 | u16 | record type (§5) |
| 2 | u16 | flags |
| 4 | u32 | record length in bytes, **including** this header and padding; multiple of 8 |
| 8 | i64 | timestamp, monotonic ns (`CLOCK_BOOTTIME`) |

Records are padded with zero bytes to a multiple of 8. **Unknown record types must be skipped**
using the length. A record whose length runs past the end of the file is an interrupted write; the
file is valid up to the previous record.

**Flags:**

| Bits | Meaning |
|---|---|
| 0–2 | timestamp source: 0 `LOGGER` (time the logger received the callback), 1 `SENSOR` (`SensorEvent.timestamp`), 2 `LOCATION` (`Location.elapsedRealtimeNanos`), 3 `MODEM` (`CellInfo`/`SignalStrength` timestamp, millisecond resolution), 4 `PACKET` (native capture clock) |
| 3 | `REFRESH`: periodic repeat of an unchanged state (not a change event) |
| 4–15 | reserved (0) |

Records that carry a source timestamp also store the logger's receive time in their payload, so the
delay between measurement and delivery is known.

## 5. Record types

| Type | Name | Kind | Written |
|---|---|---|---|
| 0x0001 | `SESSION_INFO` | state | once at start |
| 0x0002 | `CLOCK_SYNC` | sync | start, every 60 s, on time change, at stop |
| 0x0003 | `SESSION_END` | state | once at stop (or appended by recovery) |
| 0x0004 | `CAPTURE_STATS` | sample | every 10 s and at stop |
| 0x0005 | `DROPPED_EVENTS` | event | when metadata records were dropped |
| 0x0006 | `SENSOR_STATUS` | state | per source at start and on change |
| 0x0010 | `LOCATION` | continuous | each new fix (time/distance thresholds) |
| 0x0011 | `GNSS_STATUS` | sample | on satellite status change, at most 1 Hz |
| 0x0020 | `MOTION_SAMPLE` | continuous | per sensor sample (all / max rate / threshold mode) |
| 0x0030 | `RADIO_STATE` | state | on change of technology, data state/activity, service state |
| 0x0031 | `CELL_IDENTITY` | state | when the serving-cell set changes; periodic `REFRESH` |
| 0x0032 | `CELL_MEASUREMENT` | sample | each new cell-info report (serving + neighbors) |
| 0x0033 | `SIGNAL_STRENGTH` | sample | each serving signal-strength report |
| 0x0040 | `NETWORK_STATE` | state | on default-network change |
| 0x0041 | `WIFI_STATE` | state/sample | on Wi-Fi link change; periodic `REFRESH` |
| 0x0050 | `UID_MAPPING` | state | when a UID is first resolved to packages |
| 0x0051 | `FLOW_MAPPING` | state | when a flow's owner lookup finishes (resolved or not) |

### 0x0001 SESSION_INFO

`u16 count`, then `count` × (`str key`, `str value`). Keys include `app_version`, `device_manufacturer`,
`device_model`, `android_release`, `api_level`, `ip_snaplen` (0 = full packet), `mtu`, `filter_mode`,
`filter_packages` (comma separated), `pcap_file`, and the configuration of every collector
(`gps`, `gps_min_time_ms`, `gps_min_distance_m`, `radio`, `radio_refresh_ms`, `motion`, `motion_mode`,
`motion_hz`, `motion_threshold`, …). Unknown keys are ignored.

### 0x0002 CLOCK_SYNC

Both clocks are read back to back in native code (`clock_gettime`), nanosecond precision; the
record timestamp is the midpoint of two CLOCK_BOOTTIME reads around the CLOCK_REALTIME read.

| Type | Field |
|---|---|
| i64 | realtime ns (Unix epoch) taken together with the record timestamp |
| u8 | reason: 0 start, 1 periodic, 2 time changed, 3 timezone changed, 4 stop |
| 7 bytes | padding |

### 0x0003 SESSION_END

| Type | Field |
|---|---|
| u8 | status: 1 complete, 2 recovered (process ended without Stop) |
| str | stop reason (e.g. `user_stop`, `low_storage`, `vpn_revoked`, `process_terminated_recovered`) |
| u16 + (str, u64)× | final counters (name, value) |

### 0x0004 CAPTURE_STATS

`u16 count` + (`str name`, `u64 value`)×: native capture counters (packets, capture-queue drops per
direction, records written, flows, UID lookups, storage errors, …).

### 0x0005 DROPPED_EVENTS

| Type | Field |
|---|---|
| u16 | record type that was dropped (0 = any/unknown) |
| u16 | reason: 1 queue full, 2 record too large (> 1 MiB), 3 write error, 4 encoding error, 5 emitted after the file was closed (counted in SESSION_END only) |
| u32 | dropped since the previous `DROPPED_EVENTS` of this type/reason |
| u64 | total dropped of this type/reason in the session |

### 0x0006 SENSOR_STATUS

| Type | Field |
|---|---|
| u16 | source: 1 location, 2 GNSS, 3 accelerometer, 4 gyroscope, 5 radio, 6 cell info, 7 network, 8 Wi-Fi, 9 apps |
| u8 | status: 0 active, 1 unavailable (no hardware/API), 2 permission denied, 3 disabled by user setting, 4 disabled in system (e.g. location off), 5 error, 6 stopped |
| u8 | padding |
| str | detail (provider name, sensor name, exception class, …) |

### 0x0010 LOCATION

Timestamp = `Location.elapsedRealtimeNanos` (source `LOCATION`).

| Type | Field (presence bit) |
|---|---|
| u32 | presence |
| i64 | logger receive time, monotonic ns |
| f64 | latitude deg (0) |
| f64 | longitude deg (0) |
| f64 | altitude m, WGS84 (1) |
| f64 | MSL altitude m (2) |
| f32 | horizontal accuracy m, 68 % (3) |
| f32 | vertical accuracy m (4) |
| f32 | speed m/s (5) |
| f32 | speed accuracy m/s (6) |
| f32 | bearing deg (7) |
| f32 | bearing accuracy deg (8) |
| u8 | provider: 0 unknown, 1 gps, 2 network, 3 fused, 4 passive |
| u8 | satellites used in fix (9) |
| u16 | padding |

### 0x0011 GNSS_STATUS

| Type | Field |
|---|---|
| u16 | satellites visible |
| u16 | satellites used in fix |
| f32 | mean C/N0 of used satellites, dB-Hz (NaN if none) |
| u32 | constellation bitmask of used satellites (bit = `GnssStatus.CONSTELLATION_*`) |

### 0x0020 MOTION_SAMPLE

Timestamp = `SensorEvent.timestamp` (source `SENSOR`; same base as `elapsedRealtimeNanos`).

| Type | Field |
|---|---|
| u8 | sensor: 1 accelerometer, 2 gyroscope, 3 linear acceleration, 4 gravity, 5 magnetometer, 6 rotation vector, 7 pressure |
| u8 | accuracy (`SensorManager.SENSOR_STATUS_*`) |
| u8 | value count *n* |
| u8 | padding |
| f32 × *n* | values in Android units (m/s², rad/s, µT, hPa, unit quaternion parts) |

### 0x0030 RADIO_STATE

Timestamp = callback time (`LOGGER`). Values are raw Android constants (documented in
`TelephonyManager`, `TelephonyDisplayInfo`, `ServiceState`) so no meaning is lost.

| Type | Field (presence bit) |
|---|---|
| u32 | presence |
| i32 | data network type, `TelephonyManager.NETWORK_TYPE_*` (0) |
| i32 | display override, `TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_*` (1), e.g. 3 = NR NSA |
| i32 | data connection state, `TelephonyManager.DATA_*` (2) |
| i32 | data activity, `TelephonyManager.DATA_ACTIVITY_*` (3) |
| i32 | service state, `ServiceState.STATE_*` (4) |
| u8 | roaming (5) |
| 3 bytes | padding |
| str | network operator MCC+MNC (6) |
| str | operator name (7) |

### Cell entries (used by 0x0031, 0x0032, 0x0033)

Each record: `u16 count`, `u16 padding`, then `count` entries. Every entry starts with its own length so
readers can skip unknown extensions:

| Type | Field |
|---|---|
| u16 | entry length in bytes (including this field) |
| u8 | RAT: 1 GSM, 2 WCDMA, 3 TD-SCDMA, 4 CDMA, 5 LTE, 6 NR |
| u8 | status: bit 0 registered (serving), bits 1–2 connection status (0 none, 1 primary, 2 secondary, 3 unknown) |
| u32 | presence |
| i64 | entry timestamp, monotonic ns (from `CellInfo`/`SignalStrength`, ms resolution); presence bit 0 |

**CELL_IDENTITY entry** continues with:

| Type | Field (presence bit) |
|---|---|
| u16 | MCC (1) |
| u16 | MNC (2) |
| u8 | MNC digits (2 or 3) |
| 3 bytes | padding |
| i64 | cell identity: LTE ECI, NR NCI, WCDMA/GSM CID, CDMA base station ID (3) |
| i32 | PCI (LTE/NR), PSC (WCDMA), BSIC (GSM), CPID (TD-SCDMA) (4) |
| i32 | ARFCN: EARFCN, NR-ARFCN, UARFCN, ARFCN (5) |
| i32 | TAC (LTE/NR) or LAC (6) |
| i32 | bandwidth kHz (7) |
| u16 + i32× | bands (8) |

**CELL_MEASUREMENT and SIGNAL_STRENGTH entry** continue with:

| Type | Field (presence bit) |
|---|---|
| i32 | PCI/PSC/BSIC/CPID (1) |
| i32 | ARFCN (2) |
| i32 | signal level 0–4 (3) |
| i32 × 8 | measurements m0..m7 (bits 4..11), meaning by RAT below |

| RAT | m0 | m1 | m2 | m3 | m4 | m5 | m6 | m7 |
|---|---|---|---|---|---|---|---|---|
| LTE | RSRP dBm | RSRQ dB | RSSNR dB | RSSI dBm | CQI | timing advance | – | – |
| NR | SS-RSRP dBm | SS-RSRQ dB | SS-SINR dB | CSI-RSRP dBm | CSI-RSRQ dB | CSI-SINR dB | – | – |
| WCDMA | RSCP dBm | Ec/No dB | RSSI dBm | – | – | – | – | – |
| GSM | RSSI dBm | bit error rate | timing advance | – | – | – | – | – |
| TD-SCDMA | RSCP dBm | – | – | – | – | – | – | – |
| CDMA | CDMA dBm | CDMA Ec/Io | EVDO dBm | EVDO SNR | – | – | – | – |

`SIGNAL_STRENGTH` entries come from `SignalStrength.getCellSignalStrengths()` (serving cells only,
usually refreshed more often than cell info); PCI and ARFCN are absent there.

### 0x0040 NETWORK_STATE

| Type | Field |
|---|---|
| u32 | transports bitmask (bit = `NetworkCapabilities.TRANSPORT_*`; 0 = no default network) |
| u8 | validated |
| u8 | metered |
| u8 | event: 0 available/changed, 1 lost |
| u8 | padding |
| i32 | estimated downstream kbps |
| i32 | estimated upstream kbps |
| i32 | signal strength (`NetworkCapabilities.getSignalStrength`, `Integer.MIN_VALUE` if unspecified) |
| i32 | padding |

### 0x0041 WIFI_STATE

| Type | Field (presence bit) |
|---|---|
| u32 | presence (bit 0 connected) |
| i32 | RSSI dBm (1) |
| i32 | frequency MHz (2) |
| i32 | link speed Mbps (3) |
| i32 | TX link speed Mbps (4) |
| i32 | RX link speed Mbps (5) |
| i32 | Wi-Fi standard, `ScanResult.WIFI_STANDARD_*` (6) |
| 6 bytes | BSSID (7) |
| 2 bytes | padding |

### 0x0050 UID_MAPPING

| Type | Field |
|---|---|
| i32 | UID |
| u32 | padding |
| str | class (from the user's class rules, `system` for system UIDs, else `unknown`) |
| str | class source |
| str | note (`shared_uid`, `package_not_visible_or_uninstalled`, … or empty) |
| str[] | packages |
| str[] | app names |

### 0x0051 FLOW_MAPPING

Timestamp = when the lookup finished (`LOGGER`). Every flow announced by the packet path gets
exactly one FLOW_MAPPING, resolved or not (a flow whose announcement did not fit the queue is
announced again with its next packet). The analyzer assigns a packet to the mapping with the
same 5-tuple and the latest `first_seen_ns` not after the packet's monotonic time. A 5-tuple
reused after FIN/RST or idle expiry starts a new flow with a new `first_seen_ns`; a new
connection that has no mapping of its own is reported unknown, never inherited. `first_seen_ns`
equals the first packet's PCAP time unless that record was dropped (capture queue full).

| Type | Field |
|---|---|
| u64 | flow ID (unique per session) |
| i64 | first seen, monotonic ns: exact capture time of the flow's first packet |
| u8 | IP version (4/6) |
| u8 | protocol (6 TCP, 17 UDP) |
| u16 | local port (the device side) |
| u16 | remote port |
| u16 | padding |
| 16 bytes | local address (IPv4 in the first 4 bytes) |
| 16 bytes | remote address |
| i32 | UID (−1 = unknown) |
| u8 | resolution: 1 resolved on first lookup, 2 resolved after retry, 3 unresolved (Android returned INVALID_UID after all retries), 4 unresolved (session ended before resolution) |
| u8 | lookup attempts |
| u16 | padding |
| u32 | latency from first packet to result, ms |
| u32 | padding |

## 6. Robustness

- The writer appends whole records and flushes about once per second; at Stop it writes
  `CLOCK_SYNC(stop)` and `SESSION_END(complete)` and fsyncs. `SESSION_END` is always the last
  record: pending loss reports are written just before it and nothing is appended after it.
  A session end that is followed by other records is not a valid end.
- The first write error stops the writer and the file is cut back to the last complete record
  (no torn records); such a session is not finalized and is recovered at the next start.
- If the process is killed, the next app start truncates the file after the last complete
  record and appends `SESSION_END(recovered)`.
- Collectors never block: when the bounded record pool is exhausted the record is dropped and counted;
  `DROPPED_EVENTS` reports the loss. Packet capture is never affected.
- Missing permissions, sensors or APIs are reported with `SENSOR_STATUS`, never by fabricated values.

## 7. Versioning

New record types and new trailing fields (signalled by a larger record or entry length) are minor
changes. Readers must skip unknown types and ignore trailing bytes. Changing an existing field's
meaning requires a new major version.
