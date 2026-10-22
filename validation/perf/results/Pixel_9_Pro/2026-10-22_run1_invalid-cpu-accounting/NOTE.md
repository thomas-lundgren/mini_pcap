# Superseded run — do not use for CPU conclusions
- `app_cpu_ms` in these files is the **main thread only** (bench.py passed `sh -c <script>` through
  `adb shell`, which re-joins argv, so `/proc/<pid>/stat` was never read). `app_threads_cpu_ms`
  (all other threads, native engine+writer under the inherited name `capture-control`) is valid.
- UDP 5k pps runs with 6–10 % loss were caused by relay `sendto(MSG_DONTWAIT)` EAGAIN on the
  default UDP send buffer (`udp_send_errors`), a forwarding defect present in all VPN variants,
  fixed by 1 MiB relay socket buffers. The "5 s writer stall" loss belongs to the same defect.
Replaced by the rerun in the sibling directory.
