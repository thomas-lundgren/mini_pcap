# Architecture Decision Log

No implementation decisions have yet been validated. Record all choices using:

## ADR-NNN: Title
- Date:
- State: proposed / accepted / superseded
- Problem:
- Options considered:
- Evidence (links to tests/source):
- Decision and rationale:
- Consequences and rollback path:

### Pending decisions
- Forwarding backend, dependency license and integration hook.
- PCAPNG EPB direction flag mapping and host parser compatibility.
- Distribution target, requested package visibility and foreground service type.
- Upload API/receiver deployment target and authentication provisioning; protocol v1 proposed in `UPLOAD_PROTOCOL.md`.
- Production HTTPS only, with any insecure local testing isolated to debug builds.
- On-demand upload of latest COMPLETE capture pair (not active `.partial`), app-internal progress/receipt, no automatic upload.
- Platform-dependent transfer scheduler choice (API 29–33 versus 34+, Android 16 quota constraints) pending testing.

### Low-overhead architecture proposals (not yet validated)
- **ADR-001 proposed:** Kotlin handles UI/VPN lifecycle/notification/UID worker/upload; native C/C++ handles TUN observation, fast parsing, flow cache, bounded prefix queue and PCAPNG write. JNI only for lifecycle or batched control; forwarding candidate chosen by M1 P0 tests.
- **ADR-002 proposed:** Record session-unique `flow_id` per parsable flow; compact EPB comments `f-<id>` or `u-<uid>;f-<id>` constructed on writer thread; add `flow_uid_map` to sidecar. Do not fabricate UID for unresolved flows; compatibility/parser tests required.
- **ADR-003 proposed:** Four to sixteen MiB test pool, 256 KiB–1 MiB writer batches, 1 Hz UI snapshot, no upload during recording. Capacities/queue design selected by benchmarks rather than intuition.
- **ADR-004 proposed:** Require P0 (VPN-only), P1 (native capture/backpressure), P2 (release overhead) measured gates per `docs/PERFORMANCE_PLAN.md`; provisional release budgets need coordinator approval after P0.
