# Live telemetry status

The dashboard reads a fixed server-configured status file. It does not start
collection, accept browser-selected paths, score anomalies, or authorize execution.

Run one publisher per status file inside the hardened non-root Linux container:

```bash
python -m intentx.telemetry.live_status --status-path /app/runtime/telemetry/live-status.json
```

The publisher observes resource/process/network/cgroup sensors every five seconds.
Authentication, audit and kernel are explicitly unavailable. Only availability and
timestamps are published atomically. This monitor does not persist events or modify
models. An extra collector can affect experimental process/resource observations;
use a separate monitoring session rather than adding it to a baseline experiment.

Configure the API with `INTENTX_TELEMETRY_STATUS` pointing to that same live file.
The API must have read access to the live volume. A one-time exported copy is not
a live connection. Keep local API access bound to localhost.

The UI refreshes every ten seconds while visible. Status older than thirty seconds
becomes stale with unknown sensor status. Errors, clean stops, missing files and
invalid reports never imply healthy monitoring. A recent heartbeat shows a recent
cycle, not uninterrupted coverage. Without configuration the panel is not connected.

`GET /api/v1/telemetry/status` reads at most 16 KiB and exposes only curated status.
Paths, raw errors, process arguments and network addresses are excluded.
