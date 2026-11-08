# Controlled lab normal-behavior workload

Run `python -m intentx.behavior.workload` alongside the existing experiment
runner, in the **same container** so both share its process and network
namespaces. The module uses only the Python standard library and refuses root.
The image's existing `USER intentx` applies to both commands.

Example (build the updated image first):

```sh
docker build -t intentx:benign .
docker volume create intentx-baseline-results
docker run -d --name intentx-baseline --read-only --network none \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
  --mount type=volume,source=intentx-baseline-results,target=/app/runtime \
  intentx:benign python -m intentx.behavior.workload \
  --duration-seconds 5400 --interval-seconds 10 --seed 42
caffeinate -i docker exec intentx-baseline python -m intentx.behavior.experiment \
  --duration-seconds 3600 --interval-seconds 5 \
  --window-seconds 60 --minimum-windows 60
```

Experiment artifacts remain in the Docker volume after the container stops.
Export them with a read-only helper container, then extract the archive locally:

```sh
docker run --rm --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount type=volume,source=intentx-baseline-results,target=/saved,readonly \
  intentx:benign python -c 'import sys, tarfile; archive = tarfile.open(fileobj=sys.stdout.buffer, mode="w|"); archive.add("/saved/behavior/experiments", arcname="experiments"); archive.close()' \
  > experiment-artifacts.tar
tar -xf experiment-artifacts.tar
```

Use a fresh volume and container name for each run to keep experiments separate.
Keep the volume until exported artifacts have been verified. The 90-minute
workload leaves time for the hour-long collection and training. On macOS,
`caffeinate -i` prevents idle system sleep while the experiment command runs;
keep the laptop lid open and Docker Desktop running. It cannot prevent manual
sleep, shutdown, or Docker suspension.

The runner now rejects overdue collection slots, clock discontinuities, and
collection crossing the deadline. It never runs catch-up cycles. It requires
one successful resource snapshot per scheduled slot, with half an interval of
timestamp tolerance. Every window must contain telemetry, but small timestamp
jitter may move a boundary sample between adjacent windows. Coverage is checked
against scheduled slots rather than requiring exact per-window counts. The collection
interval must divide the window duration exactly. It waits through the final
window before validating coverage and training. A successful schema-v2 manifest
contains `collection_coverage`; a rejected collection preserves the database
and `collection_failure.json`, exits unsuccessfully, and produces no model.
This validates collection completeness, not workload representativeness.

Check workload completion with `docker logs` and its exit status with
`docker inspect`. Stopping the container sends SIGTERM; the workload closes
sockets, reaps children, and removes its private temporary directory.
There are no host bind mounts, exposed ports, or shell execution in the generator.

Each cycle selects one to three fixed Python sleep children and matching
loopback TCP connections. Connections remain open during the cycle to improve
visibility at the default five-second collection cadence. Payloads are tiny;
file writes/readbacks use one private temporary file and at most 1 MiB. CPU work
is a bounded arithmetic loop, at most 100,000 iterations per cycle. Defaults
use 64 KiB files and at most 20,000 iterations. Children are terminated and
reaped each cycle. Duration is limited to 24 hours, intervals to 0.1–60 seconds,
and children to three. All limits are validated before activity starts.

`--file-bytes`, `--cpu-iterations`, and `--max-children` configure these bounds.
The seed reproduces activity choices; OS timing, ephemeral ports, process IDs,
and measured resource utilization vary. Extremely short cycles can finish
before telemetry samples them. Preserve the printed profile/configuration and
completion counters with the experiment manifest as workload provenance.

This produces a **controlled lab normal-behavior baseline**, not representative
real-world Linux behavior. File activity is not proof of file/audit telemetry;
no authentication, privilege, audit, or kernel events are synthesized. Compare
feature distributions after collection before evaluating anomaly scenarios.
