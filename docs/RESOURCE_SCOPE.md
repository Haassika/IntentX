# Resource measurement scope

Existing 25-feature models retain their original feature meanings:

| Measurement | Scope and meaning |
| --- | --- |
| Load averages | Linux system scheduler load from `/proc/loadavg`; Docker Desktop VM context |
| Memory used ratio | `(MemTotal - MemAvailable) / MemTotal` from `/proc/meminfo`; Linux system context |
| Process count | Processes visible in the current PID namespace |
| Process memory percentage | procps `ps %MEM`, relative to Linux system physical memory |
| Process CPU percentage | procps `ps %CPU`, lifetime average relative to one CPU, not a five-second utilization sample |

Resource and process events now declare these scopes explicitly. System-wide
context can vary when other workloads run in the Docker VM even if IntentX's
container limits remain identical. Scope labels explain this; they do not
remove variation or establish why a particular Isolation Forest flag occurred.

A separate read-only cgroup-v2 measurement records memory.current (bytes charged
to the current cgroup and descendants) and memory.max (local hard limit).
When finite, their quotient is `cgroup_memory_used_ratio`. Charged memory
includes page cache, tmpfs, and kernel-accounted memory; it is not process RSS
or the procfs definition of used memory. A transient ratio above one is not
silently clipped. A `max` limit omits the ratio. Ancestor limits are not resolved,
so a local unlimited limit is not a claim that the entire hierarchy is unlimited.

The collector reads `/proc/self/cgroup` and the standard unified mount at
`/sys/fs/cgroup`. Docker's private cgroup namespace is supported. Missing,
unreadable, malformed, cgroup-v1, and unsupported mount-layout data is recorded
as unavailable with an explanation. It is never replaced with VM memory values.
Optional cgroup failure does not falsely mark the existing procfs sensor as
failed. This adds resource accounting, not audit or kernel security events.

These cgroup attributes are persisted for analysis but do not enter the current
25-feature model. Replacing system memory features with container memory,
changing CPU sample semantics, or removing load context requires an explicit
feature-schema change and newly trained models. Do not compare an existing
model against silently redefined inputs. The next experiment should verify
these new attributes in a short run before designing that model migration.

Reference: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html

## Diagnostic memory breakdown

New telemetry separately records memory.stat `anon`, `file`, and `kernel` byte
counters. `file` includes cached filesystem data, tmpfs and shared memory; it
is not proof that all file-backed memory is reclaimable cache. These are
non-atomic diagnostic snapshots, not a guaranteed exact decomposition of
memory.current. Missing, malformed, or unreadable breakdown counters are marked
unavailable without discarding valid total memory accounting. They do not
change either model feature schema or the existing calibrated threshold.

For future collection, add `--record-profile` to the workload command. The
non-root workload writes its seed, bounds, duration, hostname, PID, UID and start
time to the fixed `/app/runtime/behavior/workload-profile.json` path. This
requires the existing writable runtime volume. Experiment and evaluation
manifests retain the record and its checksum. Missing/invalid/stale records are
not proof that the workload ran; completion counters and container logs remain
important evidence. Existing runs cannot be retroactively given a breakdown
or authenticated workload history.
