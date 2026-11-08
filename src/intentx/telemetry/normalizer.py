"""Normalization of Linux telemetry observations into security events."""

from __future__ import annotations

from intentx.telemetry.events import (
    CollectionStatus,
    EvidenceProvenance,
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
    new_event_id,
)
from intentx.telemetry.models import (
    SecuritySnapshot,
    SensorCollectionStatus,
)


class TelemetryEventNormalizer:
    """
    Converts host telemetry snapshots into canonical security events.

    This component performs normalization only. It does not classify
    observations as malicious, calculate anomaly scores, authorize actions,
    or execute mitigation.
    """

    def normalize_snapshot(
        self,
        snapshot: SecuritySnapshot,
    ) -> tuple[SecurityEvent, ...]:
        events: list[SecurityEvent] = []

        events.append(self._resource_event(snapshot))

        for process in snapshot.processes:
            events.append(
                SecurityEvent(
                    event_id=new_event_id(),
                    observed_at=snapshot.captured_at,
                    hostname=snapshot.hostname,
                    source=TelemetrySource.PROCESS,
                    event_type=SecurityEventType.PROCESS_OBSERVED,
                    collection_status=CollectionStatus.COLLECTED,
                    process=ProcessContext(
                        pid=process.pid,
                        ppid=process.ppid,
                        user=process.user,
                        command=process.command,
                    ),
                    attributes={
                        "cpu_percent": process.cpu_percent,
                        "memory_percent": process.memory_percent,
                        "memory_percent_scope": "linux_system_memory",
                        "cpu_percent_basis": "process_lifetime_average_one_cpu",
                        "process_population_scope": "visible_pid_namespace",
                    },
                    evidence=EvidenceProvenance(
                        sensor="linux_process_sensor",
                        mechanism="ps",
                        source_reference=f"pid:{process.pid}",
                    ),
                )
            )

        if (
            snapshot.network_sensor.status
            is SensorCollectionStatus.UNAVAILABLE
        ):
            events.append(
                SecurityEvent(
                    event_id=new_event_id(),
                    observed_at=snapshot.captured_at,
                    hostname=snapshot.hostname,
                    source=TelemetrySource.NETWORK,
                    event_type=SecurityEventType.SENSOR_STATUS,
                    collection_status=CollectionStatus.UNAVAILABLE,
                    attributes={
                        "detail": (
                            snapshot.network_sensor.detail
                            or "network telemetry unavailable"
                        )
                    },
                    evidence=EvidenceProvenance(
                        sensor="linux_network_sensor",
                        mechanism="ss",
                        source_reference="collection-status",
                    ),
                )
            )

        for connection in snapshot.network_connections:
            event_type = (
                SecurityEventType.NETWORK_LISTENER
                if connection.state.upper() == "LISTEN"
                else SecurityEventType.NETWORK_CONNECTION
            )

            events.append(
                SecurityEvent(
                    event_id=new_event_id(),
                    observed_at=snapshot.captured_at,
                    hostname=snapshot.hostname,
                    source=TelemetrySource.NETWORK,
                    event_type=event_type,
                    collection_status=CollectionStatus.COLLECTED,
                    network=NetworkContext(
                        protocol=connection.protocol,
                        local_address=connection.local_address,
                        remote_address=connection.remote_address,
                        state=connection.state,
                    ),
                    attributes={
                        "process": connection.process,
                    },
                    evidence=EvidenceProvenance(
                        sensor="linux_network_sensor",
                        mechanism="ss",
                        source_reference=(
                            f"{connection.protocol}:"
                            f"{connection.local_address}->"
                            f"{connection.remote_address}"
                        ),
                    ),
                )
            )

        # Normalize kernel security observations
        kernel_sec = getattr(snapshot, "kernel_security", None)
        if kernel_sec is not None:
            if kernel_sec.tainted > 0 or kernel_sec.security_events:
                for alert in kernel_sec.security_events:
                    events.append(
                        SecurityEvent(
                            event_id=new_event_id(),
                            observed_at=snapshot.captured_at,
                            hostname=snapshot.hostname,
                            source=TelemetrySource.KERNEL,
                            event_type=SecurityEventType.KERNEL_EVENT,
                            collection_status=CollectionStatus.COLLECTED,
                            attributes={
                                "alert": alert,
                                "tainted": kernel_sec.tainted,
                                "taint_flags": list(kernel_sec.taint_flags),
                                "ptrace_scope": kernel_sec.ptrace_scope,
                                "modules_disabled": kernel_sec.modules_disabled,
                            },
                            evidence=EvidenceProvenance(
                                sensor="linux_kernel_sensor",
                                mechanism="procfs_kmsg",
                                source_reference="/proc/sys/kernel/tainted",
                            ),
                        )
                    )
            if kernel_sec.ptrace_scope is not None and kernel_sec.ptrace_scope == 0:
                events.append(
                    SecurityEvent(
                        event_id=new_event_id(),
                        observed_at=snapshot.captured_at,
                        hostname=snapshot.hostname,
                        source=TelemetrySource.LINUX_AUDIT,
                        event_type=SecurityEventType.AUDIT_EVENT,
                        collection_status=CollectionStatus.COLLECTED,
                        attributes={
                            "warning": "ptrace_scope_unrestricted",
                            "ptrace_scope": kernel_sec.ptrace_scope,
                        },
                        evidence=EvidenceProvenance(
                            sensor="linux_kernel_sensor",
                            mechanism="procfs",
                            source_reference="/proc/sys/kernel/yama/ptrace_scope",
                        ),
                    )
                )

        return tuple(events)

    @staticmethod
    def _resource_event(snapshot: SecuritySnapshot) -> SecurityEvent:
        if snapshot.memory_total_kb > 0:
            memory_used_kb = max(
                snapshot.memory_total_kb - snapshot.memory_available_kb,
                0,
            )
            memory_used_ratio = min(
                memory_used_kb / snapshot.memory_total_kb,
                1.0,
            )
        else:
            memory_used_ratio = 0.0

        cgroup = snapshot.cgroup_memory
        cgroup_attributes = {
            "cgroup_memory_status": cgroup.status.status.value,
            "cgroup_memory_scope": "current_cgroup_and_descendants",
            "cgroup_memory_accounting": "charged_memory_including_cache",
        }
        cgroup_attributes["cgroup_memory_breakdown_status"] = cgroup.breakdown_status.status.value
        if cgroup.breakdown_status.detail is not None:
            cgroup_attributes["cgroup_memory_breakdown_detail"] = cgroup.breakdown_status.detail
        for name in ("anon", "file", "kernel"):
            value = getattr(cgroup, f"{name}_bytes")
            if value is not None:
                cgroup_attributes[f"cgroup_memory_{name}_bytes"] = value
        if cgroup.status.detail is not None:
            cgroup_attributes["cgroup_memory_detail"] = cgroup.status.detail
        if cgroup.source_path is not None:
            cgroup_attributes["cgroup_memory_source_path"] = cgroup.source_path
        if cgroup.current_bytes is not None:
            cgroup_attributes["cgroup_memory_current_bytes"] = cgroup.current_bytes
            cgroup_attributes["cgroup_memory_limit_finite"] = cgroup.limit_bytes is not None
        if cgroup.limit_bytes is not None:
            cgroup_attributes["cgroup_memory_limit_bytes"] = cgroup.limit_bytes
            if cgroup.current_bytes is not None:
                cgroup_attributes["cgroup_memory_used_ratio"] = cgroup.current_bytes / cgroup.limit_bytes

        return SecurityEvent(
            event_id=new_event_id(),
            observed_at=snapshot.captured_at,
            hostname=snapshot.hostname,
            source=TelemetrySource.RESOURCE,
            event_type=SecurityEventType.RESOURCE_SNAPSHOT,
            collection_status=CollectionStatus.COLLECTED,
            attributes={
                "resource_semantics_version": 1,
                "load_scope": "linux_system",
                "memory_scope": "linux_system",
                "process_count_scope": "visible_pid_namespace",
                **cgroup_attributes,
                "load_1m": snapshot.load_1m,
                "load_5m": snapshot.load_5m,
                "load_15m": snapshot.load_15m,
                "memory_total_kb": snapshot.memory_total_kb,
                "memory_available_kb": snapshot.memory_available_kb,
                "memory_used_ratio": memory_used_ratio,
                "process_count": snapshot.process_count,
            },
            evidence=EvidenceProvenance(
                sensor="linux_resource_sensor",
                mechanism="procfs",
                source_reference="/proc/loadavg;/proc/meminfo",
            ),
        )
