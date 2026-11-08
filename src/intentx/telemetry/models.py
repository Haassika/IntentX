"""Immutable data models for read-only Linux security telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Tuple


class SensorCollectionStatus(str, Enum):
    """Collection state for an individual telemetry sensor."""

    COLLECTED = "collected"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class SensorStatus:
    """Collection status and diagnostic information for a sensor."""

    status: SensorCollectionStatus
    detail: str | None = None


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    ppid: int
    user: str
    command: str
    cpu_percent: float
    memory_percent: float


@dataclass(frozen=True)
class NetworkObservation:
    protocol: str
    local_address: str
    remote_address: str
    state: str
    process: str


@dataclass(frozen=True)
class CgroupMemoryObservation:
    """Memory charged to the current cgroup and descendants, including cache."""

    current_bytes: int | None = None
    limit_bytes: int | None = None
    source_path: str | None = None
    status: SensorStatus = SensorStatus(
        status=SensorCollectionStatus.UNAVAILABLE,
        detail="cgroup memory was not collected",
    )
    anon_bytes: int | None = None
    file_bytes: int | None = None
    kernel_bytes: int | None = None
    breakdown_status: SensorStatus = SensorStatus(
        status=SensorCollectionStatus.UNAVAILABLE,
        detail="cgroup memory breakdown was not collected",
    )


@dataclass(frozen=True)
class KernelSecurityObservation:
    """Read-only snapshot of kernel security status, taint state, and intrusion events."""

    tainted: int = 0
    taint_flags: tuple[str, ...] = ()
    ptrace_scope: int | None = None
    modules_disabled: int | None = None
    dmesg_restrict: int | None = None
    security_event_count: int = 0
    security_events: tuple[str, ...] = ()
    status: SensorStatus = SensorStatus(status=SensorCollectionStatus.COLLECTED)


@dataclass(frozen=True)
class SecuritySnapshot:
    captured_at: datetime
    hostname: str
    load_1m: float
    load_5m: float
    load_15m: float
    memory_total_kb: int
    memory_available_kb: int
    process_count: int
    processes: Tuple[ProcessObservation, ...]
    network_connections: Tuple[NetworkObservation, ...]
    network_sensor: SensorStatus = SensorStatus(
        status=SensorCollectionStatus.COLLECTED
    )
    cgroup_memory: CgroupMemoryObservation = CgroupMemoryObservation()
    kernel_security: KernelSecurityObservation = KernelSecurityObservation()



@dataclass(frozen=True)
class BehavioralFeatures:
    """Numerical features consumed by behavioral security models."""

    load_1m: float
    load_5m: float
    load_15m: float
    memory_used_ratio: float
    process_count: int
    root_process_count: int
    high_cpu_process_count: int
    high_memory_process_count: int
    network_connection_count: int
    established_connection_count: int

    def as_vector(self) -> tuple[float, ...]:
        return (
            self.load_1m,
            self.load_5m,
            self.load_15m,
            self.memory_used_ratio,
            float(self.process_count),
            float(self.root_process_count),
            float(self.high_cpu_process_count),
            float(self.high_memory_process_count),
            float(self.network_connection_count),
            float(self.established_connection_count),
        )
