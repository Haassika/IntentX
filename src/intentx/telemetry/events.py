"""Normalized security-event domain models for IntentX telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from uuid import uuid4


class TelemetrySource(str, Enum):
    """Origin of a security observation."""

    PROCESS = "process"
    RESOURCE = "resource"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    SYSTEM_LOG = "system_log"
    LINUX_AUDIT = "linux_audit"
    KERNEL = "kernel"


class SecurityEventType(str, Enum):
    """Normalized event categories used by the detection pipeline."""

    PROCESS_OBSERVED = "process_observed"
    PROCESS_STARTED = "process_started"
    PROCESS_EXITED = "process_exited"

    RESOURCE_SNAPSHOT = "resource_snapshot"

    NETWORK_CONNECTION = "network_connection"
    NETWORK_LISTENER = "network_listener"

    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"

    PRIVILEGE_ACTIVITY = "privilege_activity"
    FILE_ACTIVITY = "file_activity"

    AUDIT_EVENT = "audit_event"
    KERNEL_EVENT = "kernel_event"

    SENSOR_STATUS = "sensor_status"


class CollectionStatus(str, Enum):
    """Whether telemetry was actually available to the collector."""

    COLLECTED = "collected"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True)
class EvidenceProvenance:
    """Describes how a security observation was obtained."""

    sensor: str
    mechanism: str
    source_reference: str | None = None

    def __post_init__(self) -> None:
        if not self.sensor.strip():
            raise ValueError("EvidenceProvenance.sensor must not be empty.")

        if not self.mechanism.strip():
            raise ValueError(
                "EvidenceProvenance.mechanism must not be empty."
            )


@dataclass(frozen=True)
class ProcessContext:
    """Process-related evidence associated with an event."""

    pid: int | None = None
    ppid: int | None = None
    uid: int | None = None
    user: str | None = None
    executable: str | None = None
    command: str | None = None


@dataclass(frozen=True)
class NetworkContext:
    """Network-related evidence associated with an event."""

    protocol: str | None = None
    local_address: str | None = None
    remote_address: str | None = None
    state: str | None = None


@dataclass(frozen=True)
class AuthenticationContext:
    """Authentication evidence associated with an event."""

    user: str | None = None
    remote_address: str | None = None
    service: str | None = None
    result: str | None = None


@dataclass(frozen=True)
class SecurityEvent:
    """
    Canonical security event consumed by downstream detection components.

    Raw collectors may use different formats, but they must normalize
    observations into this model before behavioral analysis.
    """

    event_id: str
    observed_at: datetime
    hostname: str
    source: TelemetrySource
    event_type: SecurityEventType
    collection_status: CollectionStatus

    process: ProcessContext | None = None
    network: NetworkContext | None = None
    authentication: AuthenticationContext | None = None

    attributes: Mapping[str, str | int | float | bool] = field(
        default_factory=lambda: MappingProxyType({})
    )

    evidence: EvidenceProvenance | None = None

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("SecurityEvent.observed_at must be timezone-aware.")

        if not self.event_id.strip():
            raise ValueError("SecurityEvent.event_id must not be empty.")

        if not self.hostname.strip():
            raise ValueError("SecurityEvent.hostname must not be empty.")

        # Prevent callers from retaining a mutable dictionary reference.
        object.__setattr__(
            self,
            "attributes",
            MappingProxyType(dict(self.attributes)),
        )


def new_event_id() -> str:
    """Return a unique identifier for a normalized telemetry event."""

    return str(uuid4())
