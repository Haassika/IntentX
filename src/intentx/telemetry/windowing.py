"""Deterministic time-window aggregation for behavioral security analysis."""

from __future__ import annotations

import math

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from intentx.telemetry.events import (
    CollectionStatus,
    SecurityEvent,
    SecurityEventType,
)


@dataclass(frozen=True)
class BehavioralWindow:
    """
    Numerical behavior observed during one fixed time window.

    This object contains measurements only. It does not classify activity
    as malicious, assign threat severity, authorize actions, or execute
    mitigation.
    """

    window_start: datetime
    window_end: datetime
    hostname: str

    event_count: int
    process_event_count: int
    unique_process_count: int
    root_process_event_count: int

    network_connection_count: int
    network_listener_count: int
    unique_remote_address_count: int

    auth_success_count: int
    auth_failure_count: int
    privilege_activity_count: int
    file_activity_count: int
    audit_event_count: int
    kernel_event_count: int

    sensor_unavailable_count: int
    sensor_error_count: int

    mean_load_1m: float
    max_load_1m: float
    mean_memory_used_ratio: float
    max_memory_used_ratio: float
    mean_process_count: float
    max_process_count: int

    mean_process_cpu_percent: float
    max_process_cpu_percent: float
    mean_process_memory_percent: float
    max_process_memory_percent: float

    mean_cgroup_memory_used_ratio: float | None = None
    max_cgroup_memory_used_ratio: float | None = None

    FEATURE_NAMES = (
        "event_count",
        "process_event_count",
        "unique_process_count",
        "root_process_event_count",
        "network_connection_count",
        "network_listener_count",
        "unique_remote_address_count",
        "auth_success_count",
        "auth_failure_count",
        "privilege_activity_count",
        "file_activity_count",
        "audit_event_count",
        "kernel_event_count",
        "sensor_unavailable_count",
        "sensor_error_count",
        "mean_load_1m",
        "max_load_1m",
        "mean_memory_used_ratio",
        "max_memory_used_ratio",
        "mean_process_count",
        "max_process_count",
        "mean_process_cpu_percent",
        "max_process_cpu_percent",
        "mean_process_memory_percent",
        "max_process_memory_percent",
    )

    FEATURE_NAMES_V2 = tuple(
        name for name in FEATURE_NAMES
        if name not in {
            "mean_load_1m", "max_load_1m", "mean_memory_used_ratio",
            "max_memory_used_ratio", "mean_process_cpu_percent",
            "max_process_cpu_percent", "mean_process_memory_percent",
            "max_process_memory_percent",
        }
    ) + ("mean_cgroup_memory_used_ratio", "max_cgroup_memory_used_ratio")

    @classmethod
    def feature_names(cls, version=1):
        if version == 1:
            return cls.FEATURE_NAMES
        if version == 2:
            return cls.FEATURE_NAMES_V2
        raise ValueError("Unsupported behavioral feature schema version")

    def as_vector(self, feature_schema_version=1) -> tuple[float, ...]:
        """Return a stable numerical feature vector for downstream ML."""

        names = self.feature_names(feature_schema_version)
        if any(getattr(self, name) is None for name in names):
            raise ValueError("Schema v2 requires complete finite-limit cgroup memory telemetry")
        return tuple(float(getattr(self, name)) for name in names)


class BehavioralWindowAggregator:
    """
    Aggregates normalized SecurityEvents into fixed-duration feature windows.

    The aggregator is deterministic and performs no anomaly detection or
    threat classification.
    """

    def __init__(self, *, window_seconds: int = 60) -> None:
        if window_seconds < 1:
            raise ValueError(
                "window_seconds must be greater than zero."
            )

        self._window_seconds = window_seconds

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def aggregate(
        self,
        events: Iterable[SecurityEvent],
        *,
        window_start: datetime,
        hostname: str,
    ) -> BehavioralWindow:
        if window_start.tzinfo is None:
            raise ValueError(
                "window_start must be timezone-aware."
            )

        if not hostname.strip():
            raise ValueError(
                "hostname must not be empty."
            )

        window_end = window_start + timedelta(
            seconds=self._window_seconds
        )

        selected = tuple(
            event
            for event in events
            if (
                event.hostname == hostname
                and window_start
                <= event.observed_at
                < window_end
            )
        )

        process_events = tuple(
            event
            for event in selected
            if event.event_type
            in {
                SecurityEventType.PROCESS_OBSERVED,
                SecurityEventType.PROCESS_STARTED,
                SecurityEventType.PROCESS_EXITED,
            }
        )

        process_ids = {
            event.process.pid
            for event in process_events
            if (
                event.process is not None
                and event.process.pid is not None
            )
        }

        root_process_event_count = sum(
            1
            for event in process_events
            if (
                event.process is not None
                and (
                    event.process.uid == 0
                    or event.process.user == "root"
                )
            )
        )

        network_connections = tuple(
            event
            for event in selected
            if event.event_type
            is SecurityEventType.NETWORK_CONNECTION
        )

        network_listeners = tuple(
            event
            for event in selected
            if event.event_type
            is SecurityEventType.NETWORK_LISTENER
        )

        remote_addresses = {
            event.network.remote_address
            for event in network_connections
            if (
                event.network is not None
                and event.network.remote_address
            )
        }

        resource_events = tuple(
            event
            for event in selected
            if event.event_type
            is SecurityEventType.RESOURCE_SNAPSHOT
        )

        cgroup_values = []
        cgroup_complete = bool(resource_events)
        for event in resource_events:
            attributes = event.attributes
            value = attributes.get("cgroup_memory_used_ratio")
            if (attributes.get("cgroup_memory_status") != "collected"
                or attributes.get("cgroup_memory_scope") != "current_cgroup_and_descendants"
                or attributes.get("cgroup_memory_limit_finite") is not True
                or not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value) or value < 0):
                cgroup_complete = False
            else:
                cgroup_values.append(float(value))

        load_1m = self._numeric_attributes(
            resource_events,
            "load_1m",
        )
        memory_used_ratio = self._numeric_attributes(
            resource_events,
            "memory_used_ratio",
        )
        process_count = self._numeric_attributes(
            resource_events,
            "process_count",
        )

        process_cpu = self._numeric_attributes(
            process_events,
            "cpu_percent",
        )
        process_memory = self._numeric_attributes(
            process_events,
            "memory_percent",
        )

        return BehavioralWindow(
            window_start=window_start,
            window_end=window_end,
            hostname=hostname,
            mean_cgroup_memory_used_ratio=self._mean(cgroup_values) if cgroup_complete else None,
            max_cgroup_memory_used_ratio=self._maximum(cgroup_values) if cgroup_complete else None,
            event_count=len(selected),
            process_event_count=len(process_events),
            unique_process_count=len(process_ids),
            root_process_event_count=root_process_event_count,
            network_connection_count=len(network_connections),
            network_listener_count=len(network_listeners),
            unique_remote_address_count=len(remote_addresses),
            auth_success_count=self._count_type(
                selected,
                SecurityEventType.AUTH_SUCCESS,
            ),
            auth_failure_count=self._count_type(
                selected,
                SecurityEventType.AUTH_FAILURE,
            ),
            privilege_activity_count=self._count_type(
                selected,
                SecurityEventType.PRIVILEGE_ACTIVITY,
            ),
            file_activity_count=self._count_type(
                selected,
                SecurityEventType.FILE_ACTIVITY,
            ),
            audit_event_count=self._count_type(
                selected,
                SecurityEventType.AUDIT_EVENT,
            ),
            kernel_event_count=self._count_type(
                selected,
                SecurityEventType.KERNEL_EVENT,
            ),
            sensor_unavailable_count=sum(
                1
                for event in selected
                if event.collection_status
                is CollectionStatus.UNAVAILABLE
            ),
            sensor_error_count=sum(
                1
                for event in selected
                if event.collection_status
                is CollectionStatus.ERROR
            ),
            mean_load_1m=self._mean(load_1m),
            max_load_1m=self._maximum(load_1m),
            mean_memory_used_ratio=self._mean(
                memory_used_ratio
            ),
            max_memory_used_ratio=self._maximum(
                memory_used_ratio
            ),
            mean_process_count=self._mean(process_count),
            max_process_count=int(
                self._maximum(process_count)
            ),
            mean_process_cpu_percent=self._mean(
                process_cpu
            ),
            max_process_cpu_percent=self._maximum(
                process_cpu
            ),
            mean_process_memory_percent=self._mean(
                process_memory
            ),
            max_process_memory_percent=self._maximum(
                process_memory
            ),
        )

    @staticmethod
    def _count_type(
        events: Iterable[SecurityEvent],
        event_type: SecurityEventType,
    ) -> int:
        return sum(
            1
            for event in events
            if event.event_type is event_type
        )

    @staticmethod
    def _numeric_attributes(
        events: Iterable[SecurityEvent],
        name: str,
    ) -> tuple[float, ...]:
        values: list[float] = []

        for event in events:
            value = event.attributes.get(name)

            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
            ):
                values.append(float(value))

        return tuple(values)

    @staticmethod
    def _mean(values: tuple[float, ...]) -> float:
        if not values:
            return 0.0

        return sum(values) / len(values)

    @staticmethod
    def _maximum(values: tuple[float, ...]) -> float:
        if not values:
            return 0.0

        return max(values)
