from datetime import datetime, timedelta, timezone

import pytest

from intentx.telemetry.events import (
    CollectionStatus,
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
)
from intentx.telemetry.windowing import (
    BehavioralWindow,
    BehavioralWindowAggregator,
)


START = datetime(
    2026,
    10,
    2,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_event(
    event_id: str,
    *,
    seconds: int = 0,
    hostname: str = "host-a",
    source: TelemetrySource = TelemetrySource.PROCESS,
    event_type: SecurityEventType = (
        SecurityEventType.PROCESS_OBSERVED
    ),
    status: CollectionStatus = CollectionStatus.COLLECTED,
    process: ProcessContext | None = None,
    network: NetworkContext | None = None,
    attributes=None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        observed_at=START + timedelta(seconds=seconds),
        hostname=hostname,
        source=source,
        event_type=event_type,
        collection_status=status,
        process=process,
        network=network,
        attributes=attributes or {},
    )


def test_empty_window_produces_zero_features():
    aggregator = BehavioralWindowAggregator(
        window_seconds=60
    )

    result = aggregator.aggregate(
        (),
        window_start=START,
        hostname="host-a",
    )

    assert result.event_count == 0
    assert result.process_event_count == 0
    assert result.mean_load_1m == 0.0
    assert result.max_process_cpu_percent == 0.0
    assert len(result.as_vector()) == len(
        BehavioralWindow.FEATURE_NAMES
    )


def test_window_is_start_inclusive_end_exclusive():
    events = (
        make_event("before", seconds=-1),
        make_event("start", seconds=0),
        make_event("inside", seconds=59),
        make_event("end", seconds=60),
    )

    result = BehavioralWindowAggregator(
        window_seconds=60
    ).aggregate(
        events,
        window_start=START,
        hostname="host-a",
    )

    assert result.event_count == 2


def test_events_are_isolated_by_hostname():
    events = (
        make_event("a", hostname="host-a"),
        make_event("b", hostname="host-b"),
    )

    result = BehavioralWindowAggregator().aggregate(
        events,
        window_start=START,
        hostname="host-a",
    )

    assert result.event_count == 1


def test_process_features_are_aggregated():
    events = (
        make_event(
            "p1",
            process=ProcessContext(
                pid=100,
                ppid=1,
                uid=0,
                user="root",
                command="daemon-a",
            ),
            attributes={
                "cpu_percent": 10.0,
                "memory_percent": 5.0,
            },
        ),
        make_event(
            "p2",
            seconds=1,
            process=ProcessContext(
                pid=101,
                ppid=100,
                uid=1000,
                user="alice",
                command="worker",
            ),
            attributes={
                "cpu_percent": 30.0,
                "memory_percent": 15.0,
            },
        ),
        make_event(
            "p3",
            seconds=2,
            process=ProcessContext(
                pid=100,
                ppid=1,
                uid=0,
                user="root",
                command="daemon-a",
            ),
            attributes={
                "cpu_percent": 20.0,
                "memory_percent": 10.0,
            },
        ),
    )

    result = BehavioralWindowAggregator().aggregate(
        events,
        window_start=START,
        hostname="host-a",
    )

    assert result.process_event_count == 3
    assert result.unique_process_count == 2
    assert result.root_process_event_count == 2
    assert result.mean_process_cpu_percent == 20.0
    assert result.max_process_cpu_percent == 30.0
    assert result.mean_process_memory_percent == 10.0
    assert result.max_process_memory_percent == 15.0


def test_network_features_are_aggregated():
    events = (
        make_event(
            "n1",
            source=TelemetrySource.NETWORK,
            event_type=SecurityEventType.NETWORK_CONNECTION,
            network=NetworkContext(
                protocol="tcp",
                local_address="10.0.0.1:50000",
                remote_address="1.1.1.1:443",
                state="ESTAB",
            ),
        ),
        make_event(
            "n2",
            seconds=1,
            source=TelemetrySource.NETWORK,
            event_type=SecurityEventType.NETWORK_CONNECTION,
            network=NetworkContext(
                protocol="tcp",
                local_address="10.0.0.1:50001",
                remote_address="1.1.1.1:443",
                state="ESTAB",
            ),
        ),
        make_event(
            "n3",
            seconds=2,
            source=TelemetrySource.NETWORK,
            event_type=SecurityEventType.NETWORK_LISTENER,
            network=NetworkContext(
                protocol="tcp",
                local_address="0.0.0.0:22",
                state="LISTEN",
            ),
        ),
    )

    result = BehavioralWindowAggregator().aggregate(
        events,
        window_start=START,
        hostname="host-a",
    )

    assert result.network_connection_count == 2
    assert result.network_listener_count == 1
    assert result.unique_remote_address_count == 1


def test_security_activity_counts_are_aggregated():
    event_types = (
        SecurityEventType.AUTH_SUCCESS,
        SecurityEventType.AUTH_FAILURE,
        SecurityEventType.AUTH_FAILURE,
        SecurityEventType.PRIVILEGE_ACTIVITY,
        SecurityEventType.FILE_ACTIVITY,
        SecurityEventType.AUDIT_EVENT,
        SecurityEventType.AUDIT_EVENT,
        SecurityEventType.KERNEL_EVENT,
    )

    events = tuple(
        make_event(
            f"event-{index}",
            seconds=index,
            source=TelemetrySource.LINUX_AUDIT,
            event_type=event_type,
        )
        for index, event_type in enumerate(event_types)
    )

    result = BehavioralWindowAggregator().aggregate(
        events,
        window_start=START,
        hostname="host-a",
    )

    assert result.auth_success_count == 1
    assert result.auth_failure_count == 2
    assert result.privilege_activity_count == 1
    assert result.file_activity_count == 1
    assert result.audit_event_count == 2
    assert result.kernel_event_count == 1


def test_resource_features_use_mean_and_max():
    events = (
        make_event(
            "r1",
            source=TelemetrySource.RESOURCE,
            event_type=SecurityEventType.RESOURCE_SNAPSHOT,
            attributes={
                "load_1m": 1.0,
                "memory_used_ratio": 0.25,
                "process_count": 100,
            },
        ),
        make_event(
            "r2",
            seconds=30,
            source=TelemetrySource.RESOURCE,
            event_type=SecurityEventType.RESOURCE_SNAPSHOT,
            attributes={
                "load_1m": 3.0,
                "memory_used_ratio": 0.75,
                "process_count": 140,
            },
        ),
    )

    result = BehavioralWindowAggregator().aggregate(
        events,
        window_start=START,
        hostname="host-a",
    )

    assert result.mean_load_1m == 2.0
    assert result.max_load_1m == 3.0
    assert result.mean_memory_used_ratio == 0.5
    assert result.max_memory_used_ratio == 0.75
    assert result.mean_process_count == 120.0
    assert result.max_process_count == 140


def test_sensor_health_is_preserved_as_features():
    events = (
        make_event(
            "unavailable",
            source=TelemetrySource.NETWORK,
            event_type=SecurityEventType.SENSOR_STATUS,
            status=CollectionStatus.UNAVAILABLE,
        ),
        make_event(
            "error",
            seconds=1,
            source=TelemetrySource.KERNEL,
            event_type=SecurityEventType.SENSOR_STATUS,
            status=CollectionStatus.ERROR,
        ),
    )

    result = BehavioralWindowAggregator().aggregate(
        events,
        window_start=START,
        hostname="host-a",
    )

    assert result.sensor_unavailable_count == 1
    assert result.sensor_error_count == 1


def test_feature_vector_order_is_stable():
    result = BehavioralWindowAggregator().aggregate(
        (),
        window_start=START,
        hostname="host-a",
    )

    vector = result.as_vector()

    assert len(vector) == 25
    assert len(vector) == len(
        BehavioralWindow.FEATURE_NAMES
    )
    assert all(isinstance(value, float) for value in vector)


def test_invalid_window_size_is_rejected():
    with pytest.raises(
        ValueError,
        match="window_seconds",
    ):
        BehavioralWindowAggregator(
            window_seconds=0
        )


def test_naive_window_start_is_rejected():
    aggregator = BehavioralWindowAggregator()

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        aggregator.aggregate(
            (),
            window_start=datetime(2026, 10, 2, 12, 0),
            hostname="host-a",
        )


def test_empty_hostname_is_rejected():
    aggregator = BehavioralWindowAggregator()

    with pytest.raises(
        ValueError,
        match="hostname",
    ):
        aggregator.aggregate(
            (),
            window_start=START,
            hostname=" ",
        )
