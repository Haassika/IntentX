from datetime import datetime, timedelta, timezone

from intentx.telemetry.events import (
    CollectionStatus,
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
)
from intentx.telemetry.repository import SecurityEventRepository
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
    seconds: int,
    source: TelemetrySource,
    event_type: SecurityEventType,
    process: ProcessContext | None = None,
    network: NetworkContext | None = None,
    attributes=None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        observed_at=START + timedelta(seconds=seconds),
        hostname="intentx-test",
        source=source,
        event_type=event_type,
        collection_status=CollectionStatus.COLLECTED,
        process=process,
        network=network,
        attributes=attributes or {},
    )


def test_repository_to_behavioral_vector_pipeline(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    events = (
        make_event(
            "resource-1",
            seconds=0,
            source=TelemetrySource.RESOURCE,
            event_type=SecurityEventType.RESOURCE_SNAPSHOT,
            attributes={
                "load_1m": 1.5,
                "memory_used_ratio": 0.50,
                "process_count": 100,
            },
        ),
        make_event(
            "process-1",
            seconds=5,
            source=TelemetrySource.PROCESS,
            event_type=SecurityEventType.PROCESS_OBSERVED,
            process=ProcessContext(
                pid=100,
                ppid=1,
                uid=0,
                user="root",
                command="system-service",
            ),
            attributes={
                "cpu_percent": 20.0,
                "memory_percent": 10.0,
            },
        ),
        make_event(
            "process-2",
            seconds=10,
            source=TelemetrySource.PROCESS,
            event_type=SecurityEventType.PROCESS_OBSERVED,
            process=ProcessContext(
                pid=101,
                ppid=100,
                uid=1000,
                user="intentx",
                command="worker",
            ),
            attributes={
                "cpu_percent": 40.0,
                "memory_percent": 20.0,
            },
        ),
        make_event(
            "network-1",
            seconds=15,
            source=TelemetrySource.NETWORK,
            event_type=SecurityEventType.NETWORK_CONNECTION,
            network=NetworkContext(
                protocol="tcp",
                local_address="10.0.0.2:50000",
                remote_address="1.1.1.1:443",
                state="ESTAB",
            ),
        ),
        make_event(
            "auth-failure",
            seconds=20,
            source=TelemetrySource.AUTHENTICATION,
            event_type=SecurityEventType.AUTH_FAILURE,
        ),
        make_event(
            "outside-window",
            seconds=60,
            source=TelemetrySource.PROCESS,
            event_type=SecurityEventType.PROCESS_OBSERVED,
            process=ProcessContext(
                pid=999,
                user="root",
                command="outside",
            ),
            attributes={
                "cpu_percent": 99.0,
                "memory_percent": 99.0,
            },
        ),
    )

    repository.save_many(events)

    persisted = repository.get_window(
        hostname="intentx-test",
        start_time=START,
        end_time=START + timedelta(seconds=60),
    )

    assert [event.event_id for event in persisted] == [
        "resource-1",
        "process-1",
        "process-2",
        "network-1",
        "auth-failure",
    ]

    window = BehavioralWindowAggregator(
        window_seconds=60
    ).aggregate(
        persisted,
        window_start=START,
        hostname="intentx-test",
    )

    assert window.event_count == 5
    assert window.process_event_count == 2
    assert window.unique_process_count == 2
    assert window.root_process_event_count == 1

    assert window.network_connection_count == 1
    assert window.unique_remote_address_count == 1

    assert window.auth_failure_count == 1

    assert window.mean_load_1m == 1.5
    assert window.mean_memory_used_ratio == 0.50
    assert window.mean_process_count == 100.0

    assert window.mean_process_cpu_percent == 30.0
    assert window.max_process_cpu_percent == 40.0

    vector = window.as_vector()

    assert len(vector) == 25
    assert len(vector) == len(
        BehavioralWindow.FEATURE_NAMES
    )
    assert all(isinstance(value, float) for value in vector)
