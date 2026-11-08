from datetime import datetime, timezone

from intentx.telemetry.events import (
    CollectionStatus,
    SecurityEventType,
    TelemetrySource,
)
from intentx.telemetry.models import (
    NetworkObservation,
    ProcessObservation,
    SecuritySnapshot,
)
from intentx.telemetry.normalizer import TelemetryEventNormalizer


def make_snapshot() -> SecuritySnapshot:
    return SecuritySnapshot(
        captured_at=datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc),
        hostname="intentx-test",
        load_1m=0.5,
        load_5m=0.4,
        load_15m=0.3,
        memory_total_kb=1000,
        memory_available_kb=250,
        process_count=2,
        processes=(
            ProcessObservation(
                pid=1,
                ppid=0,
                user="root",
                command="init",
                cpu_percent=1.0,
                memory_percent=2.0,
            ),
            ProcessObservation(
                pid=100,
                ppid=1,
                user="intentx",
                command="python3",
                cpu_percent=15.0,
                memory_percent=5.0,
            ),
        ),
        network_connections=(
            NetworkObservation(
                protocol="tcp",
                local_address="127.0.0.1:8000",
                remote_address="127.0.0.1:50000",
                state="ESTAB",
                process="python3",
            ),
            NetworkObservation(
                protocol="tcp",
                local_address="0.0.0.0:8000",
                remote_address="0.0.0.0:*",
                state="LISTEN",
                process="python3",
            ),
        ),
    )


def test_normalizer_creates_expected_number_of_events():
    events = TelemetryEventNormalizer().normalize_snapshot(make_snapshot())

    # 1 resource + 2 process + 2 network
    assert len(events) == 5


def test_normalizer_preserves_common_provenance():
    snapshot = make_snapshot()

    events = TelemetryEventNormalizer().normalize_snapshot(snapshot)

    assert all(event.hostname == snapshot.hostname for event in events)
    assert all(event.observed_at == snapshot.captured_at for event in events)
    assert all(
        event.collection_status is CollectionStatus.COLLECTED
        for event in events
    )
    assert all(event.evidence is not None for event in events)


def test_resource_event_contains_host_metrics():
    events = TelemetryEventNormalizer().normalize_snapshot(make_snapshot())

    resource = events[0]

    assert resource.source is TelemetrySource.RESOURCE
    assert resource.event_type is SecurityEventType.RESOURCE_SNAPSHOT
    assert resource.attributes["load_1m"] == 0.5
    assert resource.attributes["memory_used_ratio"] == 0.75
    assert resource.attributes["process_count"] == 2
    assert resource.evidence is not None
    assert resource.evidence.mechanism == "procfs"


def test_process_observations_become_process_events():
    events = TelemetryEventNormalizer().normalize_snapshot(make_snapshot())

    process_events = [
        event
        for event in events
        if event.source is TelemetrySource.PROCESS
    ]

    assert len(process_events) == 2

    second = process_events[1]

    assert second.event_type is SecurityEventType.PROCESS_OBSERVED
    assert second.process is not None
    assert second.process.pid == 100
    assert second.process.ppid == 1
    assert second.process.user == "intentx"
    assert second.process.command == "python3"
    assert second.attributes["cpu_percent"] == 15.0
    assert second.attributes["memory_percent"] == 5.0
    assert second.evidence is not None
    assert second.evidence.mechanism == "ps"


def test_network_state_determines_normalized_event_type():
    events = TelemetryEventNormalizer().normalize_snapshot(make_snapshot())

    network_events = [
        event
        for event in events
        if event.source is TelemetrySource.NETWORK
    ]

    assert len(network_events) == 2

    established, listener = network_events

    assert (
        established.event_type
        is SecurityEventType.NETWORK_CONNECTION
    )
    assert (
        listener.event_type
        is SecurityEventType.NETWORK_LISTENER
    )

    assert established.network is not None
    assert established.network.state == "ESTAB"

    assert listener.network is not None
    assert listener.network.state == "LISTEN"


def test_event_ids_are_unique():
    events = TelemetryEventNormalizer().normalize_snapshot(make_snapshot())

    event_ids = [event.event_id for event in events]

    assert len(event_ids) == len(set(event_ids))


def test_normalized_attributes_are_immutable():
    events = TelemetryEventNormalizer().normalize_snapshot(make_snapshot())

    resource = events[0]

    try:
        resource.attributes["load_1m"] = 99.0
    except TypeError:
        pass
    else:
        raise AssertionError("Normalized attributes must be immutable.")


def test_unavailable_network_sensor_creates_status_event():
    from dataclasses import replace

    from intentx.telemetry.models import (
        SensorCollectionStatus,
        SensorStatus,
    )

    snapshot = replace(
        make_snapshot(),
        network_connections=(),
        network_sensor=SensorStatus(
            status=SensorCollectionStatus.UNAVAILABLE,
            detail="ss unavailable",
        ),
    )

    events = TelemetryEventNormalizer().normalize_snapshot(snapshot)

    status_events = [
        event
        for event in events
        if event.event_type is SecurityEventType.SENSOR_STATUS
    ]

    assert len(status_events) == 1

    event = status_events[0]

    assert event.source is TelemetrySource.NETWORK
    assert event.collection_status is CollectionStatus.UNAVAILABLE
    assert event.attributes["detail"] == "ss unavailable"
    assert event.evidence is not None
    assert event.evidence.mechanism == "ss"


def test_resource_scopes_and_cgroup_ratio_are_distinct():
    from dataclasses import replace
    from intentx.telemetry.models import CgroupMemoryObservation, SensorStatus, SensorCollectionStatus
    snapshot = replace(make_snapshot(), cgroup_memory=CgroupMemoryObservation(
        current_bytes=256, limit_bytes=1024, source_path='/sys/fs/cgroup',
        status=SensorStatus(SensorCollectionStatus.COLLECTED)))
    events = TelemetryEventNormalizer().normalize_snapshot(snapshot)
    resource = next(e for e in events if e.event_type is SecurityEventType.RESOURCE_SNAPSHOT)
    assert resource.attributes['memory_used_ratio'] == .75
    assert resource.attributes['cgroup_memory_used_ratio'] == .25
    assert resource.attributes['memory_scope'] == 'linux_system'
    assert resource.attributes['load_scope'] == 'linux_system'
    assert resource.attributes['cgroup_memory_limit_bytes'] == 1024
    process = next(e for e in events if e.event_type is SecurityEventType.PROCESS_OBSERVED)
    assert process.attributes['memory_percent_scope'] == 'linux_system_memory'
    assert process.attributes['cpu_percent_basis'] == 'process_lifetime_average_one_cpu'


def test_unlimited_cgroup_has_no_fabricated_ratio():
    from dataclasses import replace
    from intentx.telemetry.models import CgroupMemoryObservation, SensorStatus, SensorCollectionStatus
    snapshot = replace(make_snapshot(), cgroup_memory=CgroupMemoryObservation(
        current_bytes=256, status=SensorStatus(SensorCollectionStatus.COLLECTED)))
    events = TelemetryEventNormalizer().normalize_snapshot(snapshot)
    resource = next(e for e in events if e.event_type is SecurityEventType.RESOURCE_SNAPSHOT)
    assert resource.attributes['cgroup_memory_limit_finite'] is False
    assert 'cgroup_memory_used_ratio' not in resource.attributes


def test_unavailable_cgroup_has_no_fabricated_usage():
    resource = TelemetryEventNormalizer()._resource_event(make_snapshot())
    assert resource.attributes['cgroup_memory_status'] == 'unavailable'
    assert 'cgroup_memory_current_bytes' not in resource.attributes
    assert 'cgroup_memory_used_ratio' not in resource.attributes
