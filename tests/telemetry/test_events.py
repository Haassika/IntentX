from datetime import datetime, timezone

import pytest

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


def test_security_event_accepts_timezone_aware_timestamp():
    event = SecurityEvent(
        event_id=new_event_id(),
        observed_at=datetime.now(timezone.utc),
        hostname="intentx-test",
        source=TelemetrySource.PROCESS,
        event_type=SecurityEventType.PROCESS_OBSERVED,
        collection_status=CollectionStatus.COLLECTED,
        process=ProcessContext(
            pid=100,
            ppid=1,
            uid=1000,
            user="intentx",
            executable="/usr/bin/python3",
            command="python3 worker.py",
        ),
    )

    assert event.source is TelemetrySource.PROCESS
    assert event.process is not None
    assert event.process.pid == 100


def test_security_event_rejects_naive_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        SecurityEvent(
            event_id=new_event_id(),
            observed_at=datetime.now(),
            hostname="intentx-test",
            source=TelemetrySource.NETWORK,
            event_type=SecurityEventType.NETWORK_CONNECTION,
            collection_status=CollectionStatus.COLLECTED,
        )


def test_security_event_rejects_empty_event_id():
    with pytest.raises(ValueError, match="event_id"):
        SecurityEvent(
            event_id="   ",
            observed_at=datetime.now(timezone.utc),
            hostname="intentx-test",
            source=TelemetrySource.PROCESS,
            event_type=SecurityEventType.PROCESS_OBSERVED,
            collection_status=CollectionStatus.COLLECTED,
        )


def test_security_event_rejects_empty_hostname():
    with pytest.raises(ValueError, match="hostname"):
        SecurityEvent(
            event_id=new_event_id(),
            observed_at=datetime.now(timezone.utc),
            hostname="",
            source=TelemetrySource.PROCESS,
            event_type=SecurityEventType.PROCESS_OBSERVED,
            collection_status=CollectionStatus.COLLECTED,
        )


def test_security_event_attributes_are_immutable_copy():
    original = {"cpu_percent": 12.5}

    event = SecurityEvent(
        event_id=new_event_id(),
        observed_at=datetime.now(timezone.utc),
        hostname="intentx-test",
        source=TelemetrySource.RESOURCE,
        event_type=SecurityEventType.RESOURCE_SNAPSHOT,
        collection_status=CollectionStatus.COLLECTED,
        attributes=original,
    )

    original["cpu_percent"] = 99.0

    assert event.attributes["cpu_percent"] == 12.5

    with pytest.raises(TypeError):
        event.attributes["cpu_percent"] = 50.0


def test_network_context_preserves_evidence():
    event = SecurityEvent(
        event_id=new_event_id(),
        observed_at=datetime.now(timezone.utc),
        hostname="intentx-test",
        source=TelemetrySource.NETWORK,
        event_type=SecurityEventType.NETWORK_CONNECTION,
        collection_status=CollectionStatus.COLLECTED,
        network=NetworkContext(
            protocol="tcp",
            local_address="10.0.0.2:50000",
            remote_address="10.0.0.10:443",
            state="ESTAB",
        ),
        evidence=EvidenceProvenance(
            sensor="network_sensor",
            mechanism="ss",
            source_reference="socket-table",
        ),
    )

    assert event.network is not None
    assert event.network.remote_address == "10.0.0.10:443"
    assert event.evidence is not None
    assert event.evidence.sensor == "network_sensor"
    assert event.evidence.mechanism == "ss"
    assert event.evidence.source_reference == "socket-table"


def test_collection_status_distinguishes_unavailable_from_empty():
    event = SecurityEvent(
        event_id=new_event_id(),
        observed_at=datetime.now(timezone.utc),
        hostname="intentx-test",
        source=TelemetrySource.NETWORK,
        event_type=SecurityEventType.SENSOR_STATUS,
        collection_status=CollectionStatus.UNAVAILABLE,
        evidence=EvidenceProvenance(
            sensor="network_sensor",
            mechanism="ss",
            source_reference="collection-unavailable",
        ),
    )

    assert event.collection_status is CollectionStatus.UNAVAILABLE
    assert event.event_type is SecurityEventType.SENSOR_STATUS



def test_evidence_provenance_rejects_empty_sensor():
    with pytest.raises(ValueError, match="sensor"):
        EvidenceProvenance(
            sensor=" ",
            mechanism="ss",
        )


def test_evidence_provenance_rejects_empty_mechanism():
    with pytest.raises(ValueError, match="mechanism"):
        EvidenceProvenance(
            sensor="network_sensor",
            mechanism=" ",
        )
