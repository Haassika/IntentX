from datetime import datetime, timezone

from intentx.telemetry.features import BehavioralFeatureExtractor
from intentx.telemetry.models import (
    NetworkObservation,
    ProcessObservation,
    SecuritySnapshot,
)


def make_snapshot():
    return SecuritySnapshot(
        captured_at=datetime.now(timezone.utc),
        hostname="intentx-test",
        load_1m=0.5,
        load_5m=0.4,
        load_15m=0.3,
        memory_total_kb=1000,
        memory_available_kb=250,
        process_count=3,
        processes=(
            ProcessObservation(
                pid=1,
                ppid=0,
                user="root",
                command="init",
                cpu_percent=1.0,
                memory_percent=1.0,
            ),
            ProcessObservation(
                pid=10,
                ppid=1,
                user="intentx",
                command="worker",
                cpu_percent=70.0,
                memory_percent=5.0,
            ),
            ProcessObservation(
                pid=20,
                ppid=1,
                user="root",
                command="database",
                cpu_percent=2.0,
                memory_percent=30.0,
            ),
        ),
        network_connections=(
            NetworkObservation(
                protocol="tcp",
                local_address="127.0.0.1:8000",
                remote_address="127.0.0.1:50000",
                state="ESTAB",
                process="python",
            ),
            NetworkObservation(
                protocol="tcp",
                local_address="0.0.0.0:8000",
                remote_address="0.0.0.0:*",
                state="LISTEN",
                process="python",
            ),
        ),
    )


def test_feature_extraction():
    features = BehavioralFeatureExtractor().extract(make_snapshot())

    assert features.load_1m == 0.5
    assert features.load_5m == 0.4
    assert features.load_15m == 0.3
    assert features.memory_used_ratio == 0.75
    assert features.process_count == 3
    assert features.root_process_count == 2
    assert features.high_cpu_process_count == 1
    assert features.high_memory_process_count == 1
    assert features.network_connection_count == 2
    assert features.established_connection_count == 1


def test_feature_vector_is_numeric_and_stable():
    features = BehavioralFeatureExtractor().extract(make_snapshot())

    vector = features.as_vector()

    assert len(vector) == 10
    assert all(isinstance(value, float) for value in vector)


def test_invalid_total_memory_fails_safe_to_zero_ratio():
    snapshot = make_snapshot()

    snapshot = SecuritySnapshot(
        captured_at=snapshot.captured_at,
        hostname=snapshot.hostname,
        load_1m=snapshot.load_1m,
        load_5m=snapshot.load_5m,
        load_15m=snapshot.load_15m,
        memory_total_kb=0,
        memory_available_kb=0,
        process_count=snapshot.process_count,
        processes=snapshot.processes,
        network_connections=snapshot.network_connections,
    )

    features = BehavioralFeatureExtractor().extract(snapshot)

    assert features.memory_used_ratio == 0.0
