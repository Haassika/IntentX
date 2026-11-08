from datetime import datetime, timezone

import pytest

from intentx.telemetry.events import (
    CollectionStatus,
    EvidenceProvenance,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
)
from intentx.telemetry.models import SecuritySnapshot
from intentx.telemetry.repository import SecurityEventRepository
from intentx.telemetry.service import TelemetryService


def make_snapshot() -> SecuritySnapshot:
    return SecuritySnapshot(
        captured_at=datetime(
            2026,
            10,
            2,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        hostname="intentx-test",
        load_1m=0.1,
        load_5m=0.2,
        load_15m=0.3,
        memory_total_kb=1000,
        memory_available_kb=500,
        process_count=0,
        processes=(),
        network_connections=(),
    )


def make_event(
    event_id: str = "event-1",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        observed_at=datetime(
            2026,
            10,
            2,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        hostname="intentx-test",
        source=TelemetrySource.RESOURCE,
        event_type=SecurityEventType.RESOURCE_SNAPSHOT,
        collection_status=CollectionStatus.COLLECTED,
        attributes={"load_1m": 0.1},
        evidence=EvidenceProvenance(
            sensor="test_sensor",
            mechanism="test",
        ),
    )


class FakeCollector:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self) -> SecuritySnapshot:
        self.calls += 1
        return make_snapshot()


class FakeNormalizer:
    def __init__(self) -> None:
        self.calls = 0

    def normalize_snapshot(
        self,
        snapshot: SecuritySnapshot,
    ) -> tuple[SecurityEvent, ...]:
        self.calls += 1
        assert snapshot.hostname == "intentx-test"

        return (
            make_event(
                event_id=f"event-{self.calls}"
            ),
        )


def make_service(
    tmp_path,
    *,
    interval_seconds: float = 5.0,
    max_events: int = 100,
    wait_function=None,
):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    collector = FakeCollector()
    normalizer = FakeNormalizer()

    service = TelemetryService(
        collector=collector,
        normalizer=normalizer,
        repository=repository,
        interval_seconds=interval_seconds,
        max_events=max_events,
        wait_function=wait_function,
    )

    return service, collector, normalizer, repository


def test_collect_once_persists_normalized_events(tmp_path):
    service, collector, normalizer, repository = (
        make_service(tmp_path)
    )

    result = service.collect_once()

    assert result.events_collected == 1
    assert result.events_removed_by_retention == 0
    assert collector.calls == 1
    assert normalizer.calls == 1
    assert repository.count() == 1


def test_collect_once_enforces_retention(tmp_path):
    service, _, _, repository = make_service(
        tmp_path,
        max_events=2,
    )

    first = service.collect_once()
    second = service.collect_once()
    third = service.collect_once()

    assert first.events_removed_by_retention == 0
    assert second.events_removed_by_retention == 0
    assert third.events_removed_by_retention == 1
    assert repository.count() == 2

    recent = repository.get_recent(limit=10)

    assert [event.event_id for event in recent] == [
        "event-3",
        "event-2",
    ]


def test_run_forever_can_stop_without_real_sleep(tmp_path):
    waits: list[float] = []

    def fake_wait(seconds: float) -> bool:
        waits.append(seconds)
        return len(waits) >= 3

    service, collector, _, repository = make_service(
        tmp_path,
        interval_seconds=2.5,
        wait_function=fake_wait,
    )

    service.run_forever()

    assert collector.calls == 3
    assert repository.count() == 3
    assert waits == [2.5, 2.5, 2.5]


def test_stop_marks_service_stopped(tmp_path):
    service, _, _, _ = make_service(tmp_path)

    assert service.stopped is False

    service.stop()

    assert service.stopped is True


def test_invalid_interval_is_rejected(tmp_path):
    with pytest.raises(
        ValueError,
        match="interval_seconds",
    ):
        make_service(
            tmp_path,
            interval_seconds=0,
        )


def test_invalid_retention_is_rejected(tmp_path):
    with pytest.raises(
        ValueError,
        match="max_events",
    ):
        make_service(
            tmp_path,
            max_events=0,
        )


def test_collection_failure_propagates(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    class FailingCollector:
        def collect(self):
            raise RuntimeError("collection failed")

    service = TelemetryService(
        collector=FailingCollector(),
        normalizer=FakeNormalizer(),
        repository=repository,
    )

    with pytest.raises(
        RuntimeError,
        match="collection failed",
    ):
        service.collect_once()

    assert repository.count() == 0
