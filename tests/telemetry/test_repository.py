from datetime import datetime, timedelta, timezone

import pytest

from intentx.telemetry.events import (
    CollectionStatus,
    EvidenceProvenance,
    ProcessContext,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
)
from intentx.telemetry.repository import SecurityEventRepository


def make_event(
    *,
    event_id: str = "event-1",
    seconds: int = 0,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        observed_at=(
            datetime(
                2026,
                10,
                2,
                12,
                0,
                tzinfo=timezone.utc,
            )
            + timedelta(seconds=seconds)
        ),
        hostname="intentx-test",
        source=TelemetrySource.PROCESS,
        event_type=SecurityEventType.PROCESS_OBSERVED,
        collection_status=CollectionStatus.COLLECTED,
        process=ProcessContext(
            pid=100 + seconds,
            ppid=1,
            uid=1000,
            user="intentx",
            executable="/usr/bin/python3",
            command="python3 worker.py",
        ),
        attributes={
            "cpu_percent": 12.5,
            "trusted": True,
        },
        evidence=EvidenceProvenance(
            sensor="linux_process_sensor",
            mechanism="ps",
            source_reference=f"event:{event_id}",
        ),
    )


def test_initialize_creates_database(tmp_path):
    database = tmp_path / "telemetry.db"
    repository = SecurityEventRepository(database)

    repository.initialize()

    assert database.exists()
    assert repository.count() == 0


def test_event_round_trip_preserves_security_context(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    event = make_event()

    assert repository.save_many((event,)) == 1

    loaded = repository.get_recent(limit=10)

    assert len(loaded) == 1
    restored = loaded[0]

    assert restored.event_id == event.event_id
    assert restored.observed_at == event.observed_at
    assert restored.hostname == event.hostname
    assert restored.source is TelemetrySource.PROCESS
    assert (
        restored.event_type
        is SecurityEventType.PROCESS_OBSERVED
    )
    assert restored.process == event.process
    assert dict(restored.attributes) == dict(event.attributes)
    assert restored.evidence == event.evidence


def test_save_many_persists_multiple_events(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    events = (
        make_event(event_id="event-1", seconds=1),
        make_event(event_id="event-2", seconds=2),
        make_event(event_id="event-3", seconds=3),
    )

    assert repository.save_many(events) == 3
    assert repository.count() == 3


def test_recent_events_are_newest_first(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    repository.save_many(
        (
            make_event(event_id="old", seconds=1),
            make_event(event_id="middle", seconds=2),
            make_event(event_id="new", seconds=3),
        )
    )

    recent = repository.get_recent(limit=2)

    assert [event.event_id for event in recent] == [
        "new",
        "middle",
    ]


def test_recent_limit_is_bounded(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    with pytest.raises(ValueError, match="limit"):
        repository.get_recent(limit=0)

    with pytest.raises(ValueError, match="limit"):
        repository.get_recent(limit=10_001)


def test_duplicate_event_id_is_rejected(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    event = make_event()

    repository.save(event)

    with pytest.raises(Exception):
        repository.save(event)

    assert repository.count() == 1


def test_retention_keeps_newest_events(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    repository.save_many(
        tuple(
            make_event(
                event_id=f"event-{index}",
                seconds=index,
            )
            for index in range(5)
        )
    )

    removed = repository.enforce_retention(
        max_events=3
    )

    assert removed == 2
    assert repository.count() == 3

    remaining = repository.get_recent(limit=10)

    assert [event.event_id for event in remaining] == [
        "event-4",
        "event-3",
        "event-2",
    ]


def test_retention_rejects_invalid_bound(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    with pytest.raises(ValueError, match="max_events"):
        repository.enforce_retention(max_events=0)


def test_empty_batch_is_noop(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    assert repository.save_many(()) == 0
    assert repository.count() == 0


def test_get_window_returns_chronological_events(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    repository.save_many(
        (
            make_event(event_id="three", seconds=30),
            make_event(event_id="one", seconds=10),
            make_event(event_id="two", seconds=20),
        )
    )

    start = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    events = repository.get_window(
        hostname="intentx-test",
        start_time=start,
        end_time=start + timedelta(seconds=60),
    )

    assert [event.event_id for event in events] == [
        "one",
        "two",
        "three",
    ]


def test_get_window_is_start_inclusive_end_exclusive(
    tmp_path,
):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    repository.save_many(
        (
            make_event(event_id="before", seconds=-1),
            make_event(event_id="start", seconds=0),
            make_event(event_id="inside", seconds=59),
            make_event(event_id="end", seconds=60),
        )
    )

    start = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    events = repository.get_window(
        hostname="intentx-test",
        start_time=start,
        end_time=start + timedelta(seconds=60),
    )

    assert [event.event_id for event in events] == [
        "start",
        "inside",
    ]


def test_get_window_isolated_by_hostname(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    event_a = make_event(
        event_id="host-a",
        seconds=10,
    )

    event_b = SecurityEvent(
        event_id="host-b",
        observed_at=event_a.observed_at,
        hostname="other-host",
        source=event_a.source,
        event_type=event_a.event_type,
        collection_status=event_a.collection_status,
        process=event_a.process,
        attributes=event_a.attributes,
        evidence=event_a.evidence,
    )

    repository.save_many((event_a, event_b))

    start = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    events = repository.get_window(
        hostname="intentx-test",
        start_time=start,
        end_time=start + timedelta(seconds=60),
    )

    assert [event.event_id for event in events] == [
        "host-a",
    ]


def test_get_window_rejects_invalid_time_range(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    start = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    with pytest.raises(
        ValueError,
        match="end_time",
    ):
        repository.get_window(
            hostname="intentx-test",
            start_time=start,
            end_time=start,
        )


def test_get_window_rejects_naive_timestamps(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    aware = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    naive = datetime(
        2026,
        10,
        2,
        12,
        0,
    )

    with pytest.raises(
        ValueError,
        match="start_time",
    ):
        repository.get_window(
            hostname="intentx-test",
            start_time=naive,
            end_time=aware + timedelta(seconds=60),
        )

    with pytest.raises(
        ValueError,
        match="end_time",
    ):
        repository.get_window(
            hostname="intentx-test",
            start_time=aware,
            end_time=naive,
        )


def test_get_window_rejects_empty_hostname(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    start = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    with pytest.raises(
        ValueError,
        match="hostname",
    ):
        repository.get_window(
            hostname=" ",
            start_time=start,
            end_time=start + timedelta(seconds=60),
        )


def test_get_window_rejects_invalid_event_bound(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    start = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    with pytest.raises(
        ValueError,
        match="max_events",
    ):
        repository.get_window(
            hostname="intentx-test",
            start_time=start,
            end_time=start + timedelta(seconds=60),
            max_events=0,
        )

    with pytest.raises(
        ValueError,
        match="max_events",
    ):
        repository.get_window(
            hostname="intentx-test",
            start_time=start,
            end_time=start + timedelta(seconds=60),
            max_events=100_001,
        )


def test_get_window_fails_instead_of_truncating(
    tmp_path,
):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    repository.save_many(
        tuple(
            make_event(
                event_id=f"event-{index}",
                seconds=index,
            )
            for index in range(3)
        )
    )

    start = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    with pytest.raises(
        RuntimeError,
        match="silently truncate",
    ):
        repository.get_window(
            hostname="intentx-test",
            start_time=start,
            end_time=start + timedelta(seconds=60),
            max_events=2,
        )
