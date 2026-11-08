from datetime import datetime, timedelta, timezone

import pytest

from intentx.behavior.baseline import BaselineWindowBuilder
from intentx.telemetry.events import (
    CollectionStatus,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
)
from intentx.telemetry.repository import SecurityEventRepository
from intentx.telemetry.windowing import BehavioralWindow


START = datetime(
    2026,
    10,
    2,
    10,
    0,
    tzinfo=timezone.utc,
)


def make_event(
    *,
    minute: int,
    hostname: str = "linux-lab",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"{hostname}-{minute}",
        observed_at=START + timedelta(
            minutes=minute,
            seconds=10,
        ),
        hostname=hostname,
        source=TelemetrySource.RESOURCE,
        event_type=SecurityEventType.RESOURCE_SNAPSHOT,
        collection_status=CollectionStatus.COLLECTED,
        attributes={
            "load_1m": 0.2 + minute * 0.01,
            "memory_used_ratio": 0.4,
            "process_count": 100 + minute,
        },
    )


def make_repository(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()
    return repository


def test_builds_contiguous_behavioral_windows(tmp_path):
    repository = make_repository(tmp_path)

    repository.save_many(
        make_event(minute=index)
        for index in range(5)
    )

    result = BaselineWindowBuilder(
        repository=repository,
        window_seconds=60,
        minimum_windows=5,
    ).build(
        hostname="linux-lab",
        observation_start=START,
        observation_end=START + timedelta(minutes=5),
    )

    assert result.hostname == "linux-lab"
    assert result.window_count == 5
    assert result.dataset.sample_count == 5
    assert result.dataset.feature_names == tuple(
        BehavioralWindow.FEATURE_NAMES
    )

    for index, window in enumerate(result.windows):
        assert window.window_start == (
            START + timedelta(minutes=index)
        )
        assert window.window_end == (
            START + timedelta(minutes=index + 1)
        )
        assert window.hostname == "linux-lab"
        assert window.event_count == 1


def test_ignores_other_hosts(tmp_path):
    repository = make_repository(tmp_path)

    repository.save_many(
        (
            make_event(
                minute=0,
                hostname="linux-lab",
            ),
            make_event(
                minute=0,
                hostname="other-host",
            ),
        )
    )

    result = BaselineWindowBuilder(
        repository=repository,
        minimum_windows=2,
    ).build(
        hostname="linux-lab",
        observation_start=START,
        observation_end=START + timedelta(minutes=2),
    )

    assert result.windows[0].event_count == 1
    assert result.windows[1].event_count == 0


def test_empty_windows_are_preserved(tmp_path):
    repository = make_repository(tmp_path)

    repository.save(
        make_event(minute=0)
    )

    result = BaselineWindowBuilder(
        repository=repository,
        minimum_windows=3,
    ).build(
        hostname="linux-lab",
        observation_start=START,
        observation_end=START + timedelta(minutes=3),
    )

    assert result.window_count == 3
    assert result.windows[0].event_count == 1
    assert result.windows[1].event_count == 0
    assert result.windows[2].event_count == 0


def test_partial_trailing_window_is_not_included(tmp_path):
    repository = make_repository(tmp_path)

    repository.save_many(
        make_event(minute=index)
        for index in range(3)
    )

    result = BaselineWindowBuilder(
        repository=repository,
        minimum_windows=2,
    ).build(
        hostname="linux-lab",
        observation_start=START,
        observation_end=(
            START
            + timedelta(
                minutes=2,
                seconds=30,
            )
        ),
    )

    assert result.window_count == 2
    assert result.windows[-1].window_end == (
        START + timedelta(minutes=2)
    )


def test_rejects_period_with_too_few_complete_windows(
    tmp_path,
):
    repository = make_repository(tmp_path)

    builder = BaselineWindowBuilder(
        repository=repository,
        minimum_windows=3,
    )

    with pytest.raises(
        ValueError,
        match="minimum",
    ):
        builder.build(
            hostname="linux-lab",
            observation_start=START,
            observation_end=START + timedelta(minutes=2),
        )


def test_rejects_empty_hostname(tmp_path):
    repository = make_repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="hostname",
    ):
        BaselineWindowBuilder(
            repository=repository,
            minimum_windows=2,
        ).build(
            hostname=" ",
            observation_start=START,
            observation_end=START + timedelta(minutes=2),
        )


def test_rejects_naive_start(tmp_path):
    repository = make_repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="observation_start",
    ):
        BaselineWindowBuilder(
            repository=repository,
            minimum_windows=2,
        ).build(
            hostname="linux-lab",
            observation_start=START.replace(
                tzinfo=None
            ),
            observation_end=START + timedelta(minutes=2),
        )


def test_rejects_naive_end(tmp_path):
    repository = make_repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="observation_end",
    ):
        BaselineWindowBuilder(
            repository=repository,
            minimum_windows=2,
        ).build(
            hostname="linux-lab",
            observation_start=START,
            observation_end=(
                START
                + timedelta(minutes=2)
            ).replace(tzinfo=None),
        )


def test_rejects_invalid_observation_range(tmp_path):
    repository = make_repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="greater than",
    ):
        BaselineWindowBuilder(
            repository=repository,
            minimum_windows=2,
        ).build(
            hostname="linux-lab",
            observation_start=START,
            observation_end=START,
        )


def test_rejects_invalid_window_seconds(tmp_path):
    repository = make_repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="window_seconds",
    ):
        BaselineWindowBuilder(
            repository=repository,
            window_seconds=0,
        )


def test_rejects_invalid_minimum_windows(tmp_path):
    repository = make_repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="minimum_windows",
    ):
        BaselineWindowBuilder(
            repository=repository,
            minimum_windows=1,
        )


@pytest.mark.parametrize(
    "value",
    [
        0,
        100_001,
    ],
)
def test_rejects_invalid_event_limit(
    tmp_path,
    value,
):
    repository = make_repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="max_events_per_window",
    ):
        BaselineWindowBuilder(
            repository=repository,
            max_events_per_window=value,
        )


def test_baseline_result_preserves_observation_provenance(
    tmp_path,
):
    repository = make_repository(tmp_path)

    repository.save_many(
        make_event(minute=index)
        for index in range(3)
    )

    end = START + timedelta(minutes=3)

    result = BaselineWindowBuilder(
        repository=repository,
        minimum_windows=3,
    ).build(
        hostname="linux-lab",
        observation_start=START,
        observation_end=end,
    )

    assert result.observation_start == START
    assert result.observation_end == end
    assert result.window_seconds == 60
    assert result.dataset.hostnames == (
        "linux-lab",
        "linux-lab",
        "linux-lab",
    )
