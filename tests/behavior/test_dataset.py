from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from intentx.behavior.dataset import BehavioralDatasetBuilder
from intentx.telemetry.windowing import BehavioralWindow


START = datetime(
    2026,
    10,
    2,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_window(
    *,
    seconds: int = 0,
    hostname: str = "intentx-test",
) -> BehavioralWindow:
    start = START + timedelta(seconds=seconds)

    return BehavioralWindow(
        window_start=start,
        window_end=start + timedelta(seconds=60),
        hostname=hostname,
        event_count=10,
        process_event_count=5,
        unique_process_count=4,
        root_process_event_count=1,
        network_connection_count=2,
        network_listener_count=1,
        unique_remote_address_count=2,
        auth_success_count=1,
        auth_failure_count=0,
        privilege_activity_count=0,
        file_activity_count=0,
        audit_event_count=0,
        kernel_event_count=0,
        sensor_unavailable_count=0,
        sensor_error_count=0,
        mean_load_1m=0.5,
        max_load_1m=0.7,
        mean_memory_used_ratio=0.4,
        max_memory_used_ratio=0.5,
        mean_process_count=100.0,
        max_process_count=105,
        mean_process_cpu_percent=5.0,
        max_process_cpu_percent=15.0,
        mean_process_memory_percent=2.0,
        max_process_memory_percent=6.0,
    )


def test_builds_stable_baseline_dataset():
    windows = (
        make_window(seconds=0),
        make_window(seconds=60),
        make_window(seconds=120),
    )

    dataset = BehavioralDatasetBuilder(
        minimum_samples=3
    ).build(windows)

    assert dataset.sample_count == 3
    assert dataset.feature_count == 25

    assert dataset.feature_names == tuple(
        BehavioralWindow.FEATURE_NAMES
    )

    assert dataset.as_matrix() == tuple(
        window.as_vector()
        for window in windows
    )

    assert dataset.hostnames == (
        "intentx-test",
        "intentx-test",
        "intentx-test",
    )

    assert dataset.window_starts == (
        START,
        START + timedelta(seconds=60),
        START + timedelta(seconds=120),
    )


def test_dataset_is_immutable():
    dataset = BehavioralDatasetBuilder().build(
        (
            make_window(seconds=0),
            make_window(seconds=60),
        )
    )

    with pytest.raises(AttributeError):
        dataset.vectors = ()


def test_builder_rejects_empty_dataset():
    builder = BehavioralDatasetBuilder(
        minimum_samples=1
    )

    with pytest.raises(
        ValueError,
        match="at least one window",
    ):
        builder.build(())


def test_builder_enforces_minimum_samples():
    builder = BehavioralDatasetBuilder(
        minimum_samples=3
    )

    with pytest.raises(
        ValueError,
        match="minimum",
    ):
        builder.build(
            (
                make_window(seconds=0),
                make_window(seconds=60),
            )
        )


def test_builder_rejects_invalid_minimum_samples():
    with pytest.raises(
        ValueError,
        match="minimum_samples",
    ):
        BehavioralDatasetBuilder(
            minimum_samples=0
        )


def test_builder_rejects_mixed_hosts_by_default():
    windows = (
        make_window(
            seconds=0,
            hostname="host-a",
        ),
        make_window(
            seconds=60,
            hostname="host-b",
        ),
    )

    with pytest.raises(
        ValueError,
        match="single hostname",
    ):
        BehavioralDatasetBuilder().build(windows)


def test_builder_can_explicitly_allow_multiple_hosts():
    windows = (
        make_window(
            seconds=0,
            hostname="host-a",
        ),
        make_window(
            seconds=60,
            hostname="host-b",
        ),
    )

    dataset = BehavioralDatasetBuilder().build(
        windows,
        require_single_hostname=False,
    )

    assert dataset.hostnames == (
        "host-a",
        "host-b",
    )


def test_builder_rejects_non_chronological_windows():
    windows = (
        make_window(seconds=60),
        make_window(seconds=0),
    )

    with pytest.raises(
        ValueError,
        match="chronological",
    ):
        BehavioralDatasetBuilder().build(windows)


def test_builder_rejects_empty_hostname():
    windows = (
        make_window(
            seconds=0,
            hostname=" ",
        ),
        make_window(
            seconds=60,
            hostname=" ",
        ),
    )

    with pytest.raises(
        ValueError,
        match="hostname",
    ):
        BehavioralDatasetBuilder().build(windows)


def test_builder_rejects_naive_window_start():
    window = make_window()

    invalid = replace(
        window,
        window_start=window.window_start.replace(
            tzinfo=None
        ),
    )

    with pytest.raises(
        ValueError,
        match="start",
    ):
        BehavioralDatasetBuilder(
            minimum_samples=1
        ).build((invalid,))


def test_builder_rejects_naive_window_end():
    window = make_window()

    invalid = replace(
        window,
        window_end=window.window_end.replace(
            tzinfo=None
        ),
    )

    with pytest.raises(
        ValueError,
        match="end",
    ):
        BehavioralDatasetBuilder(
            minimum_samples=1
        ).build((invalid,))


def test_builder_rejects_invalid_window_range():
    window = make_window()

    invalid = replace(
        window,
        window_end=window.window_start,
    )

    with pytest.raises(
        ValueError,
        match="greater than start",
    ):
        BehavioralDatasetBuilder(
            minimum_samples=1
        ).build((invalid,))


@pytest.mark.parametrize(
    "invalid_value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_builder_rejects_non_finite_features(
    invalid_value,
):
    invalid = replace(
        make_window(seconds=0),
        mean_load_1m=invalid_value,
    )

    valid = make_window(seconds=60)

    with pytest.raises(
        ValueError,
        match="finite",
    ):
        BehavioralDatasetBuilder().build(
            (invalid, valid)
        )
