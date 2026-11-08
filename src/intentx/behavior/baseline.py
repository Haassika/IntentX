"""Construction of behavioral baseline windows from persisted telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from intentx.behavior.dataset import (
    BehavioralBaselineDataset,
    BehavioralDatasetBuilder,
)
from intentx.telemetry.repository import SecurityEventRepository
from intentx.telemetry.windowing import (
    BehavioralWindow,
    BehavioralWindowAggregator,
)


@dataclass(frozen=True)
class BaselineBuildResult:
    """
    Result of constructing an explicitly selected behavioral baseline.

    The caller is responsible for ensuring the selected observation period
    represents intended normal activity. This class does not infer normality.
    """

    hostname: str
    observation_start: datetime
    observation_end: datetime
    window_seconds: int
    windows: tuple[BehavioralWindow, ...]
    dataset: BehavioralBaselineDataset

    @property
    def window_count(self) -> int:
        return len(self.windows)


class BaselineWindowBuilder:
    """
    Build contiguous fixed-duration windows from persisted SecurityEvents.

    This workflow performs data preparation only. It does not classify
    activity as normal, anomalous, malicious, or an intrusion.
    """

    def __init__(
        self,
        *,
        repository: SecurityEventRepository,
        window_seconds: int = 60,
        minimum_windows: int = 30,
        max_events_per_window: int = 10_000,
        feature_schema_version: int = 1,
    ) -> None:
        if window_seconds < 1:
            raise ValueError(
                "window_seconds must be greater than zero."
            )

        if minimum_windows < 2:
            raise ValueError(
                "minimum_windows must be at least two."
            )

        if (
            max_events_per_window < 1
            or max_events_per_window > 100_000
        ):
            raise ValueError(
                "max_events_per_window must be between 1 and 100000."
            )

        BehavioralWindow.feature_names(feature_schema_version)
        self._feature_schema_version = feature_schema_version
        self._repository = repository
        self._window_seconds = window_seconds
        self._minimum_windows = minimum_windows
        self._max_events_per_window = max_events_per_window

        self._aggregator = BehavioralWindowAggregator(
            window_seconds=window_seconds
        )

    def build(
        self,
        *,
        hostname: str,
        observation_start: datetime,
        observation_end: datetime,
    ) -> BaselineBuildResult:
        cleaned_hostname = hostname.strip()

        if not cleaned_hostname:
            raise ValueError(
                "hostname must not be empty."
            )

        if observation_start.tzinfo is None:
            raise ValueError(
                "observation_start must be timezone-aware."
            )

        if observation_end.tzinfo is None:
            raise ValueError(
                "observation_end must be timezone-aware."
            )

        if observation_end <= observation_start:
            raise ValueError(
                "observation_end must be greater than observation_start."
            )

        duration = timedelta(
            seconds=self._window_seconds
        )

        total_seconds = (
            observation_end - observation_start
        ).total_seconds()

        complete_window_count = int(
            total_seconds // self._window_seconds
        )

        if complete_window_count < self._minimum_windows:
            raise ValueError(
                "observation period does not contain the minimum "
                "required number of complete behavioral windows."
            )

        windows: list[BehavioralWindow] = []

        for index in range(complete_window_count):
            window_start = (
                observation_start
                + index * duration
            )
            window_end = window_start + duration

            events = self._repository.get_window(
                hostname=cleaned_hostname,
                start_time=window_start,
                end_time=window_end,
                max_events=self._max_events_per_window,
            )

            window = self._aggregator.aggregate(
                events,
                window_start=window_start,
                hostname=cleaned_hostname,
            )

            windows.append(window)

        dataset = BehavioralDatasetBuilder(
            feature_schema_version=self._feature_schema_version,
            minimum_samples=self._minimum_windows
        ).build(windows)

        return BaselineBuildResult(
            hostname=cleaned_hostname,
            observation_start=observation_start,
            observation_end=observation_end,
            window_seconds=self._window_seconds,
            windows=tuple(windows),
            dataset=dataset,
        )
