"""Controlled orchestration for continuous Linux security telemetry."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

from intentx.telemetry.collector import LinuxTelemetryCollector
from intentx.telemetry.normalizer import TelemetryEventNormalizer
from intentx.telemetry.repository import SecurityEventRepository


@dataclass(frozen=True)
class TelemetryCycleResult:
    """Result of one collection-normalization-persistence cycle."""

    events_collected: int
    events_removed_by_retention: int


class TelemetryService:
    """
    Coordinates read-only telemetry collection and persistence.

    This service has no threat-classification, authorization,
    mitigation, or command-execution authority.
    """

    def __init__(
        self,
        *,
        collector: LinuxTelemetryCollector,
        normalizer: TelemetryEventNormalizer,
        repository: SecurityEventRepository,
        interval_seconds: float = 5.0,
        max_events: int = 100_000,
        wait_function: Callable[[float], bool] | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError(
                "interval_seconds must be greater than zero."
            )

        if max_events < 1:
            raise ValueError(
                "max_events must be greater than zero."
            )

        self._collector = collector
        self._normalizer = normalizer
        self._repository = repository
        self._interval_seconds = interval_seconds
        self._max_events = max_events
        self._stop_event = threading.Event()

        self._wait_function = (
            wait_function
            if wait_function is not None
            else self._stop_event.wait
        )

    def collect_once(self) -> TelemetryCycleResult:
        """
        Perform exactly one telemetry cycle.

        Collection failures from required sensors are deliberately allowed
        to propagate so callers can observe that the cycle did not succeed.
        """

        snapshot = self._collector.collect()

        events = self._normalizer.normalize_snapshot(
            snapshot
        )

        saved = self._repository.save_many(events)

        removed = self._repository.enforce_retention(
            max_events=self._max_events
        )

        return TelemetryCycleResult(
            events_collected=saved,
            events_removed_by_retention=removed,
        )

    def run_forever(self) -> None:
        """
        Run collection cycles until stop() is requested.

        The wait occurs after each completed cycle. A stop request interrupts
        the default Event.wait immediately instead of requiring a full sleep.
        """

        self._stop_event.clear()

        while not self._stop_event.is_set():
            self.collect_once()

            if self._wait_function(
                self._interval_seconds
            ):
                break

    def stop(self) -> None:
        """Request termination of the continuous collection loop."""

        self._stop_event.set()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()
