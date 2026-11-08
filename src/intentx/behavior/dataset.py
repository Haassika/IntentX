"""Validated behavioral baseline datasets for anomaly-model training."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

from intentx.telemetry.windowing import BehavioralWindow


@dataclass(frozen=True)
class BehavioralBaselineDataset:
    """
    Immutable numerical baseline prepared from behavioral windows.

    This object contains training observations only. It does not perform
    anomaly detection, threat classification, authorization, or mitigation.
    """

    feature_names: tuple[str, ...]
    vectors: tuple[tuple[float, ...], ...]
    hostnames: tuple[str, ...]
    window_starts: tuple[object, ...]
    feature_schema_version: int = 1

    @property
    def sample_count(self) -> int:
        return len(self.vectors)

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)

    def as_matrix(self) -> tuple[tuple[float, ...], ...]:
        """Return the validated immutable numerical training matrix."""
        return self.vectors


class BehavioralDatasetBuilder:
    """
    Convert deterministic BehavioralWindows into validated ML input.

    This layer validates the numerical contract only. It does not decide
    whether activity is normal, anomalous, malicious, or an intrusion.
    """

    def __init__(
        self,
        *,
        minimum_samples: int = 2,
        feature_schema_version: int = 1,
    ) -> None:
        if minimum_samples < 1:
            raise ValueError(
                "minimum_samples must be greater than zero."
            )

        BehavioralWindow.feature_names(feature_schema_version)
        self._feature_schema_version = feature_schema_version
        self._minimum_samples = minimum_samples

    @property
    def minimum_samples(self) -> int:
        return self._minimum_samples

    def build(
        self,
        windows: Iterable[BehavioralWindow],
        *,
        require_single_hostname: bool = True,
    ) -> BehavioralBaselineDataset:
        observations = tuple(windows)

        if not observations:
            raise ValueError(
                "baseline dataset must contain at least one window."
            )

        if len(observations) < self._minimum_samples:
            raise ValueError(
                "baseline dataset does not contain the minimum "
                "required number of samples."
            )

        feature_names = tuple(BehavioralWindow.feature_names(self._feature_schema_version))

        if not feature_names:
            raise ValueError(
                "behavioral feature schema must not be empty."
            )

        if len(set(feature_names)) != len(feature_names):
            raise ValueError(
                "behavioral feature schema contains duplicate names."
            )

        hostnames: list[str] = []
        window_starts: list[object] = []
        vectors: list[tuple[float, ...]] = []

        previous_start = None

        for window in observations:
            if not window.hostname.strip():
                raise ValueError(
                    "behavioral window hostname must not be empty."
                )

            if window.window_start.tzinfo is None:
                raise ValueError(
                    "behavioral window start must be timezone-aware."
                )

            if window.window_end.tzinfo is None:
                raise ValueError(
                    "behavioral window end must be timezone-aware."
                )

            if window.window_end <= window.window_start:
                raise ValueError(
                    "behavioral window end must be greater than start."
                )

            if (
                previous_start is not None
                and window.window_start < previous_start
            ):
                raise ValueError(
                    "behavioral windows must be chronological."
                )

            previous_start = window.window_start

            vector = tuple(window.as_vector() if self._feature_schema_version == 1 else window.as_vector(self._feature_schema_version))

            if len(vector) != len(feature_names):
                raise ValueError(
                    "behavioral feature vector does not match "
                    "the feature schema."
                )

            if not all(
                isinstance(value, float)
                and math.isfinite(value)
                for value in vector
            ):
                raise ValueError(
                    "behavioral feature vectors must contain only "
                    "finite floating-point values."
                )

            hostnames.append(window.hostname)
            window_starts.append(window.window_start)
            vectors.append(vector)

        if (
            require_single_hostname
            and len(set(hostnames)) != 1
        ):
            raise ValueError(
                "baseline dataset must contain a single hostname."
            )

        return BehavioralBaselineDataset(
            feature_names=feature_names,
            feature_schema_version=self._feature_schema_version,
            vectors=tuple(vectors),
            hostnames=tuple(hostnames),
            window_starts=tuple(window_starts),
        )
