"""Isolation-Forest behavioral anomaly detection for IntentX."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from intentx.behavior.dataset import BehavioralBaselineDataset
from intentx.telemetry.windowing import BehavioralWindow


MODEL_TYPE = "isolation_forest"
MODEL_FORMAT_VERSION = 1
DEFAULT_RANDOM_STATE = 42


@dataclass(frozen=True)
class BehavioralModelMetadata:
    """Training contract stored with a behavioral anomaly model."""

    model_type: str
    model_format_version: int
    feature_names: tuple[str, ...]
    training_samples: int
    training_hostnames: tuple[str, ...]
    trained_at: str
    sklearn_version: str
    n_estimators: int
    contamination: str | float
    random_state: int
    feature_schema_version: int = 1
    calibrated_score_threshold: float | None = None


@dataclass(frozen=True)
class BehavioralAnomalyResult:
    """
    Numerical anomaly assessment for one behavioral window.

    This result is not a threat classification, authorization decision,
    incident declaration, or mitigation instruction.
    """

    hostname: str
    window_start: datetime
    window_end: datetime
    decision_function: float
    score_samples: float
    model_prediction: int
    is_anomalous: bool
    applied_score_threshold: float | None = None
    uncalibrated_model_prediction: int | None = None


@dataclass(frozen=True)
class BehavioralModelArtifact:
    """Serializable model plus the exact feature/training contract."""

    metadata: BehavioralModelMetadata
    model: Any


class BehavioralAnomalyTrainer:
    """Train a deterministic Isolation Forest from a validated baseline."""

    def __init__(
        self,
        *,
        n_estimators: int = 200,
        contamination: str | float = "auto",
        random_state: int = DEFAULT_RANDOM_STATE,
    ) -> None:
        if n_estimators < 1:
            raise ValueError("n_estimators must be greater than zero.")

        if contamination != "auto":
            if (
                not isinstance(contamination, (int, float))
                or isinstance(contamination, bool)
                or not 0.0 < float(contamination) <= 0.5
            ):
                raise ValueError(
                    "contamination must be 'auto' or a number in (0.0, 0.5]."
                )

        self._n_estimators = n_estimators
        self._contamination = contamination
        self._random_state = random_state

    def train(
        self,
        dataset: BehavioralBaselineDataset,
    ) -> BehavioralModelArtifact:
        if dataset.sample_count < 2:
            raise ValueError(
                "behavioral anomaly training requires at least two samples."
            )

        expected_features = tuple(BehavioralWindow.feature_names(dataset.feature_schema_version))

        if dataset.feature_names != expected_features:
            raise ValueError(
                "baseline feature schema does not match BehavioralWindow."
            )

        matrix = np.asarray(dataset.as_matrix(), dtype=float)

        expected_shape = (
            dataset.sample_count,
            len(expected_features),
        )

        if matrix.shape != expected_shape:
            raise ValueError(
                "baseline matrix shape does not match its feature contract."
            )

        if not np.isfinite(matrix).all():
            raise ValueError(
                "baseline matrix must contain only finite numerical values."
            )

        model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=self._random_state,
            n_jobs=1,
        )

        model.fit(matrix)

        metadata = BehavioralModelMetadata(
            feature_schema_version=dataset.feature_schema_version,
            model_type=MODEL_TYPE,
            model_format_version=MODEL_FORMAT_VERSION,
            feature_names=expected_features,
            training_samples=dataset.sample_count,
            training_hostnames=tuple(
                sorted(set(dataset.hostnames))
            ),
            trained_at=datetime.now(timezone.utc).isoformat(),
            sklearn_version=sklearn.__version__,
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=self._random_state,
        )

        return BehavioralModelArtifact(
            metadata=metadata,
            model=model,
        )


class BehavioralAnomalyDetector:
    """Validate and score behavioral windows using a trained artifact."""

    def __init__(
        self,
        artifact: BehavioralModelArtifact,
    ) -> None:
        self._validate_artifact(artifact)
        self._artifact = artifact

    @property
    def metadata(self) -> BehavioralModelMetadata:
        return self._artifact.metadata

    def score(
        self,
        window: BehavioralWindow,
        *,
        feature_schema_version: int | None = None,
    ) -> BehavioralAnomalyResult:
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

        if not window.hostname.strip():
            raise ValueError(
                "behavioral window hostname must not be empty."
            )

        if window.hostname not in self.metadata.training_hostnames:
            raise ValueError(
                "behavioral window hostname was not represented "
                "in the model training baseline."
            )

        version = getattr(self.metadata, "feature_schema_version", 1)
        if feature_schema_version is not None and feature_schema_version != version:
            raise RuntimeError("Input feature schema version does not match trained model")
        current_features = tuple(BehavioralWindow.feature_names(version))

        if current_features != self.metadata.feature_names:
            raise RuntimeError(
                "runtime behavioral feature schema does not match "
                "the trained model."
            )

        vector = tuple(window.as_vector() if version == 1 else window.as_vector(version))

        if len(vector) != len(self.metadata.feature_names):
            raise ValueError(
                "behavioral feature vector does not match model schema."
            )

        if not all(
            isinstance(value, float) and math.isfinite(value)
            for value in vector
        ):
            raise ValueError(
                "behavioral feature vector must contain only "
                "finite floating-point values."
            )

        matrix = np.asarray([vector], dtype=float)

        decision = float(
            self._artifact.model.decision_function(matrix)[0]
        )

        raw_score = float(
            self._artifact.model.score_samples(matrix)[0]
        )

        prediction = int(
            self._artifact.model.predict(matrix)[0]
        )

        uncalibrated_prediction = prediction
        threshold = getattr(self.metadata, "calibrated_score_threshold", None)
        if threshold is not None:
            prediction = -1 if raw_score < threshold else 1
            decision = raw_score - threshold

        if prediction not in (-1, 1):
            raise RuntimeError(
                "Isolation Forest returned an unexpected prediction."
            )

        return BehavioralAnomalyResult(
            hostname=window.hostname,
            window_start=window.window_start,
            window_end=window.window_end,
            decision_function=decision,
            score_samples=raw_score,
            model_prediction=prediction,
            is_anomalous=(prediction == -1),
            applied_score_threshold=threshold,
            uncalibrated_model_prediction=uncalibrated_prediction if threshold is not None else None,
        )

    @staticmethod
    def _validate_artifact(
        artifact: BehavioralModelArtifact,
    ) -> None:
        metadata = artifact.metadata

        if metadata.model_type != MODEL_TYPE:
            raise ValueError(
                "unsupported behavioral model type."
            )

        if metadata.model_format_version != MODEL_FORMAT_VERSION and not (
            metadata.model_format_version == 2
            and getattr(metadata, "calibrated_score_threshold", None) is not None
        ):
            raise ValueError(
                "unsupported behavioral model format version."
            )

        cutoff = getattr(metadata, "calibrated_score_threshold", None)
        if cutoff is not None and (not isinstance(cutoff, (int, float)) or isinstance(cutoff, bool) or not math.isfinite(cutoff)):
            raise ValueError("Calibrated score threshold must be finite")
        version = getattr(metadata, "feature_schema_version", 1)
        if version not in (1, 2):
            raise ValueError("Unsupported behavioral feature schema version")
        if version == 2 and tuple(metadata.feature_names) != BehavioralWindow.FEATURE_NAMES_V2:
            raise ValueError("Schema v2 model feature names do not match version")

        if not metadata.feature_names:
            raise ValueError(
                "behavioral model feature schema must not be empty."
            )

        if len(set(metadata.feature_names)) != len(
            metadata.feature_names
        ):
            raise ValueError(
                "behavioral model feature schema contains duplicates."
            )

        for method_name in (
            "decision_function",
            "score_samples",
            "predict",
        ):
            if not callable(
                getattr(artifact.model, method_name, None)
            ):
                raise TypeError(
                    f"behavioral model does not support {method_name}()."
                )


def save_behavioral_model(
    artifact: BehavioralModelArtifact,
    path: Path | str,
) -> None:
    """Persist a validated behavioral model artifact."""

    BehavioralAnomalyDetector._validate_artifact(artifact)

    destination = Path(path)
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(artifact, destination)


def load_behavioral_model(
    path: Path | str,
) -> BehavioralModelArtifact:
    """Load and validate a behavioral model artifact."""

    source = Path(path)

    if not source.exists():
        raise FileNotFoundError(
            f"Behavioral model not found: {source}"
        )

    artifact = joblib.load(source)

    if not isinstance(
        artifact,
        BehavioralModelArtifact,
    ):
        raise TypeError(
            "Loaded object is not a BehavioralModelArtifact."
        )

    BehavioralAnomalyDetector._validate_artifact(
        artifact
    )

    return artifact
