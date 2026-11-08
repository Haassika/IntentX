"""Reproducible behavioral baseline training workflow for IntentX."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from intentx.behavior.anomaly import (
    BehavioralAnomalyTrainer,
    BehavioralModelArtifact,
    save_behavioral_model,
)
from intentx.behavior.baseline import (
    BaselineBuildResult,
    BaselineWindowBuilder,
)


@dataclass(frozen=True)
class BehavioralTrainingResult:
    """
    Result of a behavioral model training workflow.

    This records model-training provenance only. It does not establish
    that the selected baseline is representative of all normal behavior
    and does not classify any activity as malicious or an intrusion.
    """

    hostname: str
    observation_start: datetime
    observation_end: datetime
    window_seconds: int
    training_samples: int
    model_path: Path
    artifact: BehavioralModelArtifact


class BehavioralTrainingWorkflow:
    """
    Build a declared baseline and train one Isolation Forest artifact.

    Selection of a genuinely representative normal observation period is
    an experimental responsibility of the caller.
    """

    def __init__(
        self,
        *,
        baseline_builder: BaselineWindowBuilder,
        trainer: BehavioralAnomalyTrainer,
    ) -> None:
        self._baseline_builder = baseline_builder
        self._trainer = trainer

    def train(
        self,
        *,
        hostname: str,
        observation_start: datetime,
        observation_end: datetime,
        model_path: Path | str,
    ) -> BehavioralTrainingResult:
        destination = Path(model_path)

        if not destination.name:
            raise ValueError(
                "model_path must identify a model file."
            )

        baseline: BaselineBuildResult = (
            self._baseline_builder.build(
                hostname=hostname,
                observation_start=observation_start,
                observation_end=observation_end,
            )
        )

        artifact = self._trainer.train(
            baseline.dataset
        )

        if artifact.metadata.training_hostnames != (
            baseline.hostname,
        ):
            raise RuntimeError(
                "trained model hostname provenance does not match "
                "the baseline."
            )

        if (
            artifact.metadata.training_samples
            != baseline.dataset.sample_count
        ):
            raise RuntimeError(
                "trained model sample provenance does not match "
                "the baseline."
            )

        save_behavioral_model(
            artifact,
            destination,
        )

        return BehavioralTrainingResult(
            hostname=baseline.hostname,
            observation_start=baseline.observation_start,
            observation_end=baseline.observation_end,
            window_seconds=baseline.window_seconds,
            training_samples=baseline.dataset.sample_count,
            model_path=destination,
            artifact=artifact,
        )
