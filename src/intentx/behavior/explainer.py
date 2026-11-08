"""Explainable AI (XAI) feature attribution for behavioral anomaly detection."""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

import numpy as np

from intentx.behavior.anomaly import BehavioralAnomalyDetector, BehavioralAnomalyResult, BehavioralModelArtifact
from intentx.telemetry.windowing import BehavioralWindow


@dataclass(frozen=True)
class FeatureAttribution:
    """Quantitative attribution score for one behavioral feature."""

    feature_name: str
    observed_value: float
    baseline_mean: float
    baseline_std: float
    deviation_zscore: float
    attribution_score: float
    contribution_percentage: float
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "observed_value": round(self.observed_value, 4),
            "baseline_mean": round(self.baseline_mean, 4),
            "baseline_std": round(self.baseline_std, 4),
            "deviation_zscore": round(self.deviation_zscore, 4),
            "attribution_score": round(self.attribution_score, 4),
            "contribution_percentage": round(self.contribution_percentage, 2),
            "description": self.description,
            "direction": ("above" if self.observed_value > self.baseline_mean else "below" if self.observed_value < self.baseline_mean else "at"),
        }


@dataclass(frozen=True)
class WindowExplanation:
    """Human-interpretable explanation of an anomaly detection outcome."""

    hostname: str
    window_start: datetime
    window_end: datetime
    is_anomalous: bool
    score: float
    decision_margin: float
    summary: str
    primary_factors: tuple[FeatureAttribution, ...]
    all_attributions: tuple[FeatureAttribution, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "is_anomalous": self.is_anomalous,
            "score": round(self.score, 6),
            "decision_margin": round(self.decision_margin, 6),
            "summary": self.summary,
            "primary_factors": [factor.to_dict() for factor in self.primary_factors],
            "all_attributions": [attr.to_dict() for attr in self.all_attributions],
        }


class BehavioralAnomalyExplainer:
    """
    Explainable AI (XAI) engine for Isolation Forest behavioral anomaly models.

    Computes feature attributions using a combination of tree path isolation depth
    and baseline distribution deviation (z-score analysis), providing transparent
    evidence of why a system state was flagged as anomalous.
    """

    def __init__(
        self,
        artifact: BehavioralModelArtifact,
        baseline_stats: dict[str, tuple[float, float]] | None = None,
    ) -> None:
        self._artifact = artifact
        self._feature_names = tuple(artifact.metadata.feature_names)
        self._baseline_stats = baseline_stats or self._derive_baseline_stats()

    @property
    def feature_names(self) -> tuple[str, ...]:
        return self._feature_names

    def _derive_baseline_stats(self) -> dict[str, tuple[float, float]]:
        """Extract baseline mean and variance from tree splits if no explicit baseline provided."""
        stats: dict[str, tuple[float, float]] = {}
        model = self._artifact.model
        n_features = len(self._feature_names)

        # Collect split values across trees for reference distributions
        feature_splits: list[list[float]] = [[] for _ in range(n_features)]
        for estimator in getattr(model, "estimators_", []):
            tree = estimator.tree_
            for feature_idx, threshold in zip(tree.feature, tree.threshold):
                if feature_idx >= 0 and math.isfinite(threshold):
                    feature_splits[feature_idx].append(float(threshold))

        for idx, name in enumerate(self._feature_names):
            vals = feature_splits[idx]
            if vals and len(vals) > 1:
                mean = float(np.mean(vals))
                std = float(np.std(vals))
                std = std if std > 1e-4 else 1.0
            else:
                mean = 0.0
                std = 1.0
            stats[name] = (mean, std)

        return stats

    def _compute_tree_path_attributions(self, vector: Sequence[float]) -> np.ndarray:
        """
        Compute feature importance along decision paths of Isolation Forest estimators.
        Features that split anomalous samples at shallower depths have higher isolation power.
        """
        model = self._artifact.model
        estimators = getattr(model, "estimators_", [])
        n_features = len(self._feature_names)

        if not estimators:
            return np.ones(n_features) / n_features

        vec_arr = np.asarray(vector, dtype=float).reshape(1, -1)
        raw_attributions = np.zeros(n_features, dtype=float)

        for estimator in estimators:
            # node_indicator returns a sparse matrix of traversed node indices for the sample
            indicator = estimator.decision_path(vec_arr).indices
            tree = estimator.tree_

            # Depth of each node in traversal
            depth = 0
            for node_id in indicator:
                feature_idx = tree.feature[node_id]
                if feature_idx >= 0:
                    # Shallower splits isolate faster, contributing more to anomaly score
                    weight = 1.0 / (depth + 1.0)
                    raw_attributions[feature_idx] += weight
                    depth += 1

        total = np.sum(raw_attributions)
        if total > 0:
            return raw_attributions / total
        return np.ones(n_features) / n_features

    def explain_vector(
        self,
        vector: Sequence[float],
        *,
        hostname: str = "localhost",
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        score: float = 0.0,
        decision_margin: float = 0.0,
        is_anomalous: bool = False,
        top_k: int = 4,
    ) -> WindowExplanation:
        """Explain an anomaly score based on its feature vector."""
        if len(vector) != len(self._feature_names):
            raise ValueError(f"Feature vector length {len(vector)} does not match schema {len(self._feature_names)}")

        tree_weights = self._compute_tree_path_attributions(vector)

        # Standardized deviation z-score
        z_scores = np.zeros(len(vector), dtype=float)
        for i, (val, name) in enumerate(zip(vector, self._feature_names)):
            mean, std = self._baseline_stats.get(name, (0.0, 1.0))
            z = abs(val - mean) / (std if std > 1e-4 else 1.0)
            z_scores[i] = z

        # Combined attribution: balance tree path isolation depth and statistical deviation
        total_z = float(np.sum(z_scores))
        if total_z > 0:
            z_weights = z_scores / total_z
        else:
            z_weights = np.ones(len(vector)) / len(vector)

        combined = 0.5 * tree_weights + 0.5 * z_weights
        total_combined = float(np.sum(combined))
        if total_combined > 0:
            normalized_attr = combined / total_combined
        else:
            normalized_attr = np.ones(len(vector)) / len(vector)

        attributions: list[FeatureAttribution] = []
        for i, name in enumerate(self._feature_names):
            val = float(vector[i])
            mean, std = self._baseline_stats.get(name, (0.0, 1.0))
            z = float(z_scores[i])
            attr_score = float(normalized_attr[i])
            pct = attr_score * 100.0

            # Formulate human-readable description
            cleaned_name = name.replace("_", " ")
            direction = "above" if val > mean else "below" if val < mean else "at"
            magnitude = "large" if z > 2.0 else "moderate" if z > 1.0 else "small"
            desc = (
                f"{cleaned_name} is {direction} the reference "
                f"({val:.2f} vs reference {mean:.2f}; {magnitude} standardized distance {z:.1f}). "
                "Deviation alone does not establish malicious activity."
            )

            attributions.append(
                FeatureAttribution(
                    feature_name=name,
                    observed_value=val,
                    baseline_mean=mean,
                    baseline_std=std,
                    deviation_zscore=z,
                    attribution_score=attr_score,
                    contribution_percentage=pct,
                    description=desc,
                )
            )

        # Rank features by attribution score
        ranked = sorted(attributions, key=lambda a: a.attribution_score, reverse=True)
        primary = tuple(ranked[:top_k])

        # Generate summary
        start = window_start or datetime.now()
        end = window_end or datetime.now()

        if is_anomalous:
            top_names = [f"{f.feature_name} ({f.contribution_percentage:.1f}%)" for f in primary[:3]]
            summary = (
                f"Window flagged as ANOMALOUS (score: {score:.4f}, margin: {decision_margin:+.4f}). "
                f"Primary contributing indicators: {', '.join(top_names)}. "
                f"{primary[0].description}"
            )
        else:
            summary = (
                f"Window classified as NORMAL (score: {score:.4f}, margin: {decision_margin:+.4f}). "
                f"The model did not flag this window; this does not prove all metrics are within expected statistical baseline boundaries."
            )

        return WindowExplanation(
            hostname=hostname,
            window_start=start,
            window_end=end,
            is_anomalous=is_anomalous,
            score=score,
            decision_margin=decision_margin,
            summary=summary,
            primary_factors=primary,
            all_attributions=tuple(attributions),
        )

    def explain(
        self,
        window: BehavioralWindow,
        result: BehavioralAnomalyResult,
        *,
        feature_schema_version: int = 2,
        top_k: int = 4,
    ) -> WindowExplanation:
        """Generate a complete XAI explanation for a scored behavioral window."""
        vector = window.as_vector(feature_schema_version)
        return self.explain_vector(
            vector,
            hostname=window.hostname,
            window_start=window.window_start,
            window_end=window.window_end,
            score=result.score_samples,
            decision_margin=result.decision_function,
            is_anomalous=result.is_anomalous,
            top_k=top_k,
        )
