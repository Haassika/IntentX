from datetime import datetime, timezone
import pytest
import numpy as np

from intentx.behavior.anomaly import BehavioralAnomalyTrainer
from intentx.behavior.dataset import BehavioralBaselineDataset
from intentx.behavior.explainer import BehavioralAnomalyExplainer, FeatureAttribution, WindowExplanation
from intentx.telemetry.windowing import BehavioralWindow


def _make_dummy_dataset(samples=10, feature_schema_version=2):
    names = BehavioralWindow.feature_names(feature_schema_version)
    vectors = []
    hostnames = []
    window_starts = []
    for i in range(samples):
        # Generate varied baseline values
        vec = tuple(float((i + j) % 5) for j in range(len(names)))
        vectors.append(vec)
        hostnames.append("testhost")
        window_starts.append(f"2026-10-03T10:{i:02d}:00+00:00")
    return BehavioralBaselineDataset(
        feature_names=names,
        vectors=tuple(vectors),
        hostnames=tuple(hostnames),
        window_starts=tuple(window_starts),
        feature_schema_version=feature_schema_version,
    )


def test_explainer_initialization():
    dataset = _make_dummy_dataset()
    artifact = BehavioralAnomalyTrainer(n_estimators=10).train(dataset)
    explainer = BehavioralAnomalyExplainer(artifact)

    assert explainer.feature_names == tuple(BehavioralWindow.FEATURE_NAMES_V2)
    assert len(explainer._baseline_stats) == len(BehavioralWindow.FEATURE_NAMES_V2)


def test_explain_vector_dimensions_check():
    dataset = _make_dummy_dataset()
    artifact = BehavioralAnomalyTrainer(n_estimators=10).train(dataset)
    explainer = BehavioralAnomalyExplainer(artifact)

    with pytest.raises(ValueError, match="Feature vector length"):
        explainer.explain_vector([1.0, 2.0])


def test_explain_vector_attribution_math():
    dataset = _make_dummy_dataset()
    artifact = BehavioralAnomalyTrainer(n_estimators=10).train(dataset)
    explainer = BehavioralAnomalyExplainer(artifact)

    names = BehavioralWindow.FEATURE_NAMES_V2
    # Create an anomalous vector with an extreme spike in process_event_count (index 1)
    anomalous_vector = [0.0] * len(names)
    anomalous_vector[1] = 100.0  # huge spike

    explanation = explainer.explain_vector(
        anomalous_vector,
        hostname="testhost",
        score=-0.45,
        decision_margin=-0.15,
        is_anomalous=True,
        top_k=3,
    )

    assert isinstance(explanation, WindowExplanation)
    assert explanation.is_anomalous is True
    assert explanation.score == -0.45
    assert explanation.decision_margin == -0.15
    assert len(explanation.primary_factors) == 3
    assert len(explanation.all_attributions) == len(names)

    # Sum of all attribution percentages should be approximately 100%
    total_pct = sum(a.contribution_percentage for a in explanation.all_attributions)
    assert 99.0 <= total_pct <= 101.0

    # The spiked feature should be among the top factors
    top_feature_names = [f.feature_name for f in explanation.primary_factors]
    assert "process_event_count" in top_feature_names

    # Check serialization
    d = explanation.to_dict()
    assert d["hostname"] == "testhost"
    assert d["is_anomalous"] is True
    assert "summary" in d
    assert len(d["primary_factors"]) == 3


def test_explain_normal_window():
    dataset = _make_dummy_dataset()
    artifact = BehavioralAnomalyTrainer(n_estimators=10).train(dataset)
    explainer = BehavioralAnomalyExplainer(artifact)

    normal_vector = [1.0] * len(BehavioralWindow.FEATURE_NAMES_V2)

    explanation = explainer.explain_vector(
        normal_vector,
        hostname="testhost",
        score=0.25,
        decision_margin=0.08,
        is_anomalous=False,
    )

    assert explanation.is_anomalous is False
    assert "NORMAL" in explanation.summary
    assert "expected statistical baseline" in explanation.summary
