from datetime import datetime, timezone
import pytest

from intentx.application.service import IntentXApplicationService
from intentx.behavior.explainer import FeatureAttribution, WindowExplanation
from intentx.behavior.mitigation import MitigationRecommendation, MitigationRecommender


def _make_dummy_explanation(
    is_anomalous: bool,
    primary_feature: str = "process_event_count",
    z_score: float = 3.5,
) -> WindowExplanation:
    primary = FeatureAttribution(
        feature_name=primary_feature,
        observed_value=25.0,
        baseline_mean=2.0,
        baseline_std=1.0,
        deviation_zscore=z_score,
        attribution_score=0.45,
        contribution_percentage=45.0,
        description=f"{primary_feature} is elevated",
    )
    return WindowExplanation(
        hostname="testhost",
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        is_anomalous=is_anomalous,
        score=-0.42 if is_anomalous else 0.25,
        decision_margin=-0.12 if is_anomalous else 0.05,
        summary="Test anomaly explanation summary",
        primary_factors=(primary,),
        all_attributions=(primary,),
    )


def test_recommend_returns_empty_for_normal_window():
    explanation = _make_dummy_explanation(is_anomalous=False)
    recommendations = MitigationRecommender.recommend(explanation)
    assert recommendations == []


def test_recommend_process_anomaly():
    explanation = _make_dummy_explanation(is_anomalous=True, primary_feature="process_event_count")
    recommendations = MitigationRecommender.recommend(explanation)

    assert len(recommendations) >= 1
    categories = [r.category for r in recommendations]
    assert "process_inspection" in categories or "process_management" in categories

    rec = recommendations[0]
    assert isinstance(rec, MitigationRecommendation)
    assert rec.suggested_intent
    assert rec.rationale
    assert rec.priority in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    # Test serialization
    d = rec.to_dict()
    assert "recommendation_id" in d
    assert "suggested_intent" in d
    assert "command_hint" in d


def test_recommend_network_anomaly():
    explanation = _make_dummy_explanation(is_anomalous=True, primary_feature="network_connection_count")
    recommendations = MitigationRecommender.recommend(explanation)

    assert len(recommendations) >= 1
    categories = [r.category for r in recommendations]
    assert "network_inspection" in categories or "network_management" in categories


def test_recommend_memory_anomaly():
    explanation = _make_dummy_explanation(is_anomalous=True, primary_feature="max_cgroup_memory_used_ratio")
    recommendations = MitigationRecommender.recommend(explanation)

    assert len(recommendations) >= 1
    categories = [r.category for r in recommendations]
    assert "storage_inspection" in categories or "storage_maintenance" in categories


def test_recommend_kernel_anomaly():
    explanation = _make_dummy_explanation(is_anomalous=True, primary_feature="kernel_event_count")
    recommendations = MitigationRecommender.recommend(explanation)

    assert len(recommendations) >= 1
    categories = [r.category for r in recommendations]
    assert "kernel_hardening" in categories or "system_information" in categories
    assert any("modules" in r.command_hint or "ptrace" in r.command_hint for r in recommendations)


def test_mitigation_to_application_request_integration():
    """Verify that a generated mitigation seamlessly feeds into the IntentX Application Service."""
    explanation = _make_dummy_explanation(is_anomalous=True, primary_feature="process_event_count")
    recommendations = MitigationRecommender.recommend(explanation)
    assert len(recommendations) > 0

    inspection_rec = next(r for r in recommendations if not r.state_changing)

    # Convert to IntentX ApplicationRequest
    app_request = inspection_rec.to_application_request(
        role="OPERATOR",
        environment="DEV",
        execute=False,
    )

    assert app_request.role == "OPERATOR"
    assert app_request.environment == "DEV"
    assert app_request.execute is False
    assert "mitigation-" in app_request.correlation_id

    # Feed into the core IntentX Application Service
    service = IntentXApplicationService()
    result = service.handle(app_request)

    # Must produce a valid result from the ML & deterministic pipeline
    assert result.status in {"PLAN_CREATED", "CLARIFICATION_REQUIRED"}
    assert result.predicted_intent is not None
