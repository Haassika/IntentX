from dataclasses import dataclass

import pytest

from fastapi.testclient import TestClient

from intentx.application.service import (
    ApplicationResult,
)
from intentx.planning.models import OperationPlan


class FakeApplicationService:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def handle(self, request):
        self.calls.append(request)
        return self.result


def make_plan():
    return OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="free",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )


def make_client(result):
    from intentx.api.app import create_app

    service = FakeApplicationService(result)

    app = create_app(
        application_service=service
    )

    return TestClient(app), service


def test_health_endpoint():
    from intentx.api.app import create_app

    app = create_app(
        application_service=FakeApplicationService(
            ApplicationResult(
                status="READY",
                stage="TEST",
                reason="Not used.",
                executed=False,
            )
        )
    )

    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "intentx",
    }


def test_intent_endpoint_delegates_to_application_service():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
        predicted_intent="memory_inspection",
        confidence=0.98,
        plan=make_plan(),
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "viewer",
            "environment": "dev",
            "correlation_id": "corr-api-001",
            "execute": False,
        },
    )

    assert response.status_code == 200
    assert len(service.calls) == 1

    request = service.calls[0]

    assert request.text == "show memory usage"
    assert request.role == "VIEWER"
    assert request.environment == "DEV"
    assert request.correlation_id == (
        "corr-api-001"
    )
    assert request.execute is False


def test_intent_endpoint_returns_plan_as_json():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
        predicted_intent="memory_inspection",
        confidence=0.98,
        plan=make_plan(),
    )

    client, _ = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-002",
            "execute": False,
        },
    )

    body = response.json()

    assert body["status"] == "PLAN_CREATED"
    assert body["stage"] == "PLANNING"
    assert body["executed"] is False
    assert body["predicted_intent"] == (
        "memory_inspection"
    )
    assert body["confidence"] == 0.98

    assert body["plan"]["intent"] == (
        "memory_inspection"
    )
    assert body["plan"]["action"] == (
        "memory_usage"
    )
    assert body["plan"]["executable"] == "free"
    assert body["plan"]["arguments"] == ["-h"]


def test_execute_defaults_to_false():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
        predicted_intent="memory_inspection",
        confidence=0.98,
        plan=make_plan(),
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-003",
        },
    )

    assert response.status_code == 200
    assert service.calls[0].execute is False


def test_api_can_request_execution_only_through_service():
    result = ApplicationResult(
        status="BLOCKED",
        stage="EXECUTION",
        reason="Policy did not allow execution.",
        executed=False,
        predicted_intent="memory_inspection",
        confidence=0.98,
        plan=make_plan(),
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-004",
            "execution_id": "exec-api-001",
            "execute": True,
        },
    )

    assert response.status_code == 200
    assert len(service.calls) == 1

    request = service.calls[0]

    assert request.execute is True
    assert request.execution_id == (
        "exec-api-001"
    )

    assert response.json()["status"] == (
        "BLOCKED"
    )
    assert response.json()["executed"] is False


def test_missing_required_field_returns_422():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
        },
    )

    assert response.status_code == 422
    assert service.calls == []


def test_invalid_execute_type_returns_422():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-005",
            "execute": "yes",
        },
    )

    assert response.status_code == 422
    assert service.calls == []


def test_empty_application_values_return_422():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "   ",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-006",
        },
    )

    assert response.status_code == 422
    assert service.calls == []


def test_unknown_route_returns_404():
    result = ApplicationResult(
        status="READY",
        stage="TEST",
        reason="Not used.",
        executed=False,
    )

    client, _ = make_client(result)

    response = client.get(
        "/api/v1/does-not-exist"
    )

    assert response.status_code == 404


def test_unknown_request_field_returns_422():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-007",
            "execute": False,
            "unexpected_field": "value",
        },
    )

    assert response.status_code == 422
    assert service.calls == []


@pytest.mark.parametrize(
    "invalid_execute",
    [
        "false",
        "true",
        0,
        1,
        None,
    ],
)
def test_execute_requires_strict_boolean(
    invalid_execute,
):
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-008",
            "execute": invalid_execute,
        },
    )

    assert response.status_code == 422
    assert service.calls == []


def test_empty_execution_id_returns_422():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason="Plan created.",
        executed=False,
    )

    client, service = make_client(result)

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": "corr-api-009",
            "execute": True,
            "execution_id": "   ",
        },
    )

    assert response.status_code == 422
    assert service.calls == []


# ---------------------------------------------------------
# Phase 11B: security assessment API serialization
# ---------------------------------------------------------


def _make_api_security_assessment():
    from intentx.policy.models import (
        PolicyDecision,
        PolicyReason,
    )
    from intentx.risk.models import (
        RiskAssessmentResult,
        RiskFactor,
    )
    from intentx.security.assessment import (
        SecurityAssessment,
    )

    risk = RiskAssessmentResult(
        score=20,
        level="LOW",
        base_score=20,
        environment_adjustment=0,
        environment="DEV",
        factors=(
            RiskFactor(
                code="STATE_CHANGING",
                description=(
                    "Operation changes system state."
                ),
                score=20,
            ),
        ),
    )

    policy = PolicyDecision(
        decision="ALLOW",
        role="OPERATOR",
        environment="DEV",
        intent="memory_inspection",
        action="memory_usage",
        category="inspection",
        risk_score=20,
        risk_level="LOW",
        reasons=(
            PolicyReason(
                code="TEST_ALLOW",
                message=(
                    "Operation is allowed by "
                    "test policy."
                ),
            ),
        ),
        metadata={
            "test": True,
        },
    )

    return SecurityAssessment(
        validation_valid=True,
        validation_decision="VALID",
        validation_issues=(),
        risk=risk,
        policy=policy,
    )


def test_intent_endpoint_serializes_security_assessment():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason=(
            "Structured operation plan created."
        ),
        executed=False,
        predicted_intent="memory_inspection",
        confidence=0.98,
        plan=make_plan(),
        security_assessment=(
            _make_api_security_assessment()
        ),
    )

    client, service = make_client(
        result
    )

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "OPERATOR",
            "environment": "DEV",
            "correlation_id": (
                "corr-api-security-001"
            ),
            "execute": False,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assessment = body[
        "security_assessment"
    ]

    assert assessment is not None

    assert (
        assessment["validation"]["valid"]
        is True
    )
    assert (
        assessment["validation"]["decision"]
        == "VALID"
    )
    assert (
        assessment["validation"]["issues"]
        == []
    )

    assert assessment["risk"]["score"] == 20
    assert assessment["risk"]["level"] == "LOW"

    assert (
        assessment["risk"]["factors"][0]["code"]
        == "STATE_CHANGING"
    )
    assert (
        assessment["risk"]["factors"][0]["score"]
        == 20
    )

    assert (
        assessment["policy"]["decision"]
        == "ALLOW"
    )
    assert (
        assessment["policy"]["role"]
        == "OPERATOR"
    )
    assert (
        assessment["policy"]["environment"]
        == "DEV"
    )
    assert (
        assessment["policy"]["reason_codes"]
        == ["TEST_ALLOW"]
    )


def test_intent_endpoint_security_assessment_is_null_when_absent():
    result = ApplicationResult(
        status="CLARIFICATION_REQUIRED",
        stage="ANALYSIS",
        reason="More information is required.",
        executed=False,
        predicted_intent="file_read",
        confidence=0.42,
    )

    client, service = make_client(
        result
    )

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "read the file",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": (
                "corr-api-security-002"
            ),
            "execute": False,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "security_assessment" in body
    assert (
        body["security_assessment"]
        is None
    )


def test_security_assessment_payload_has_no_execution_authority():
    result = ApplicationResult(
        status="PLAN_CREATED",
        stage="PLANNING",
        reason=(
            "Structured operation plan created."
        ),
        executed=False,
        predicted_intent="memory_inspection",
        confidence=0.98,
        plan=make_plan(),
        security_assessment=(
            _make_api_security_assessment()
        ),
    )

    client, service = make_client(
        result
    )

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "OPERATOR",
            "environment": "DEV",
            "correlation_id": (
                "corr-api-security-003"
            ),
            "execute": False,
        },
    )

    assessment = response.json()[
        "security_assessment"
    ]

    assert "execution_request" not in assessment
    assert "execution_id" not in assessment
    assert "executed" not in assessment
    assert "authorized_execution" not in assessment


def test_behavior_explain_and_mitigation_endpoints():
    from intentx.api.app import create_app

    service = FakeApplicationService(
        ApplicationResult(
            status="READY",
            stage="TEST",
            reason="Not used.",
            executed=False,
        )
    )

    app = create_app(application_service=service)
    client = TestClient(app)

    # 1. When no live scores file is configured/available
    resp_explain = client.get("/api/v1/behavior/explain")
    assert resp_explain.status_code == 200
    data_explain = resp_explain.json()
    assert data_explain["status"] == "no_data"

    resp_mit = client.get("/api/v1/behavior/mitigations")
    assert resp_mit.status_code == 200
    assert resp_mit.json()["status"] == "no_data"
