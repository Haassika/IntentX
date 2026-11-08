from fastapi.testclient import TestClient

from intentx.api.app import create_app
from intentx.application.service import ApplicationResult


class FakeApplicationService:
    def handle(self, request):
        return ApplicationResult(
            status="READY",
            stage="TEST",
            reason="Not used by UI page test.",
            executed=False,
        )


def make_client():
    app = create_app(
        application_service=FakeApplicationService()
    )
    return TestClient(app)


def get_dashboard_text():
    client = make_client()
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

    return response.text


# ---------------------------------------------------------
# Dashboard availability and identity
# ---------------------------------------------------------


def test_dashboard_is_available():
    get_dashboard_text()


def test_dashboard_contains_intentx_identity():
    text = get_dashboard_text()

    assert "IntentX" in text
    assert "Safe Linux Command Execution" in text
    assert "Controlled Operations Console" in text


def test_existing_health_endpoint_still_works():
    client = make_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "intentx",
    }


# ---------------------------------------------------------
# Request controls
# ---------------------------------------------------------


def test_dashboard_contains_request_controls():
    text = get_dashboard_text()

    assert 'id="intent-text"' in text
    assert 'id="role"' in text
    assert 'id="environment"' in text
    assert 'id="analyze-button"' in text
    assert 'id="execute"' in text


def test_dashboard_contains_explicit_execute_control():
    text = get_dashboard_text()

    assert "Execute Safely" in text
    assert "execute=true" in text
    assert "separate" in text


# ---------------------------------------------------------
# Analysis and security visualization
# ---------------------------------------------------------


def test_dashboard_contains_result_sections():
    text = get_dashboard_text()

    assert 'id="intent-result"' in text
    assert 'id="confidence-result"' in text
    assert 'id="plan-result"' in text
    assert 'id="status-result"' in text


def test_dashboard_contains_security_assessment_sections():
    text = get_dashboard_text()

    assert 'id="validation-result"' in text
    assert 'id="risk-score-result"' in text
    assert 'id="risk-level-result"' in text
    assert 'id="policy-result"' in text
    assert 'id="policy-role-result"' in text
    assert 'id="policy-environment-result"' in text
    assert 'id="risk-factors-result"' in text
    assert 'id="policy-reasons-result"' in text


def test_dashboard_describes_assessment_as_read_only():
    text = get_dashboard_text()

    assert "Read-only security assessment" in text
    assert "not execution authorization" in text


def test_dashboard_reads_security_assessment_from_api_response():
    text = get_dashboard_text()

    assert "data.security_assessment" in text
    assert "assessment.validation" in text
    assert "assessment.risk" in text
    assert "assessment.policy" in text


# ---------------------------------------------------------
# Phase 14A: explicit two-step execution workflow
# ---------------------------------------------------------


def test_analyze_path_requests_execute_false():
    text = get_dashboard_text()

    assert "execute: false" in text
    assert "call(false)" in text


def test_execute_control_uses_separate_execute_true_request():
    text = get_dashboard_text()

    assert "execute.onclick" in text
    assert "call(true)" in text


def test_dashboard_uses_single_intent_api_boundary():
    text = get_dashboard_text()

    assert 'fetch("/api/v1/intent"' in text

    assert "/api/v1/execute" not in text
    assert "/execute" not in text


def test_execute_requires_prior_analysis_snapshot():
    text = get_dashboard_text()

    assert "if(!snapshot)return" in text

    assert (
        "Analyze again before execution."
        in text
    )


def test_request_change_invalidates_execution_state():
    text = get_dashboard_text()

    assert (
        "intent.value.trim()!=snapshot.q"
        in text
    )
    assert "role.value!=snapshot.r" in text
    assert "env.value!=snapshot.e" in text


# ---------------------------------------------------------
# Execution result visualization
# ---------------------------------------------------------


def test_dashboard_contains_execution_result_sections():
    text = get_dashboard_text()

    assert 'id="execution"' in text
    assert 'id="execSummary"' in text
    assert 'id="execId"' in text
    assert 'id="duration"' in text
    assert 'id="execStatus"' in text
    assert 'id="terminal"' in text
    assert 'id="auth"' in text
    assert 'id="process"' in text
    assert 'id="exit"' in text
    assert 'id="bounds"' in text


def test_dashboard_renders_execution_response_fields():
    text = get_dashboard_text()

    assert ".execution_result" in text
    assert "stdout" in text
    assert "stderr" in text
    assert "return_code" in text
    assert "execution_id" in text
    assert "stdout_truncated" in text
    assert "stderr_truncated" in text


def test_dashboard_explains_controlled_runtime_boundary():
    text = get_dashboard_text()

    assert (
        "controlled runtime"
        in text.lower()
    )

    assert (
        "no authorized process launch occurred"
        in text.lower()
    )


# ---------------------------------------------------------
# Client-side security boundaries
# ---------------------------------------------------------


def test_dashboard_contains_no_client_side_security_engine():
    text = get_dashboard_text()

    forbidden = (
        "new PolicyEngine",
        "new RiskAssessmentEngine",
        "new ExecutionBroker",
        "new ProcessRunner",
        "subprocess",
        "shell=True",
    )

    for value in forbidden:
        assert value not in text


def test_dashboard_contains_no_direct_browser_process_execution():
    text = get_dashboard_text()

    forbidden = (
        "child_process",
        "execSync(",
        "spawn(",
        "os.system",
    )

    for value in forbidden:
        assert value not in text


def test_dashboard_contains_xai_and_mitigation_panel():
    text = get_dashboard_text()

    assert "xai-mitigation-panel" in text
    assert "Explainable AI (XAI) & Threat Mitigation" in text
    assert "Intelligent Mitigation Recommendations" in text
    assert "/api/v1/behavior/explain" in text
