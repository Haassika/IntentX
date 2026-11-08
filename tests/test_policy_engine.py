import pytest

from intentx.planning.models import OperationPlan
from intentx.planning.planner import OperationPlanner
from intentx.policy.engine import PolicyEngine
from intentx.policy.models import (
    PolicyDecision,
    PolicyReason,
)
from intentx.risk.engine import RiskAssessmentEngine
from intentx.risk.models import RiskAssessmentResult
from intentx.validation.operation_validator import (
    OperationValidator,
)


@pytest.fixture
def planner():
    return OperationPlanner()


@pytest.fixture
def validator():
    return OperationValidator()


@pytest.fixture
def risk_engine():
    return RiskAssessmentEngine()


@pytest.fixture
def policy_engine():
    return PolicyEngine()


def make_validated_plan(
    planner,
    validator,
    *,
    text,
    intent,
    entities,
):
    planning = planner.plan(
        text=text,
        intent=intent,
        entities=entities,
    )

    assert planning.plan is not None

    validation = validator.validate(
        planning.plan
    )

    assert validation.valid is True
    assert validation.plan is not None

    return validation.plan


def assess(
    risk_engine,
    plan,
    environment="DEV",
):
    return risk_engine.assess(
        plan,
        environment=environment,
    )


def test_policy_reason_is_immutable():
    reason = PolicyReason(
        code="TEST",
        message="Test reason.",
    )

    with pytest.raises(Exception):
        reason.code = "CHANGED"


def test_policy_decision_is_immutable():
    decision = PolicyDecision(
        decision="ALLOW",
        role="VIEWER",
        environment="DEV",
        intent="memory_inspection",
        action="memory_usage",
        category="inspection",
        risk_score=0,
        risk_level="LOW",
        reasons=(
            PolicyReason(
                code="TEST",
                message="Test reason.",
            ),
        ),
        metadata={},
    )

    with pytest.raises(Exception):
        decision.decision = "DENY"


def test_policy_metadata_is_immutable():
    decision = PolicyDecision(
        decision="ALLOW",
        role="VIEWER",
        environment="DEV",
        intent="memory_inspection",
        action="memory_usage",
        category="inspection",
        risk_score=0,
        risk_level="LOW",
        reasons=(
            PolicyReason(
                code="TEST",
                message="Test reason.",
            ),
        ),
        metadata={
            "example": True,
        },
    )

    with pytest.raises(TypeError):
        decision.metadata["changed"] = True


def test_policy_to_dict_returns_defensive_copies():
    decision = PolicyDecision(
        decision="ALLOW",
        role="VIEWER",
        environment="DEV",
        intent="memory_inspection",
        action="memory_usage",
        category="inspection",
        risk_score=0,
        risk_level="LOW",
        reasons=(
            PolicyReason(
                code="TEST",
                message="Test reason.",
            ),
        ),
        metadata={
            "example": True,
        },
    )

    exported = decision.to_dict()

    exported["metadata"]["example"] = False
    exported["reasons"][0]["code"] = "CHANGED"

    assert (
        decision.metadata["example"]
        is True
    )

    assert (
        decision.reasons[0].code
        == "TEST"
    )


def test_viewer_memory_inspection_is_allowed(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    risk = assess(
        risk_engine,
        plan,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="VIEWER",
        environment="DEV",
    )

    assert decision.decision == "ALLOW"
    assert decision.risk_score == 0
    assert decision.risk_level == "LOW"

    assert decision.reason_codes == [
        "RISK_POLICY_APPLIED"
    ]


def test_role_is_normalized(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    risk = assess(
        risk_engine,
        plan,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role=" viewer ",
        environment="DEV",
    )

    assert decision.role == "VIEWER"
    assert decision.decision == "ALLOW"


def test_environment_is_normalized(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    risk = assess(
        risk_engine,
        plan,
        environment="DEV",
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="VIEWER",
        environment=" dev ",
    )

    assert decision.environment == "DEV"
    assert decision.decision == "ALLOW"


def test_environment_can_be_taken_from_risk(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    risk = assess(
        risk_engine,
        plan,
        environment="DEV",
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="VIEWER",
    )

    assert decision.environment == "DEV"
    assert decision.decision == "ALLOW"


def test_viewer_cannot_restart_service(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    risk = assess(
        risk_engine,
        plan,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="VIEWER",
        environment="DEV",
    )

    assert decision.decision == "DENY"

    assert decision.reason_codes == [
        "ROLE_CATEGORY_NOT_ALLOWED"
    ]


def test_operator_restart_requires_approval(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    risk = assess(
        risk_engine,
        plan,
    )

    assert risk.score == 50
    assert risk.level == "MEDIUM"

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="OPERATOR",
        environment="DEV",
    )

    assert (
        decision.decision
        == "REQUIRE_APPROVAL"
    )

    assert decision.reason_codes == [
        "RISK_POLICY_APPLIED"
    ]


def test_operator_cannot_delete_file(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="delete /tmp/report.txt",
        intent="file_delete",
        entities={
            "PATH": "/tmp/report.txt",
        },
    )

    risk = assess(
        risk_engine,
        plan,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="OPERATOR",
        environment="DEV",
    )

    assert decision.decision == "DENY"

    assert decision.reason_codes == [
        "ROLE_CATEGORY_NOT_ALLOWED"
    ]


def test_senior_operator_delete_requires_approval(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="delete /tmp/report.txt",
        intent="file_delete",
        entities={
            "PATH": "/tmp/report.txt",
        },
    )

    risk = assess(
        risk_engine,
        plan,
    )

    assert risk.score == 50
    assert risk.level == "MEDIUM"

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="SENIOR_OPERATOR",
        environment="DEV",
    )

    assert (
        decision.decision
        == "REQUIRE_APPROVAL"
    )


def test_administrator_delete_requires_approval(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="delete /tmp/report.txt",
        intent="file_delete",
        entities={
            "PATH": "/tmp/report.txt",
        },
    )

    risk = assess(
        risk_engine,
        plan,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="ADMINISTRATOR",
        environment="DEV",
    )

    assert (
        decision.decision
        == "REQUIRE_APPROVAL"
    )


def test_disk_format_hits_hard_boundary(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="format /dev/sdb",
        intent="disk_management",
        entities={
            "DEVICE": "/dev/sdb",
        },
    )

    risk = assess(
        risk_engine,
        plan,
    )

    assert risk.score == 100
    assert risk.level == "CRITICAL"

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="ADMINISTRATOR",
        environment="DEV",
    )

    assert decision.decision == "DENY"

    assert decision.reason_codes == [
        "HARD_SAFETY_BOUNDARY"
    ]

    assert (
        decision.metadata["boundary"]
        == "destructive_disk_operation"
    )


def test_hard_boundary_precedes_risk_policy(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="format /dev/sdb",
        intent="disk_management",
        entities={
            "DEVICE": "/dev/sdb",
        },
    )

    risk = assess(
        risk_engine,
        plan,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="ADMINISTRATOR",
        environment="DEV",
    )

    assert (
        "HARD_SAFETY_BOUNDARY"
        in decision.reason_codes
    )

    assert (
        "RISK_POLICY_APPLIED"
        not in decision.reason_codes
    )


def test_low_risk_result_cannot_be_reused_for_restart(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    memory_plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    restart_plan = make_validated_plan(
        planner,
        validator,
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    low_risk = assess(
        risk_engine,
        memory_plan,
    )

    assert low_risk.score == 0

    decision = policy_engine.evaluate(
        plan=restart_plan,
        risk=low_risk,
        role="OPERATOR",
        environment="DEV",
    )

    assert decision.decision == "DENY"

    assert decision.reason_codes == [
        "RISK_ASSESSMENT_MISMATCH"
    ]


def test_tampered_risk_score_is_denied(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    genuine = assess(
        risk_engine,
        plan,
    )

    tampered = RiskAssessmentResult(
        score=25,
        level="LOW",
        base_score=genuine.base_score,
        environment_adjustment=(
            genuine.environment_adjustment
        ),
        environment=genuine.environment,
        factors=genuine.factors,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=tampered,
        role="OPERATOR",
        environment="DEV",
    )

    assert decision.decision == "DENY"

    assert decision.reason_codes == [
        "RISK_ASSESSMENT_MISMATCH"
    ]

    assert (
        decision.metadata["mismatch"]
        == "score"
    )


def test_tampered_risk_level_is_denied(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    genuine = assess(
        risk_engine,
        plan,
    )

    tampered = RiskAssessmentResult(
        score=genuine.score,
        level="LOW",
        base_score=genuine.base_score,
        environment_adjustment=(
            genuine.environment_adjustment
        ),
        environment=genuine.environment,
        factors=genuine.factors,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=tampered,
        role="OPERATOR",
        environment="DEV",
    )

    assert decision.decision == "DENY"

    assert decision.reason_codes == [
        "RISK_ASSESSMENT_MISMATCH"
    ]

    assert (
        decision.metadata["mismatch"]
        == "level"
    )


def test_tampered_risk_factors_are_denied(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    genuine = assess(
        risk_engine,
        plan,
    )

    tampered_factors = tuple(
        factor
        for factor in genuine.factors
        if factor.code
        != "PRIVILEGE_REQUIRED"
    )

    tampered = RiskAssessmentResult(
        score=genuine.score,
        level=genuine.level,
        base_score=genuine.base_score,
        environment_adjustment=(
            genuine.environment_adjustment
        ),
        environment=genuine.environment,
        factors=tampered_factors,
    )

    decision = policy_engine.evaluate(
        plan=plan,
        risk=tampered,
        role="OPERATOR",
        environment="DEV",
    )

    assert decision.decision == "DENY"

    assert decision.reason_codes == [
        "RISK_ASSESSMENT_MISMATCH"
    ]

    assert (
        decision.metadata["mismatch"]
        == "factors"
    )


def test_environment_mismatch_is_rejected(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    dev_risk = assess(
        risk_engine,
        plan,
        environment="DEV",
    )

    with pytest.raises(
        ValueError,
        match=(
            "Risk assessment environment "
            "does not match"
        ),
    ):
        policy_engine.evaluate(
            plan=plan,
            risk=dev_risk,
            role="VIEWER",
            environment="PROD",
        )


def test_unknown_role_is_rejected(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    risk = assess(
        risk_engine,
        plan,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported role",
    ):
        policy_engine.evaluate(
            plan=plan,
            risk=risk,
            role="SUPERUSER",
            environment="DEV",
        )


def test_unknown_environment_is_rejected(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    risk = assess(
        risk_engine,
        plan,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported environment",
    ):
        policy_engine.evaluate(
            plan=plan,
            risk=risk,
            role="VIEWER",
            environment="STAGING",
        )


def test_non_plan_is_rejected(
    risk_engine,
    policy_engine,
):
    plan = OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="free",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    risk = assess(
        risk_engine,
        plan,
    )

    with pytest.raises(
        TypeError,
        match="plan must be an OperationPlan",
    ):
        policy_engine.evaluate(
            plan="not-a-plan",
            risk=risk,
            role="VIEWER",
            environment="DEV",
        )


def test_non_risk_result_is_rejected(
    policy_engine,
):
    plan = OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="free",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    with pytest.raises(
        TypeError,
        match=(
            "risk must be a "
            "RiskAssessmentResult"
        ),
    ):
        policy_engine.evaluate(
            plan=plan,
            risk="not-risk",
            role="VIEWER",
            environment="DEV",
        )


def test_prod_environment_can_raise_file_create_to_medium(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="create file /tmp/report.txt",
        intent="file_create",
        entities={
            "PATH": "/tmp/report.txt",
        },
    )

    risk = assess(
        risk_engine,
        plan,
        environment="PROD",
    )

    assert risk.score == 40
    assert risk.level == "MEDIUM"

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="OPERATOR",
        environment="PROD",
    )

    assert (
        decision.decision
        == "REQUIRE_APPROVAL"
    )


def test_dev_file_create_is_low_risk_allow(
    planner,
    validator,
    risk_engine,
    policy_engine,
):
    plan = make_validated_plan(
        planner,
        validator,
        text="create file /tmp/report.txt",
        intent="file_create",
        entities={
            "PATH": "/tmp/report.txt",
        },
    )

    risk = assess(
        risk_engine,
        plan,
        environment="DEV",
    )

    assert risk.score == 25
    assert risk.level == "LOW"

    decision = policy_engine.evaluate(
        plan=plan,
        risk=risk,
        role="OPERATOR",
        environment="DEV",
    )

    assert decision.decision == "ALLOW"