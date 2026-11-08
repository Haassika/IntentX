import pytest

from intentx.planning.models import OperationPlan
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
    SecurityAssessmentService,
)
from intentx.validation.models import (
    OperationValidationResult,
    ValidationIssue,
)


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


class ValidValidator:
    def __init__(self):
        self.calls = []

    def validate(self, plan):
        self.calls.append(plan)

        return OperationValidationResult(
            valid=True,
            decision="VALID",
            issues=[],
            plan=plan,
        )


class InvalidValidator:
    def __init__(self):
        self.calls = []

    def validate(self, plan):
        self.calls.append(plan)

        return OperationValidationResult(
            valid=False,
            decision="INVALID",
            issues=[
                ValidationIssue(
                    code="TEST_INVALID",
                    message="Plan is invalid.",
                    field="action",
                )
            ],
            plan=None,
        )


class FakeRiskEngine:
    def __init__(self):
        self.calls = []

    def assess(self, plan, environment="DEV"):
        self.calls.append(
            {
                "plan": plan,
                "environment": environment,
            }
        )

        return RiskAssessmentResult(
            score=0,
            level="LOW",
            base_score=0,
            environment_adjustment=0,
            environment=environment.upper(),
            factors=(),
        )


class FakePolicyEngine:
    def __init__(self):
        self.calls = []

    def evaluate(
        self,
        plan,
        risk,
        role,
        environment=None,
    ):
        self.calls.append(
            {
                "plan": plan,
                "risk": risk,
                "role": role,
                "environment": environment,
            }
        )

        return PolicyDecision(
            decision="ALLOW",
            role=role.upper(),
            environment=environment.upper(),
            intent=plan.intent,
            action=plan.action,
            category="inspection",
            risk_score=risk.score,
            risk_level=risk.level,
            reasons=(
                PolicyReason(
                    code="TEST_ALLOW",
                    message=(
                        "Test policy allows operation."
                    ),
                ),
            ),
            metadata={},
        )


class MustNotBeCalledRiskEngine:
    def assess(self, plan, environment="DEV"):
        raise AssertionError(
            "Risk engine must not run for "
            "an invalid plan."
        )


class MustNotBeCalledPolicyEngine:
    def evaluate(
        self,
        plan,
        risk,
        role,
        environment=None,
    ):
        raise AssertionError(
            "Policy engine must not run for "
            "an invalid plan."
        )


def test_assessment_result_is_immutable():
    result = SecurityAssessment(
        validation_valid=True,
        validation_decision="VALID",
        validation_issues=(),
        risk=None,
        policy=None,
    )

    with pytest.raises(
        AttributeError,
    ):
        result.validation_valid = False


def test_valid_plan_reaches_risk_and_policy():
    validator = ValidValidator()
    risk_engine = FakeRiskEngine()
    policy_engine = FakePolicyEngine()

    service = SecurityAssessmentService(
        validator=validator,
        risk_engine=risk_engine,
        policy_engine=policy_engine,
    )

    plan = make_plan()

    result = service.assess(
        plan=plan,
        role="viewer",
        environment="dev",
    )

    assert result.validation_valid is True
    assert result.validation_decision == "VALID"
    assert result.validation_issues == ()

    assert result.risk is not None
    assert result.risk.score == 0
    assert result.risk.level == "LOW"

    assert result.policy is not None
    assert result.policy.decision == "ALLOW"
    assert result.policy.role == "VIEWER"
    assert result.policy.environment == "DEV"

    assert validator.calls == [plan]

    assert len(risk_engine.calls) == 1
    assert risk_engine.calls[0]["plan"] is plan
    assert risk_engine.calls[0][
        "environment"
    ] == "DEV"

    assert len(policy_engine.calls) == 1
    assert policy_engine.calls[0][
        "plan"
    ] is plan
    assert policy_engine.calls[0][
        "risk"
    ] is result.risk
    assert policy_engine.calls[0][
        "role"
    ] == "VIEWER"
    assert policy_engine.calls[0][
        "environment"
    ] == "DEV"


def test_invalid_plan_fails_closed_before_risk():
    service = SecurityAssessmentService(
        validator=InvalidValidator(),
        risk_engine=MustNotBeCalledRiskEngine(),
        policy_engine=MustNotBeCalledPolicyEngine(),
    )

    result = service.assess(
        plan=make_plan(),
        role="VIEWER",
        environment="DEV",
    )

    assert result.validation_valid is False
    assert result.validation_decision == "INVALID"

    assert len(
        result.validation_issues
    ) == 1

    assert (
        result.validation_issues[0].code
        == "TEST_INVALID"
    )

    assert result.risk is None
    assert result.policy is None


def test_service_requires_operation_plan():
    service = SecurityAssessmentService(
        validator=ValidValidator(),
        risk_engine=FakeRiskEngine(),
        policy_engine=FakePolicyEngine(),
    )

    with pytest.raises(
        TypeError,
        match="OperationPlan",
    ):
        service.assess(
            plan="free -h",
            role="VIEWER",
            environment="DEV",
        )


@pytest.mark.parametrize(
    "role",
    [
        "",
        "   ",
        None,
        123,
    ],
)
def test_service_rejects_invalid_role(role):
    service = SecurityAssessmentService(
        validator=ValidValidator(),
        risk_engine=FakeRiskEngine(),
        policy_engine=FakePolicyEngine(),
    )

    with pytest.raises(
        (TypeError, ValueError),
    ):
        service.assess(
            plan=make_plan(),
            role=role,
            environment="DEV",
        )


@pytest.mark.parametrize(
    "environment",
    [
        "",
        "   ",
        None,
        123,
    ],
)
def test_service_rejects_invalid_environment(
    environment,
):
    service = SecurityAssessmentService(
        validator=ValidValidator(),
        risk_engine=FakeRiskEngine(),
        policy_engine=FakePolicyEngine(),
    )

    with pytest.raises(
        (TypeError, ValueError),
    ):
        service.assess(
            plan=make_plan(),
            role="VIEWER",
            environment=environment,
        )


def test_assessment_contains_no_execution_method():
    assert not hasattr(
        SecurityAssessmentService,
        "execute",
    )

    assert not hasattr(
        SecurityAssessmentService,
        "run",
    )

    assert not hasattr(
        SecurityAssessmentService,
        "authorize",
    )


def test_assessment_serializes_security_results():
    service = SecurityAssessmentService(
        validator=ValidValidator(),
        risk_engine=FakeRiskEngine(),
        policy_engine=FakePolicyEngine(),
    )

    result = service.assess(
        plan=make_plan(),
        role="VIEWER",
        environment="DEV",
    )

    payload = result.to_dict()

    assert payload[
        "validation"
    ]["valid"] is True

    assert payload[
        "risk"
    ]["score"] == 0

    assert payload[
        "risk"
    ]["level"] == "LOW"

    assert payload[
        "policy"
    ]["decision"] == "ALLOW"

    assert payload[
        "policy"
    ]["reason_codes"] == [
        "TEST_ALLOW"
    ]


def test_security_assessment_does_not_create_execution_request():
    service = SecurityAssessmentService(
        validator=ValidValidator(),
        risk_engine=FakeRiskEngine(),
        policy_engine=FakePolicyEngine(),
    )

    result = service.assess(
        plan=make_plan(),
        role="VIEWER",
        environment="DEV",
    )

    payload = result.to_dict()

    assert "execution_request" not in payload
    assert "execution_id" not in payload
    assert "executed" not in payload


def test_risk_factors_are_serialized():
    class RiskEngineWithFactor:
        def assess(
            self,
            plan,
            environment="DEV",
        ):
            return RiskAssessmentResult(
                score=20,
                level="LOW",
                base_score=20,
                environment_adjustment=0,
                environment=environment,
                factors=(
                    RiskFactor(
                        code="STATE_CHANGING",
                        description=(
                            "Operation changes "
                            "system state."
                        ),
                        score=20,
                    ),
                ),
            )

    service = SecurityAssessmentService(
        validator=ValidValidator(),
        risk_engine=RiskEngineWithFactor(),
        policy_engine=FakePolicyEngine(),
    )

    result = service.assess(
        plan=make_plan(),
        role="VIEWER",
        environment="DEV",
    )

    assert result.to_dict()["risk"][
        "factors"
    ][0]["code"] == "STATE_CHANGING"
