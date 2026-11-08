from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from intentx.planning.models import OperationPlan
from intentx.policy.engine import PolicyEngine
from intentx.policy.models import PolicyDecision
from intentx.risk.engine import RiskAssessmentEngine
from intentx.risk.models import RiskAssessmentResult
from intentx.validation.models import ValidationIssue
from intentx.validation.operation_validator import (
    OperationValidator,
)


@dataclass(frozen=True)
class SecurityAssessment:
    """
    Read-only deterministic security assessment.

    This result describes validation, risk, and
    policy evaluation for an OperationPlan.

    It is not an execution request, capability,
    approval token, or authority to launch a
    process.
    """

    validation_valid: bool
    validation_decision: str
    validation_issues: Tuple[
        ValidationIssue,
        ...,
    ]
    risk: Optional[RiskAssessmentResult]
    policy: Optional[PolicyDecision]

    def __post_init__(self):
        if not isinstance(
            self.validation_valid,
            bool,
        ):
            raise TypeError(
                "validation_valid must be "
                "a boolean."
            )

        if not isinstance(
            self.validation_decision,
            str,
        ):
            raise TypeError(
                "validation_decision must be "
                "a string."
            )

        validation_decision = (
            self.validation_decision.strip()
        )

        if not validation_decision:
            raise ValueError(
                "validation_decision cannot "
                "be empty."
            )

        immutable_issues = tuple(
            self.validation_issues
        )

        for issue in immutable_issues:
            if not isinstance(
                issue,
                ValidationIssue,
            ):
                raise TypeError(
                    "validation_issues must "
                    "contain ValidationIssue "
                    "objects."
                )

        if self.risk is not None:
            if not isinstance(
                self.risk,
                RiskAssessmentResult,
            ):
                raise TypeError(
                    "risk must be a "
                    "RiskAssessmentResult "
                    "or None."
                )

        if self.policy is not None:
            if not isinstance(
                self.policy,
                PolicyDecision,
            ):
                raise TypeError(
                    "policy must be a "
                    "PolicyDecision or None."
                )

        if not self.validation_valid:
            if self.risk is not None:
                raise ValueError(
                    "Invalid validation cannot "
                    "contain a risk result."
                )

            if self.policy is not None:
                raise ValueError(
                    "Invalid validation cannot "
                    "contain a policy decision."
                )

        if self.policy is not None:
            if self.risk is None:
                raise ValueError(
                    "Policy decision requires "
                    "a risk assessment."
                )

            if (
                self.policy.risk_score
                != self.risk.score
            ):
                raise ValueError(
                    "Policy and risk scores "
                    "must match."
                )

            if (
                self.policy.risk_level
                != self.risk.level
            ):
                raise ValueError(
                    "Policy and risk levels "
                    "must match."
                )

        object.__setattr__(
            self,
            "validation_decision",
            validation_decision,
        )

        object.__setattr__(
            self,
            "validation_issues",
            immutable_issues,
        )

    def to_dict(self):
        validation_payload = {
            "valid": self.validation_valid,
            "decision":
                self.validation_decision,
            "issues": [
                issue.to_dict()
                for issue
                in self.validation_issues
            ],
        }

        risk_payload = None

        if self.risk is not None:
            risk_payload = self.risk.to_dict()

        policy_payload = None

        if self.policy is not None:
            policy_payload = (
                self.policy.to_dict()
            )

            policy_payload[
                "reason_codes"
            ] = self.policy.reason_codes

        return {
            "validation":
                validation_payload,
            "risk":
                risk_payload,
            "policy":
                policy_payload,
        }


class SecurityAssessmentService:
    """
    Read-only deterministic security assessment.

    Processing order:

        OperationPlan
            -> deterministic validation
            -> deterministic risk assessment
            -> deterministic policy evaluation

    Validation failure is fail-closed: risk and
    policy evaluation do not continue.

    This service deliberately has no executable
    resolver, audit execution workflow,
    ProcessRunner, subprocess integration, or
    operating-system execution method.

    A successful assessment is descriptive only.
    Any later execution must independently pass
    through the ExecutionBroker security boundary.
    """

    def __init__(
        self,
        validator=None,
        risk_engine=None,
        policy_engine=None,
    ):
        self.validator = (
            validator
            or OperationValidator()
        )

        self.risk_engine = (
            risk_engine
            or RiskAssessmentEngine()
        )

        self.policy_engine = (
            policy_engine
            or PolicyEngine()
        )

    def assess(
        self,
        plan: OperationPlan,
        role: str,
        environment: str,
    ) -> SecurityAssessment:
        if not isinstance(
            plan,
            OperationPlan,
        ):
            raise TypeError(
                "plan must be an OperationPlan."
            )

        normalized_role = (
            self._normalize_required_string(
                role,
                "role",
            ).upper()
        )

        normalized_environment = (
            self._normalize_required_string(
                environment,
                "environment",
            ).upper()
        )

        validation = (
            self.validator.validate(plan)
        )

        if (
            not validation.valid
            or validation.plan is None
        ):
            return SecurityAssessment(
                validation_valid=False,
                validation_decision=(
                    validation.decision
                ),
                validation_issues=tuple(
                    validation.issues
                ),
                risk=None,
                policy=None,
            )

        validated_plan = validation.plan

        risk = self.risk_engine.assess(
            validated_plan,
            environment=(
                normalized_environment
            ),
        )

        policy = self.policy_engine.evaluate(
            plan=validated_plan,
            risk=risk,
            role=normalized_role,
            environment=(
                normalized_environment
            ),
        )

        return SecurityAssessment(
            validation_valid=True,
            validation_decision=(
                validation.decision
            ),
            validation_issues=tuple(
                validation.issues
            ),
            risk=risk,
            policy=policy,
        )

    @staticmethod
    def _normalize_required_string(
        value: str,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be "
                "a string."
            )

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                f"{field_name} cannot "
                "be empty."
            )

        return cleaned
