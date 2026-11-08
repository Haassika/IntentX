from dataclasses import asdict, dataclass
from typing import List, Optional

from intentx.planning.models import OperationPlan
from intentx.planning.planner import (
    OperationPlanner,
)
from intentx.validation.models import (
    ValidationIssue,
)
from intentx.validation.operation_validator import (
    OperationValidator,
)


@dataclass(frozen=True)
class ValidationPipelineResult:
    """
    Result of deterministic planning followed by
    deterministic operation validation.

    This result does NOT represent authorization
    to execute an operating-system operation.
    """

    planned: bool
    validated: bool
    decision: str
    reason: str
    plan: Optional[OperationPlan]
    issues: List[ValidationIssue]

    def to_dict(self):
        """
        Return a serialization-safe representation.

        OperationPlan contains immutable internal
        structures such as MappingProxyType. Using
        dataclasses.asdict() on the complete pipeline
        result would attempt to deepcopy those
        structures.

        Instead, OperationPlan performs its own
        defensive serialization while validation
        issues are ordinary dataclasses.
        """

        return {
            "planned": self.planned,
            "validated": self.validated,
            "decision": self.decision,
            "reason": self.reason,
            "plan": (
                self.plan.to_dict()
                if self.plan is not None
                else None
            ),
            "issues": [
                asdict(issue)
                for issue in self.issues
            ],
        }


class ValidationPipeline:
    """
    Coordinates deterministic operation planning
    and validation.

    This pipeline deliberately contains no:
    - command execution
    - shell invocation
    - privilege escalation
    - risk authorization
    - RBAC authorization
    """

    def __init__(
        self,
        planner=None,
        validator=None,
    ):
        self.planner = (
            planner
            or OperationPlanner()
        )

        self.validator = (
            validator
            or OperationValidator()
        )

    def process(
        self,
        text: str,
        intent: str,
        entities: dict,
    ) -> ValidationPipelineResult:
        """
        Plan and validate an operation.

        The caller is responsible for ensuring that
        intent classification and entity extraction
        have already passed their earlier gates.
        """

        if not isinstance(text, str):
            raise TypeError(
                "text must be a string."
            )

        if not text.strip():
            raise ValueError(
                "text cannot be empty."
            )

        if not isinstance(intent, str):
            raise TypeError(
                "intent must be a string."
            )

        if not intent.strip():
            raise ValueError(
                "intent cannot be empty."
            )

        if not isinstance(entities, dict):
            raise TypeError(
                "entities must be a dictionary."
            )

        planning_result = self.planner.plan(
            text=text,
            intent=intent,
            entities=entities,
        )

        if (
            not planning_result.planned
            or planning_result.plan is None
        ):
            return ValidationPipelineResult(
                planned=False,
                validated=False,
                decision=planning_result.decision,
                reason=planning_result.reason,
                plan=None,
                issues=[],
            )

        validation_result = (
            self.validator.validate(
                planning_result.plan
            )
        )

        if not validation_result.valid:
            return ValidationPipelineResult(
                planned=True,
                validated=False,
                decision="VALIDATION_FAILED",
                reason=(
                    "Operation plan failed "
                    "deterministic validation."
                ),
                plan=planning_result.plan,
                issues=validation_result.issues,
            )

        return ValidationPipelineResult(
            planned=True,
            validated=True,
            decision="READY_FOR_RISK_ASSESSMENT",
            reason=(
                "Operation plan passed deterministic "
                "validation. Execution is not "
                "authorized."
            ),
            plan=planning_result.plan,
            issues=[],
        )