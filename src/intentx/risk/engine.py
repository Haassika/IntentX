from pathlib import Path
from typing import Dict, Optional

import yaml

from intentx.planning.models import OperationPlan
from intentx.risk.models import (
    RiskAssessmentResult,
    RiskFactor,
)


class RiskAssessmentEngine:
    """
    Deterministic risk assessment for validated
    IntentX operation plans.

    Risk scoring parameters are loaded from the
    security policy.

    The engine measures risk. It does NOT authorize
    execution. Authorization decisions belong to
    the policy layer.
    """

    DEFAULT_POLICY_PATH = Path(
        "configs/security_policy.yaml"
    )

    def __init__(
        self,
        policy_path: Optional[Path] = None,
    ):
        self.policy_path = (
            Path(policy_path)
            if policy_path is not None
            else self.DEFAULT_POLICY_PATH
        )

        self.policy = self._load_policy()

        self.risk_levels = (
            self._load_risk_levels()
        )

        self.environments = (
            self._load_environments()
        )

        (
            self.state_changing_score,
            self.privilege_scores,
            self.critical_operation_score,
            self.action_risk_scores,
        ) = self._load_risk_scoring()

    def assess(
        self,
        plan: OperationPlan,
        environment: str = "DEV",
    ) -> RiskAssessmentResult:
        """
        Calculate deterministic risk for a validated
        OperationPlan.

        This method does not make an authorization
        decision.
        """

        if not isinstance(plan, OperationPlan):
            raise TypeError(
                "plan must be an OperationPlan."
            )

        environment = (
            self._normalize_environment(
                environment
            )
        )

        factors = []

        action_score = (
            self._action_risk_score(
                plan.action
            )
        )

        if action_score > 0:
            factors.append(
                RiskFactor(
                    code="ACTION_SENSITIVITY",
                    description=(
                        "Resolved action has an explicit "
                        "operation-sensitivity risk weight."
                    ),
                    score=action_score,
                )
            )

        if plan.state_changing:
            factors.append(
                RiskFactor(
                    code="STATE_CHANGING",
                    description=(
                        "Operation changes system state."
                    ),
                    score=self.state_changing_score,
                )
            )

        privilege_score = (
            self._privilege_risk_score(
                plan.privilege_required
            )
        )

        if privilege_score > 0:
            factors.append(
                RiskFactor(
                    code="PRIVILEGE_REQUIRED",
                    description=(
                        "Operation may require elevated "
                        "or privileged execution."
                    ),
                    score=privilege_score,
                )
            )

        if plan.critical_operation:
            factors.append(
                RiskFactor(
                    code="CRITICAL_OPERATION",
                    description=(
                        "Operation is marked critical by "
                        "the intent catalog."
                    ),
                    score=self.critical_operation_score,
                )
            )

        base_score = sum(
            factor.score
            for factor in factors
        )

        environment_adjustment = (
            self._environment_adjustment(
                environment
            )
        )

        score = self._clamp_score(
            base_score
            + environment_adjustment
        )

        level = self._risk_level_for_score(
            score
        )

        return RiskAssessmentResult(
            score=score,
            level=level,
            base_score=base_score,
            environment_adjustment=(
                environment_adjustment
            ),
            environment=environment,
            factors=tuple(factors),
        )

    def _load_policy(
        self,
    ) -> Dict[str, object]:
        if not self.policy_path.exists():
            raise FileNotFoundError(
                "Security policy not found: "
                f"{self.policy_path}"
            )

        with self.policy_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            policy = yaml.safe_load(file)

        if not isinstance(policy, dict):
            raise ValueError(
                "Security policy must contain "
                "a YAML mapping."
            )

        return policy

    def _load_risk_levels(
        self,
    ) -> Dict[str, Dict[str, int]]:
        raw_levels = self.policy.get(
            "risk_levels"
        )

        if not isinstance(
            raw_levels,
            dict,
        ):
            raise ValueError(
                "Security policy must define "
                "risk_levels."
            )

        required_levels = (
            "low",
            "medium",
            "high",
            "critical",
        )

        normalized = {}

        for level in required_levels:
            config = raw_levels.get(level)

            if not isinstance(
                config,
                dict,
            ):
                raise ValueError(
                    "Missing or invalid risk level: "
                    f"{level}"
                )

            min_score = config.get(
                "min_score"
            )

            max_score = config.get(
                "max_score"
            )

            if not isinstance(
                min_score,
                int,
            ):
                raise ValueError(
                    f"{level}.min_score must be "
                    "an integer."
                )

            if not isinstance(
                max_score,
                int,
            ):
                raise ValueError(
                    f"{level}.max_score must be "
                    "an integer."
                )

            if not (
                0
                <= min_score
                <= max_score
                <= 100
            ):
                raise ValueError(
                    "Invalid risk range for "
                    f"{level}."
                )

            normalized[level] = {
                "min_score": min_score,
                "max_score": max_score,
            }

        self._validate_risk_level_coverage(
            normalized
        )

        return normalized

    def _load_environments(
        self,
    ) -> Dict[str, int]:
        declared = self.policy.get(
            "environments"
        )

        environment_policy = (
            self.policy.get(
                "environment_policy"
            )
        )

        if not isinstance(
            declared,
            list,
        ):
            raise ValueError(
                "Security policy must define "
                "environments as a list."
            )

        if not isinstance(
            environment_policy,
            dict,
        ):
            raise ValueError(
                "Security policy must define "
                "environment_policy."
            )

        normalized = {}

        for environment in declared:
            if not isinstance(
                environment,
                str,
            ):
                raise ValueError(
                    "Environment names must be "
                    "strings."
                )

            canonical = (
                environment.strip().upper()
            )

            if not canonical:
                raise ValueError(
                    "Environment names cannot "
                    "be empty."
                )

            if canonical in normalized:
                raise ValueError(
                    "Duplicate environment: "
                    f"{canonical}"
                )

            config = (
                environment_policy.get(
                    environment
                )
            )

            if not isinstance(
                config,
                dict,
            ):
                raise ValueError(
                    "Missing environment policy "
                    f"for {environment}."
                )

            adjustment = config.get(
                "risk_adjustment"
            )

            if (
                isinstance(
                    adjustment,
                    bool,
                )
                or not isinstance(
                    adjustment,
                    int,
                )
            ):
                raise ValueError(
                    "Risk adjustment for "
                    f"{environment} must be "
                    "an integer."
                )

            normalized[
                canonical
            ] = adjustment

        return normalized

    def _load_risk_scoring(self):
        scoring = self.policy.get(
            "risk_scoring"
        )

        if not isinstance(
            scoring,
            dict,
        ):
            raise ValueError(
                "Security policy must define "
                "risk_scoring."
            )

        factor_weights = scoring.get(
            "factor_weights"
        )

        action_weights = scoring.get(
            "action_weights"
        )

        if not isinstance(
            factor_weights,
            dict,
        ):
            raise ValueError(
                "risk_scoring.factor_weights "
                "must be a mapping."
            )

        if not isinstance(
            action_weights,
            dict,
        ):
            raise ValueError(
                "risk_scoring.action_weights "
                "must be a mapping."
            )

        state_changing = (
            factor_weights.get(
                "state_changing"
            )
        )

        critical_operation = (
            factor_weights.get(
                "critical_operation"
            )
        )

        privilege_required = (
            factor_weights.get(
                "privilege_required"
            )
        )

        self._validate_weight(
            state_changing,
            "state_changing",
        )

        self._validate_weight(
            critical_operation,
            "critical_operation",
        )

        if not isinstance(
            privilege_required,
            dict,
        ):
            raise ValueError(
                "privilege_required risk weights "
                "must be a mapping."
            )

        false_weight = (
            privilege_required.get(False)
        )

        conditional_weight = (
            privilege_required.get(
                "conditional"
            )
        )

        true_weight = (
            privilege_required.get(True)
        )

        self._validate_weight(
            false_weight,
            "privilege_required.false",
        )

        self._validate_weight(
            conditional_weight,
            "privilege_required.conditional",
        )

        self._validate_weight(
            true_weight,
            "privilege_required.true",
        )

        if false_weight != 0:
            raise ValueError(
                "privilege_required.false "
                "must have risk weight 0."
            )

        normalized_actions = {}

        for action, weight in (
            action_weights.items()
        ):
            if not isinstance(
                action,
                str,
            ):
                raise ValueError(
                    "Risk action names must be "
                    "strings."
                )

            canonical_action = (
                action.strip()
            )

            if not canonical_action:
                raise ValueError(
                    "Risk action names cannot "
                    "be empty."
                )

            if canonical_action != action:
                raise ValueError(
                    "Risk action names must be "
                    "canonical and contain no "
                    "surrounding whitespace."
                )

            self._validate_weight(
                weight,
                f"action.{action}",
            )

            normalized_actions[
                canonical_action
            ] = weight

        if not normalized_actions:
            raise ValueError(
                "At least one action risk weight "
                "must be configured."
            )

        privilege_scores = {
            False: false_weight,
            "conditional": (
                conditional_weight
            ),
            True: true_weight,
        }

        return (
            state_changing,
            privilege_scores,
            critical_operation,
            normalized_actions,
        )

    @staticmethod
    def _validate_weight(
        value,
        name: str,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise ValueError(
                f"Risk weight {name} must "
                "be an integer."
            )

        if value < 0:
            raise ValueError(
                f"Risk weight {name} cannot "
                "be negative."
            )

    def _normalize_environment(
        self,
        environment: str,
    ) -> str:
        if not isinstance(
            environment,
            str,
        ):
            raise TypeError(
                "environment must be a string."
            )

        normalized = (
            environment.strip().upper()
        )

        if not normalized:
            raise ValueError(
                "environment cannot be empty."
            )

        if (
            normalized
            not in self.environments
        ):
            raise ValueError(
                "Unsupported environment: "
                f"{environment}"
            )

        return normalized

    def _action_risk_score(
        self,
        action: str,
    ) -> int:
        if not isinstance(
            action,
            str,
        ):
            raise TypeError(
                "Operation action must be "
                "a string."
            )

        if (
            action
            not in self.action_risk_scores
        ):
            raise ValueError(
                "No deterministic risk weight "
                f"defined for action: {action}"
            )

        return self.action_risk_scores[
            action
        ]

    def _privilege_risk_score(
        self,
        privilege_required,
    ) -> int:
        if privilege_required is True:
            return self.privilege_scores[
                True
            ]

        if privilege_required is False:
            return self.privilege_scores[
                False
            ]

        if (
            privilege_required
            == "conditional"
        ):
            return self.privilege_scores[
                "conditional"
            ]

        raise ValueError(
            "Unsupported privilege requirement: "
            f"{privilege_required}"
        )

    def _environment_adjustment(
        self,
        environment: str,
    ) -> int:
        return self.environments[
            environment
        ]

    @staticmethod
    def _clamp_score(
        score: int,
    ) -> int:
        return max(
            0,
            min(
                100,
                score,
            ),
        )

    def _risk_level_for_score(
        self,
        score: int,
    ) -> str:
        for level, config in (
            self.risk_levels.items()
        ):
            if (
                config["min_score"]
                <= score
                <= config["max_score"]
            ):
                return level.upper()

        raise ValueError(
            "Risk score is not covered by "
            "configured risk levels: "
            f"{score}"
        )

    @staticmethod
    def _validate_risk_level_coverage(
        levels: Dict[
            str,
            Dict[str, int],
        ],
    ) -> None:
        """
        Require configured risk levels to cover
        every integer score from 0 through 100
        exactly once.

        This prevents gaps and overlapping ranges
        from silently changing risk classification.
        """

        coverage = {
            score: 0
            for score in range(101)
        }

        for config in levels.values():
            for score in range(
                config["min_score"],
                config["max_score"] + 1,
            ):
                coverage[score] += 1

        invalid_scores = [
            score
            for score, count
            in coverage.items()
            if count != 1
        ]

        if invalid_scores:
            raise ValueError(
                "Risk level ranges must cover "
                "0-100 exactly once."
            )