from pathlib import Path
from typing import Dict, Optional

import yaml

from intentx.planning.models import OperationPlan
from intentx.policy.models import (
    PolicyDecision,
    PolicyReason,
)
from intentx.risk.engine import RiskAssessmentEngine
from intentx.risk.models import RiskAssessmentResult


class PolicyEngine:
    """
    Deterministic authorization engine for IntentX.

    The engine consumes:

        - a validated immutable OperationPlan
        - a deterministic RiskAssessmentResult
        - a role
        - an environment

    and produces an immutable PolicyDecision.

    The supplied risk assessment is independently
    recomputed from the exact operation plan before
    authorization is evaluated.

    The policy engine does NOT execute operations.
    """

    DEFAULT_POLICY_PATH = Path(
        "configs/security_policy.yaml"
    )

    DEFAULT_CATALOG_PATH = Path(
        "configs/intent_catalog.yaml"
    )

    HARD_BOUNDARY_OPERATIONS = {
        (
            "disk_management",
            "format",
        ): "destructive_disk_operation",
    }

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        catalog_path: Optional[Path] = None,
    ):
        self.policy_path = (
            Path(policy_path)
            if policy_path is not None
            else self.DEFAULT_POLICY_PATH
        )

        self.catalog_path = (
            Path(catalog_path)
            if catalog_path is not None
            else self.DEFAULT_CATALOG_PATH
        )

        self.policy = self._load_yaml_mapping(
            self.policy_path,
            "Security policy",
        )

        self.catalog = self._load_yaml_mapping(
            self.catalog_path,
            "Intent catalog",
        )

        self.decision_types = (
            self._load_decision_types()
        )

        self.principles = (
            self._load_principles()
        )

        self.roles = self._load_roles()

        self.risk_decisions = (
            self._load_risk_decisions()
        )

        self.global_denials = (
            self._load_global_denials()
        )

        self.hard_safety_boundaries = (
            self._load_hard_safety_boundaries()
        )

        self.intent_categories = (
            self._load_intent_categories()
        )

        self.environments = (
            self._load_environments()
        )

        self._validate_role_categories()
        self._validate_hard_boundary_mappings()

        self.risk_engine = RiskAssessmentEngine(
            policy_path=self.policy_path
        )

    def evaluate(
        self,
        plan: OperationPlan,
        risk: RiskAssessmentResult,
        role: str,
        environment: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Evaluate authorization policy for a validated
        operation and deterministic risk result.

        Decision precedence:

            1. input/context integrity
            2. risk-plan integrity
            3. hard safety boundaries
            4. unsupported intent
            5. RBAC category permission
            6. state-changing permission
            7. configured risk decision
        """

        if not isinstance(
            plan,
            OperationPlan,
        ):
            raise TypeError(
                "plan must be an OperationPlan."
            )

        if not isinstance(
            risk,
            RiskAssessmentResult,
        ):
            raise TypeError(
                "risk must be a "
                "RiskAssessmentResult."
            )

        normalized_role = (
            self._normalize_role(role)
        )

        normalized_environment = (
            self._resolve_environment(
                environment,
                risk,
            )
        )

        self._validate_risk_environment(
            risk,
            normalized_environment,
        )

        category = (
            self._category_for_intent(
                plan.intent
            )
        )

        risk_integrity_error = (
            self._risk_integrity_error(
                plan=plan,
                supplied_risk=risk,
                environment=(
                    normalized_environment
                ),
            )
        )

        if risk_integrity_error is not None:
            return self._decision(
                decision="DENY",
                role=normalized_role,
                environment=(
                    normalized_environment
                ),
                plan=plan,
                category=category,
                risk=risk,
                reason=PolicyReason(
                    code=(
                        "RISK_ASSESSMENT_MISMATCH"
                    ),
                    message=(
                        "The supplied risk "
                        "assessment does not match "
                        "the deterministic risk "
                        "assessment for the exact "
                        "operation plan."
                    ),
                ),
                metadata={
                    "mismatch":
                        risk_integrity_error,
                },
            )

        hard_boundary = (
            self._matched_hard_boundary(
                plan
            )
        )

        if hard_boundary is not None:
            config = (
                self.hard_safety_boundaries[
                    hard_boundary
                ]
            )

            return self._decision(
                decision=config["decision"],
                role=normalized_role,
                environment=(
                    normalized_environment
                ),
                plan=plan,
                category=category,
                risk=risk,
                reason=PolicyReason(
                    code=(
                        "HARD_SAFETY_BOUNDARY"
                    ),
                    message=config[
                        "description"
                    ],
                ),
                metadata={
                    "boundary": hard_boundary,
                },
            )

        if category == "unsupported":
            config = self.global_denials[
                "unsupported_intent"
            ]

            return self._decision(
                decision=config["decision"],
                role=normalized_role,
                environment=(
                    normalized_environment
                ),
                plan=plan,
                category=category,
                risk=risk,
                reason=PolicyReason(
                    code="UNSUPPORTED_INTENT",
                    message=config[
                        "description"
                    ],
                ),
                metadata={
                    "global_denial":
                        "unsupported_intent",
                },
            )

        role_config = self.roles[
            normalized_role
        ]

        if (
            category
            not in role_config[
                "allowed_categories"
            ]
        ):
            return self._decision(
                decision="DENY",
                role=normalized_role,
                environment=(
                    normalized_environment
                ),
                plan=plan,
                category=category,
                risk=risk,
                reason=PolicyReason(
                    code=(
                        "ROLE_CATEGORY_NOT_ALLOWED"
                    ),
                    message=(
                        "The requested operation "
                        "category is not permitted "
                        "for this role."
                    ),
                ),
                metadata={
                    "allowed_categories": list(
                        role_config[
                            "allowed_categories"
                        ]
                    ),
                },
            )

        if (
            plan.state_changing
            and not role_config[
                "state_changing_allowed"
            ]
        ):
            return self._decision(
                decision="DENY",
                role=normalized_role,
                environment=(
                    normalized_environment
                ),
                plan=plan,
                category=category,
                risk=risk,
                reason=PolicyReason(
                    code=(
                        "STATE_CHANGE_NOT_ALLOWED"
                    ),
                    message=(
                        "The role is not permitted "
                        "to authorize state-changing "
                        "operations."
                    ),
                ),
                metadata={},
            )

        risk_decision = (
            self._decision_for_risk(
                risk.level
            )
        )

        return self._decision(
            decision=risk_decision,
            role=normalized_role,
            environment=(
                normalized_environment
            ),
            plan=plan,
            category=category,
            risk=risk,
            reason=PolicyReason(
                code="RISK_POLICY_APPLIED",
                message=(
                    "Authorization outcome was "
                    "determined by the configured "
                    "risk decision policy after "
                    "hard safety and RBAC checks."
                ),
            ),
            metadata={
                "risk_policy_level":
                    risk.level.upper(),
            },
        )

    def _risk_integrity_error(
        self,
        *,
        plan: OperationPlan,
        supplied_risk: RiskAssessmentResult,
        environment: str,
    ) -> Optional[str]:
        """
        Independently recompute risk from the exact
        plan and compare all security-relevant risk
        result fields.

        A mismatch fails closed at the policy layer.
        """

        expected = self.risk_engine.assess(
            plan,
            environment=environment,
        )

        if (
            supplied_risk.score
            != expected.score
        ):
            return "score"

        if (
            supplied_risk.level.strip().upper()
            != expected.level.strip().upper()
        ):
            return "level"

        if (
            supplied_risk.base_score
            != expected.base_score
        ):
            return "base_score"

        if (
            supplied_risk.environment_adjustment
            != expected.environment_adjustment
        ):
            return "environment_adjustment"

        if (
            supplied_risk.environment
            .strip()
            .upper()
            != expected.environment
            .strip()
            .upper()
        ):
            return "environment"

        if (
            supplied_risk.factors
            != expected.factors
        ):
            return "factors"

        return None

    def _decision(
        self,
        *,
        decision: str,
        role: str,
        environment: str,
        plan: OperationPlan,
        category: str,
        risk: RiskAssessmentResult,
        reason: PolicyReason,
        metadata: Dict[str, object],
    ) -> PolicyDecision:
        if decision not in self.decision_types:
            raise ValueError(
                "Policy attempted to produce "
                "unsupported decision: "
                f"{decision}"
            )

        return PolicyDecision(
            decision=decision,
            role=role,
            environment=environment,
            intent=plan.intent,
            action=plan.action,
            category=category,
            risk_score=risk.score,
            risk_level=risk.level.upper(),
            reasons=(reason,),
            metadata=metadata,
        )

    @staticmethod
    def _load_yaml_mapping(
        path: Path,
        label: str,
    ) -> Dict[str, object]:
        if not path.exists():
            raise FileNotFoundError(
                f"{label} not found: {path}"
            )

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ValueError(
                f"{label} must contain "
                "a YAML mapping."
            )

        return data

    def _load_decision_types(
        self,
    ) -> frozenset[str]:
        values = self.policy.get(
            "decision_types"
        )

        if not isinstance(values, list):
            raise ValueError(
                "Security policy must define "
                "decision_types as a list."
            )

        required = {
            "ALLOW",
            "REQUIRE_APPROVAL",
            "DENY",
            "CLARIFICATION_REQUIRED",
        }

        normalized = set()

        for value in values:
            if not isinstance(value, str):
                raise ValueError(
                    "Decision types must be "
                    "strings."
                )

            value = value.strip().upper()

            if not value:
                raise ValueError(
                    "Decision type cannot be "
                    "empty."
                )

            normalized.add(value)

        if normalized != required:
            raise ValueError(
                "decision_types must contain "
                "exactly ALLOW, "
                "REQUIRE_APPROVAL, DENY, and "
                "CLARIFICATION_REQUIRED."
            )

        return frozenset(normalized)

    def _load_principles(
        self,
    ) -> Dict[str, bool]:
        principles = self.policy.get(
            "principles"
        )

        if not isinstance(
            principles,
            dict,
        ):
            raise ValueError(
                "Security policy must define "
                "principles."
            )

        required = {
            "fail_closed": True,
            "least_privilege": True,
            "ai_can_authorize_execution": False,
            (
                "arbitrary_shell_execution_allowed"
            ): False,
            (
                "critical_operations_auto_execute"
            ): False,
        }

        normalized = {}

        for name, expected in required.items():
            actual = principles.get(name)

            if not isinstance(actual, bool):
                raise ValueError(
                    f"Policy principle {name} "
                    "must be boolean."
                )

            if actual is not expected:
                raise ValueError(
                    "Unsafe policy principle: "
                    f"{name}"
                )

            normalized[name] = actual

        return normalized

    def _load_roles(
        self,
    ) -> Dict[str, Dict[str, object]]:
        raw_roles = self.policy.get(
            "roles"
        )

        if not isinstance(raw_roles, dict):
            raise ValueError(
                "Security policy must define "
                "roles."
            )

        normalized = {}

        for role, config in raw_roles.items():
            if not isinstance(role, str):
                raise ValueError(
                    "Role names must be strings."
                )

            canonical_role = (
                role.strip().upper()
            )

            if not canonical_role:
                raise ValueError(
                    "Role name cannot be empty."
                )

            if canonical_role in normalized:
                raise ValueError(
                    "Duplicate role: "
                    f"{canonical_role}"
                )

            if not isinstance(config, dict):
                raise ValueError(
                    "Role configuration must "
                    "be a mapping."
                )

            categories = config.get(
                "allowed_categories"
            )

            state_allowed = config.get(
                "state_changing_allowed"
            )

            if not isinstance(
                categories,
                list,
            ):
                raise ValueError(
                    "allowed_categories for "
                    f"{role} must be a list."
                )

            normalized_categories = []

            for category in categories:
                if not isinstance(
                    category,
                    str,
                ):
                    raise ValueError(
                        "Role categories must "
                        "be strings."
                    )

                category = category.strip()

                if not category:
                    raise ValueError(
                        "Role category cannot "
                        "be empty."
                    )

                if (
                    category
                    in normalized_categories
                ):
                    raise ValueError(
                        "Duplicate category "
                        f"{category} for role "
                        f"{role}."
                    )

                normalized_categories.append(
                    category
                )

            if not isinstance(
                state_allowed,
                bool,
            ):
                raise ValueError(
                    "state_changing_allowed for "
                    f"{role} must be boolean."
                )

            normalized[
                canonical_role
            ] = {
                "allowed_categories":
                    tuple(
                        normalized_categories
                    ),
                "state_changing_allowed":
                    state_allowed,
            }

        if not normalized:
            raise ValueError(
                "At least one role must be "
                "configured."
            )

        return normalized

    def _load_risk_decisions(
        self,
    ) -> Dict[str, str]:
        raw = self.policy.get(
            "risk_decisions"
        )

        if not isinstance(raw, dict):
            raise ValueError(
                "Security policy must define "
                "risk_decisions."
            )

        required_levels = {
            "low",
            "medium",
            "high",
            "critical",
        }

        if set(raw) != required_levels:
            raise ValueError(
                "risk_decisions must define "
                "exactly low, medium, high, "
                "and critical."
            )

        normalized = {}

        for level in required_levels:
            config = raw[level]

            if not isinstance(config, dict):
                raise ValueError(
                    "Risk decision configuration "
                    f"for {level} must be a "
                    "mapping."
                )

            decision = config.get(
                "default_decision"
            )

            if not isinstance(
                decision,
                str,
            ):
                raise ValueError(
                    "Risk default decision for "
                    f"{level} must be a string."
                )

            decision = (
                decision.strip().upper()
            )

            if (
                decision
                not in self.decision_types
            ):
                raise ValueError(
                    "Unsupported risk decision "
                    f"for {level}: {decision}"
                )

            normalized[
                level.upper()
            ] = decision

        return normalized

    def _load_global_denials(
        self,
    ) -> Dict[str, Dict[str, str]]:
        raw = self.policy.get(
            "global_denials"
        )

        if not isinstance(raw, dict):
            raise ValueError(
                "Security policy must define "
                "global_denials."
            )

        required = {
            "arbitrary_shell",
            "unsupported_intent",
            "intent_command_mismatch",
            "invalid_entity",
            "unsupported_executable",
            "unsupported_shell_construct",
        }

        if not required.issubset(raw):
            missing = sorted(
                required - set(raw)
            )

            raise ValueError(
                "Missing global denials: "
                f"{missing}"
            )

        normalized = {}

        for name, config in raw.items():
            normalized[name] = (
                self._load_denial_rule(
                    config,
                    f"global_denials.{name}",
                )
            )

        return normalized

    def _load_hard_safety_boundaries(
        self,
    ) -> Dict[str, Dict[str, str]]:
        raw = self.policy.get(
            "hard_safety_boundaries"
        )

        if not isinstance(raw, dict):
            raise ValueError(
                "Security policy must define "
                "hard_safety_boundaries."
            )

        required = {
            "destructive_disk_operation",
            "arbitrary_remote_code_execution",
            "unrestricted_root_shell",
        }

        if not required.issubset(raw):
            missing = sorted(
                required - set(raw)
            )

            raise ValueError(
                "Missing hard safety "
                f"boundaries: {missing}"
            )

        normalized = {}

        for name, config in raw.items():
            normalized[name] = (
                self._load_denial_rule(
                    config,
                    (
                        "hard_safety_boundaries."
                        f"{name}"
                    ),
                )
            )

        return normalized

    def _load_denial_rule(
        self,
        config,
        name: str,
    ) -> Dict[str, str]:
        if not isinstance(config, dict):
            raise ValueError(
                f"{name} must be a mapping."
            )

        description = config.get(
            "description"
        )

        decision = config.get(
            "decision"
        )

        if not isinstance(
            description,
            str,
        ) or not description.strip():
            raise ValueError(
                f"{name}.description must "
                "be a non-empty string."
            )

        if not isinstance(
            decision,
            str,
        ):
            raise ValueError(
                f"{name}.decision must be "
                "a string."
            )

        decision = decision.strip().upper()

        if decision != "DENY":
            raise ValueError(
                f"{name} must use DENY."
            )

        if (
            decision
            not in self.decision_types
        ):
            raise ValueError(
                f"{name} uses an unsupported "
                "decision."
            )

        return {
            "description":
                description.strip(),
            "decision": decision,
        }

    def _load_intent_categories(
        self,
    ) -> Dict[str, str]:
        intents = self.catalog.get(
            "intents"
        )

        if not isinstance(intents, dict):
            raise ValueError(
                "Intent catalog must define "
                "intents."
            )

        normalized = {}

        for intent, config in (
            intents.items()
        ):
            if not isinstance(
                intent,
                str,
            ):
                raise ValueError(
                    "Intent names must be "
                    "strings."
                )

            if not isinstance(config, dict):
                raise ValueError(
                    "Intent configuration must "
                    "be a mapping."
                )

            category = config.get(
                "category"
            )

            if not isinstance(
                category,
                str,
            ) or not category.strip():
                raise ValueError(
                    "Intent category must be "
                    "a non-empty string."
                )

            normalized[
                intent
            ] = category.strip()

        if not normalized:
            raise ValueError(
                "Intent catalog cannot be "
                "empty."
            )

        return normalized

    def _load_environments(
        self,
    ) -> frozenset[str]:
        environments = self.policy.get(
            "environments"
        )

        if not isinstance(
            environments,
            list,
        ):
            raise ValueError(
                "Security policy must define "
                "environments as a list."
            )

        normalized = set()

        for environment in environments:
            if not isinstance(
                environment,
                str,
            ):
                raise ValueError(
                    "Environment names must "
                    "be strings."
                )

            environment = (
                environment.strip().upper()
            )

            if not environment:
                raise ValueError(
                    "Environment cannot be "
                    "empty."
                )

            if environment in normalized:
                raise ValueError(
                    "Duplicate environment: "
                    f"{environment}"
                )

            normalized.add(environment)

        if not normalized:
            raise ValueError(
                "At least one environment "
                "must be configured."
            )

        return frozenset(normalized)

    def _validate_role_categories(
        self,
    ) -> None:
        catalog_categories = set(
            self.intent_categories.values()
        )

        for role, config in (
            self.roles.items()
        ):
            for category in config[
                "allowed_categories"
            ]:
                if (
                    category
                    not in catalog_categories
                ):
                    raise ValueError(
                        "Role "
                        f"{role} references "
                        "unknown intent category: "
                        f"{category}"
                    )

                if category == "unsupported":
                    raise ValueError(
                        "The unsupported category "
                        "cannot be granted to "
                        f"role {role}."
                    )

    def _normalize_role(
        self,
        role: str,
    ) -> str:
        if not isinstance(role, str):
            raise TypeError(
                "role must be a string."
            )

        normalized = (
            role.strip().upper()
        )

        if not normalized:
            raise ValueError(
                "role cannot be empty."
            )

        if normalized not in self.roles:
            raise ValueError(
                "Unsupported role: "
                f"{role}"
            )

        return normalized

    def _resolve_environment(
        self,
        environment: Optional[str],
        risk: RiskAssessmentResult,
    ) -> str:
        if environment is None:
            environment = risk.environment

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

    @staticmethod
    def _validate_risk_environment(
        risk: RiskAssessmentResult,
        environment: str,
    ) -> None:
        risk_environment = (
            risk.environment.strip().upper()
        )

        if (
            risk_environment
            != environment
        ):
            raise ValueError(
                "Risk assessment environment "
                "does not match policy "
                "evaluation environment."
            )

    def _category_for_intent(
        self,
        intent: str,
    ) -> str:
        if not isinstance(intent, str):
            raise TypeError(
                "Plan intent must be a string."
            )

        if (
            intent
            not in self.intent_categories
        ):
            raise ValueError(
                "Unknown plan intent: "
                f"{intent}"
            )

        return self.intent_categories[
            intent
        ]

    def _matched_hard_boundary(
        self,
        plan: OperationPlan,
    ) -> Optional[str]:
        return self.HARD_BOUNDARY_OPERATIONS.get(
            (
                plan.intent,
                plan.action,
            )
        )

    def _decision_for_risk(
        self,
        level: str,
    ) -> str:
        if not isinstance(level, str):
            raise TypeError(
                "Risk level must be a string."
            )

        normalized = (
            level.strip().upper()
        )

        if (
            normalized
            not in self.risk_decisions
        ):
            raise ValueError(
                "Unsupported risk level: "
                f"{level}"
            )

        return self.risk_decisions[
            normalized
        ]

    def _validate_hard_boundary_mappings(
        self,
    ) -> None:
        for (
            intent,
            action,
        ), boundary in (
            self.HARD_BOUNDARY_OPERATIONS.items()
        ):
            if (
                boundary
                not in self.hard_safety_boundaries
            ):
                raise ValueError(
                    "Hard-boundary mapping "
                    "references unknown boundary: "
                    f"{boundary}"
                )

            intents = self.catalog[
                "intents"
            ]

            if intent not in intents:
                raise ValueError(
                    "Hard-boundary mapping "
                    "references unknown intent: "
                    f"{intent}"
                )

            actions = intents[
                intent
            ].get(
                "actions"
            )

            if (
                not isinstance(actions, list)
                or action not in actions
            ):
                raise ValueError(
                    "Hard-boundary mapping "
                    "references unsupported "
                    "intent/action pair: "
                    f"{intent}/{action}"
                )