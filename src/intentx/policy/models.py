from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Mapping, Tuple


@dataclass(frozen=True)
class PolicyReason:
    """
    One deterministic reason contributing to a
    policy authorization decision.

    Reasons are structured so that authorization
    outcomes remain explainable and auditable.
    """

    code: str
    message: str

    def __post_init__(self):
        if not isinstance(self.code, str):
            raise TypeError(
                "Policy reason code must be a string."
            )

        if not self.code.strip():
            raise ValueError(
                "Policy reason code cannot be empty."
            )

        if not isinstance(self.message, str):
            raise TypeError(
                "Policy reason message must be a string."
            )

        if not self.message.strip():
            raise ValueError(
                "Policy reason message cannot be empty."
            )

    def to_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class PolicyDecision:
    """
    Immutable authorization result produced by the
    deterministic policy engine.

    Unlike planning, validation, and risk assessment,
    this object represents an actual authorization
    decision.

    It still does not execute an operation.
    """

    decision: str
    role: str
    environment: str
    intent: str
    action: str
    category: str
    risk_score: int
    risk_level: str
    reasons: Tuple[PolicyReason, ...]
    metadata: Mapping[str, object]

    def __post_init__(self):
        valid_decisions = {
            "ALLOW",
            "REQUIRE_APPROVAL",
            "DENY",
            "CLARIFICATION_REQUIRED",
        }

        if not isinstance(self.decision, str):
            raise TypeError(
                "Policy decision must be a string."
            )

        if self.decision not in valid_decisions:
            raise ValueError(
                "Unsupported policy decision: "
                f"{self.decision}"
            )

        for field_name, value in (
            ("role", self.role),
            ("environment", self.environment),
            ("intent", self.intent),
            ("action", self.action),
            ("category", self.category),
            ("risk_level", self.risk_level),
        ):
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string."
                )

            if not value.strip():
                raise ValueError(
                    f"{field_name} cannot be empty."
                )

        if (
            isinstance(self.risk_score, bool)
            or not isinstance(self.risk_score, int)
        ):
            raise TypeError(
                "risk_score must be an integer."
            )

        if not 0 <= self.risk_score <= 100:
            raise ValueError(
                "risk_score must be between 0 and 100."
            )

        immutable_reasons = tuple(
            self.reasons
        )

        for reason in immutable_reasons:
            if not isinstance(
                reason,
                PolicyReason,
            ):
                raise TypeError(
                    "All reasons must be "
                    "PolicyReason objects."
                )

        if not immutable_reasons:
            raise ValueError(
                "Policy decision must contain "
                "at least one reason."
            )

        if not isinstance(
            self.metadata,
            Mapping,
        ):
            raise TypeError(
                "metadata must be a mapping."
            )

        immutable_metadata = (
            MappingProxyType(
                dict(self.metadata)
            )
        )

        object.__setattr__(
            self,
            "reasons",
            immutable_reasons,
        )

        object.__setattr__(
            self,
            "metadata",
            immutable_metadata,
        )

    @property
    def reason_codes(self) -> list[str]:
        """
        Return a fresh list so callers cannot mutate
        the canonical policy result.
        """

        return [
            reason.code
            for reason in self.reasons
        ]

    def to_dict(self) -> Dict[str, object]:
        """
        Return serialization-friendly defensive
        copies of the immutable policy result.
        """

        return {
            "decision": self.decision,
            "role": self.role,
            "environment": self.environment,
            "intent": self.intent,
            "action": self.action,
            "category": self.category,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "reasons": [
                reason.to_dict()
                for reason in self.reasons
            ],
            "metadata": dict(
                self.metadata
            ),
        }