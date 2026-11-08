from dataclasses import asdict, dataclass
from typing import Dict, List


@dataclass(frozen=True)
class RiskFactor:
    """
    One deterministic factor contributing to an
    operation's calculated risk score.

    Risk factors describe risk only. They do not
    authorize or deny execution.
    """

    code: str
    description: str
    score: int

    def __post_init__(self):
        if not isinstance(self.code, str):
            raise TypeError("Risk factor code must be a string.")

        if not self.code.strip():
            raise ValueError("Risk factor code cannot be empty.")

        if not isinstance(self.description, str):
            raise TypeError(
                "Risk factor description must be a string."
            )

        if not self.description.strip():
            raise ValueError(
                "Risk factor description cannot be empty."
            )

        if not isinstance(self.score, int):
            raise TypeError(
                "Risk factor score must be an integer."
            )

        if self.score < 0:
            raise ValueError(
                "Risk factor score cannot be negative."
            )

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RiskAssessmentResult:
    """
    Immutable result produced by the deterministic
    risk assessment engine.

    This object intentionally contains no ALLOW,
    DENY, or REQUIRE_APPROVAL decision. Authorization
    belongs to the policy layer.
    """

    score: int
    level: str
    base_score: int
    environment_adjustment: int
    environment: str
    factors: tuple[RiskFactor, ...]

    def __post_init__(self):
        if not isinstance(self.score, int):
            raise TypeError(
                "Risk score must be an integer."
            )

        if not 0 <= self.score <= 100:
            raise ValueError(
                "Risk score must be between 0 and 100."
            )

        if not isinstance(self.base_score, int):
            raise TypeError(
                "Base risk score must be an integer."
            )

        if self.base_score < 0:
            raise ValueError(
                "Base risk score cannot be negative."
            )

        if not isinstance(
            self.environment_adjustment,
            int,
        ):
            raise TypeError(
                "Environment adjustment must be an integer."
            )

        if not isinstance(self.level, str):
            raise TypeError(
                "Risk level must be a string."
            )

        if not self.level.strip():
            raise ValueError(
                "Risk level cannot be empty."
            )

        if not isinstance(self.environment, str):
            raise TypeError(
                "Environment must be a string."
            )

        if not self.environment.strip():
            raise ValueError(
                "Environment cannot be empty."
            )

        immutable_factors = tuple(self.factors)

        for factor in immutable_factors:
            if not isinstance(factor, RiskFactor):
                raise TypeError(
                    "All risk factors must be RiskFactor objects."
                )

        object.__setattr__(
            self,
            "factors",
            immutable_factors,
        )

    def to_dict(self) -> Dict[str, object]:
        """
        Return serialization-friendly defensive
        copies of the immutable assessment.
        """

        return {
            "score": self.score,
            "level": self.level,
            "base_score": self.base_score,
            "environment_adjustment": (
                self.environment_adjustment
            ),
            "environment": self.environment,
            "factors": [
                factor.to_dict()
                for factor in self.factors
            ],
        }

    @property
    def factor_codes(self) -> List[str]:
        """
        Return a fresh list so callers cannot mutate
        the canonical assessment.
        """

        return [
            factor.code
            for factor in self.factors
        ]