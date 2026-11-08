from dataclasses import asdict, dataclass
from typing import List, Optional

from intentx.planning.models import OperationPlan


@dataclass(frozen=True)
class ValidationIssue:
    """
    Represents one validation failure.

    code:
        Stable machine-readable identifier.

    message:
        Human-readable explanation.

    field:
        Optional entity or operation field related
        to the validation failure.
    """

    code: str
    message: str
    field: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class OperationValidationResult:
    """
    Result returned by the operation validation layer.

    valid=True means the proposed OperationPlan passed
    deterministic validation.

    Validation does NOT authorize execution.
    """

    valid: bool
    decision: str
    issues: List[ValidationIssue]
    plan: Optional[OperationPlan]

    def to_dict(self):
        return asdict(self)