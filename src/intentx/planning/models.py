from dataclasses import dataclass
from types import MappingProxyType
from typing import (
    Dict,
    List,
    Mapping,
    Tuple,
    Union,
)


PrivilegeRequirement = Union[
    bool,
    str,
]


@dataclass(frozen=True)
class OperationPlan:
    """
    Immutable structured representation of a
    proposed operating-system operation.

    The constructor may receive ordinary mutable
    lists and dictionaries from the planner.

    During construction they are defensively copied
    into immutable representations so that a plan
    cannot be changed after creation.

    This is important because the same structured
    operation may later cross validation, risk,
    policy, and execution trust boundaries.

    This object represents a proposed operation
    only. It does NOT authorize execution.
    """

    intent: str
    action: str
    executable: str
    arguments: Tuple[str, ...]
    entities: Mapping[str, str]
    state_changing: bool
    privilege_required: PrivilegeRequirement
    critical_operation: bool

    def __post_init__(self):
        """
        Defensively copy mutable constructor inputs
        into immutable internal representations.

        frozen=True prevents attribute reassignment.

        Tuple arguments prevent element mutation.

        MappingProxyType prevents entity mutation.

        The defensive copies also ensure that later
        mutation of the original list or dictionary
        supplied by a caller cannot mutate this plan.
        """

        immutable_arguments = tuple(
            self.arguments
        )

        immutable_entities = (
            MappingProxyType(
                dict(self.entities)
            )
        )

        object.__setattr__(
            self,
            "arguments",
            immutable_arguments,
        )

        object.__setattr__(
            self,
            "entities",
            immutable_entities,
        )

    def to_dict(self) -> Dict[str, object]:
        """
        Return a normal serialization-friendly
        dictionary.

        Mutable list/dict copies are intentionally
        returned here. Mutating the returned value
        cannot mutate the OperationPlan itself.
        """

        return {
            "intent": self.intent,
            "action": self.action,
            "executable": self.executable,
            "arguments": list(
                self.arguments
            ),
            "entities": dict(
                self.entities
            ),
            "state_changing": (
                self.state_changing
            ),
            "privilege_required": (
                self.privilege_required
            ),
            "critical_operation": (
                self.critical_operation
            ),
        }

    @property
    def argv(self) -> List[str]:
        """
        Return a fresh structured argv list.

        No shell command string is constructed.

        A fresh list is deliberately returned so
        callers may pass it to an execution API
        without gaining a mutable reference to the
        validated plan's internal arguments.
        """

        return [
            self.executable,
            *self.arguments,
        ]