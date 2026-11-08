from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Mapping, Optional, Tuple


VALID_EXECUTION_STATUSES = frozenset(
    {
        "EXECUTED",
        "BLOCKED",
        "FAILED",
        "TIMED_OUT",
    }
)


@dataclass(frozen=True)
class ExecutionRequest:
    """
    Immutable request presented to the execution
    boundary.

    This object does not itself authorize execution.
    Authorization must be independently verified by
    the execution broker.
    """

    execution_id: str
    role: str
    environment: str
    intent: str
    action: str
    executable: str
    arguments: Tuple[str, ...]

    def __post_init__(self):
        for field_name, value in (
            ("execution_id", self.execution_id),
            ("role", self.role),
            ("environment", self.environment),
            ("intent", self.intent),
            ("action", self.action),
            ("executable", self.executable),
        ):
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string."
                )

            if not value.strip():
                raise ValueError(
                    f"{field_name} cannot be empty."
                )

        immutable_arguments = tuple(
            self.arguments
        )

        for argument in immutable_arguments:
            if not isinstance(argument, str):
                raise TypeError(
                    "All execution arguments "
                    "must be strings."
                )

        object.__setattr__(
            self,
            "arguments",
            immutable_arguments,
        )

    @property
    def argv(self) -> list[str]:
        """
        Return a fresh argv list.

        Callers cannot mutate the canonical request
        by modifying the returned list.
        """

        return [
            self.executable,
            *self.arguments,
        ]

    def to_dict(self) -> Dict[str, object]:
        return {
            "execution_id":
                self.execution_id,
            "role":
                self.role,
            "environment":
                self.environment,
            "intent":
                self.intent,
            "action":
                self.action,
            "executable":
                self.executable,
            "arguments":
                list(self.arguments),
            "argv":
                self.argv,
        }


@dataclass(frozen=True)
class ExecutionResult:
    """
    Immutable result produced by the execution
    boundary.

    BLOCKED means IntentX intentionally prevented
    execution before an operating-system process
    was launched.

    EXECUTED means a process was launched and
    completed within the execution boundary.

    FAILED means execution was attempted but the
    process could not complete normally.

    TIMED_OUT means execution exceeded the
    configured execution timeout.
    """

    execution_id: str
    status: str
    executable: str
    arguments: Tuple[str, ...]
    return_code: Optional[int]
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    reason_code: str
    reason: str
    metadata: Mapping[str, object]

    def __post_init__(self):
        for field_name, value in (
            ("execution_id", self.execution_id),
            ("status", self.status),
            ("executable", self.executable),
            ("stdout", self.stdout),
            ("stderr", self.stderr),
            ("reason_code", self.reason_code),
            ("reason", self.reason),
        ):
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string."
                )

        if not self.execution_id.strip():
            raise ValueError(
                "execution_id cannot be empty."
            )

        normalized_status = (
            self.status.strip().upper()
        )

        if (
            normalized_status
            not in VALID_EXECUTION_STATUSES
        ):
            raise ValueError(
                "Unsupported execution status: "
                f"{self.status}"
            )

        if not self.executable.strip():
            raise ValueError(
                "executable cannot be empty."
            )

        if not self.reason_code.strip():
            raise ValueError(
                "reason_code cannot be empty."
            )

        if not self.reason.strip():
            raise ValueError(
                "reason cannot be empty."
            )

        if (
            self.return_code is not None
            and (
                isinstance(
                    self.return_code,
                    bool,
                )
                or not isinstance(
                    self.return_code,
                    int,
                )
            )
        ):
            raise TypeError(
                "return_code must be an integer "
                "or None."
            )

        if not isinstance(
            self.stdout_truncated,
            bool,
        ):
            raise TypeError(
                "stdout_truncated must be "
                "boolean."
            )

        if not isinstance(
            self.stderr_truncated,
            bool,
        ):
            raise TypeError(
                "stderr_truncated must be "
                "boolean."
            )

        immutable_arguments = tuple(
            self.arguments
        )

        for argument in immutable_arguments:
            if not isinstance(argument, str):
                raise TypeError(
                    "All execution arguments "
                    "must be strings."
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
            "status",
            normalized_status,
        )

        object.__setattr__(
            self,
            "arguments",
            immutable_arguments,
        )

        object.__setattr__(
            self,
            "metadata",
            immutable_metadata,
        )

    @property
    def argv(self) -> list[str]:
        return [
            self.executable,
            *self.arguments,
        ]

    @property
    def process_started(self) -> bool:
        """
        Whether the result represents an operation
        that crossed the OS process boundary.

        BLOCKED is the only status guaranteed not to
        have launched a process.
        """

        return self.status != "BLOCKED"

    @property
    def successful(self) -> bool:
        return (
            self.status == "EXECUTED"
            and self.return_code == 0
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "execution_id":
                self.execution_id,
            "status":
                self.status,
            "executable":
                self.executable,
            "arguments":
                list(self.arguments),
            "argv":
                self.argv,
            "return_code":
                self.return_code,
            "stdout":
                self.stdout,
            "stderr":
                self.stderr,
            "stdout_truncated":
                self.stdout_truncated,
            "stderr_truncated":
                self.stderr_truncated,
            "reason_code":
                self.reason_code,
            "reason":
                self.reason,
            "metadata":
                dict(self.metadata),
            "process_started":
                self.process_started,
            "successful":
                self.successful,
        }