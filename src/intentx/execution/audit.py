from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Dict, Mapping, Optional, Tuple


VALID_AUDIT_EVENT_TYPES = frozenset(
    {
        "EXECUTION_BLOCKED",
        "EXECUTION_ATTEMPTED",
        "EXECUTION_COMPLETED",
        "EXECUTION_FAILED",
        "EXECUTION_TIMED_OUT",
    }
)


@dataclass(frozen=True)
class ExecutionAuditRecord:
    """
    Immutable audit record for the execution stage.

    correlation_id:
        Links this event to the complete IntentX request
        lifecycle.

    execution_id:
        Identifies one specific execution attempt.

    This model intentionally records structured argv rather
    than a shell command string.

    Sensitive environment variables and unrelated process
    state must not be placed in metadata.
    """

    timestamp: str
    correlation_id: str
    execution_id: str
    event_type: str

    role: str
    environment: str

    intent: str
    action: str
    executable: str
    arguments: Tuple[str, ...]

    policy_decision: str
    execution_status: str

    return_code: Optional[int]

    stdout_truncated: bool
    stderr_truncated: bool

    duration_ms: Optional[int]

    reason_code: str
    reason: str

    metadata: Mapping[str, object]

    def __post_init__(self):
        required_strings = (
            ("timestamp", self.timestamp),
            (
                "correlation_id",
                self.correlation_id,
            ),
            (
                "execution_id",
                self.execution_id,
            ),
            (
                "event_type",
                self.event_type,
            ),
            ("role", self.role),
            (
                "environment",
                self.environment,
            ),
            ("intent", self.intent),
            ("action", self.action),
            (
                "executable",
                self.executable,
            ),
            (
                "policy_decision",
                self.policy_decision,
            ),
            (
                "execution_status",
                self.execution_status,
            ),
            (
                "reason_code",
                self.reason_code,
            ),
            ("reason", self.reason),
        )

        for field_name, value in required_strings:
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be "
                    "a string."
                )

            if not value.strip():
                raise ValueError(
                    f"{field_name} cannot "
                    "be empty."
                )

        normalized_event_type = (
            self.event_type.strip().upper()
        )

        if (
            normalized_event_type
            not in VALID_AUDIT_EVENT_TYPES
        ):
            raise ValueError(
                "Unsupported audit event type: "
                f"{self.event_type}"
            )

        normalized_policy_decision = (
            self.policy_decision.strip().upper()
        )

        normalized_execution_status = (
            self.execution_status.strip().upper()
        )

        self._validate_timestamp(
            self.timestamp
        )

        immutable_arguments = tuple(
            self.arguments
        )

        for argument in immutable_arguments:
            if not isinstance(argument, str):
                raise TypeError(
                    "All audit arguments "
                    "must be strings."
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
                "return_code must be an "
                "integer or None."
            )

        for field_name, value in (
            (
                "stdout_truncated",
                self.stdout_truncated,
            ),
            (
                "stderr_truncated",
                self.stderr_truncated,
            ),
        ):
            if not isinstance(value, bool):
                raise TypeError(
                    f"{field_name} must be "
                    "boolean."
                )

        if self.duration_ms is not None:
            if (
                isinstance(
                    self.duration_ms,
                    bool,
                )
                or not isinstance(
                    self.duration_ms,
                    int,
                )
            ):
                raise TypeError(
                    "duration_ms must be an "
                    "integer or None."
                )

            if self.duration_ms < 0:
                raise ValueError(
                    "duration_ms cannot be "
                    "negative."
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
            "event_type",
            normalized_event_type,
        )

        object.__setattr__(
            self,
            "policy_decision",
            normalized_policy_decision,
        )

        object.__setattr__(
            self,
            "execution_status",
            normalized_execution_status,
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

    @staticmethod
    def _validate_timestamp(
        timestamp: str,
    ) -> None:
        """
        Require an ISO-8601 timestamp containing timezone
        information.

        Audit records must not rely on ambiguous local time.
        """

        try:
            parsed = datetime.fromisoformat(
                timestamp.replace(
                    "Z",
                    "+00:00",
                )
            )
        except ValueError as exc:
            raise ValueError(
                "timestamp must be a valid "
                "ISO-8601 timestamp."
            ) from exc

        if parsed.tzinfo is None:
            raise ValueError(
                "timestamp must include "
                "timezone information."
            )

    @property
    def argv(self) -> list[str]:
        """
        Return a defensive argv copy.
        """

        return [
            self.executable,
            *self.arguments,
        ]

    def to_dict(self) -> Dict[str, object]:
        return {
            "timestamp":
                self.timestamp,
            "correlation_id":
                self.correlation_id,
            "execution_id":
                self.execution_id,
            "event_type":
                self.event_type,
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
            "policy_decision":
                self.policy_decision,
            "execution_status":
                self.execution_status,
            "return_code":
                self.return_code,
            "stdout_truncated":
                self.stdout_truncated,
            "stderr_truncated":
                self.stderr_truncated,
            "duration_ms":
                self.duration_ms,
            "reason_code":
                self.reason_code,
            "reason":
                self.reason,
            "metadata":
                dict(self.metadata),
        }


def utc_timestamp() -> str:
    """
    Return an unambiguous UTC ISO-8601 timestamp.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


class JsonlAuditWriter:
    """
    Append-only JSON Lines audit writer.

    Each call writes exactly one JSON object followed by a
    newline.

    This writer deliberately performs file I/O only. It has
    no command-execution capability.
    """

    def __init__(
        self,
        path: Path | str,
    ):
        self.path = Path(path)

        if self.path.exists():
            if not self.path.is_file():
                raise ValueError(
                    "Audit path must reference "
                    "a file."
                )

    def write(
        self,
        record: ExecutionAuditRecord,
    ) -> None:
        if not isinstance(
            record,
            ExecutionAuditRecord,
        ):
            raise TypeError(
                "record must be an "
                "ExecutionAuditRecord."
            )

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        serialized = json.dumps(
            record.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(serialized)
            handle.write("\n")