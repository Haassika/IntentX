from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional


@dataclass(frozen=True)
class LifecycleRecord:
    """
    Immutable persisted representation of an IntentX
    request lifecycle checkpoint.

    This record describes what happened during request
    processing. It does not grant authorization and
    must never be treated as execution authority.
    """

    request_id: str
    correlation_id: str
    execution_id: Optional[str]

    request_text: str
    role: str
    environment: str

    stage: str
    status: str

    predicted_intent: Optional[str]
    confidence: Optional[float]

    reason: str

    created_at: str
    updated_at: str

    def __post_init__(self):
        required_strings = (
            ("request_id", self.request_id),
            (
                "correlation_id",
                self.correlation_id,
            ),
            (
                "request_text",
                self.request_text,
            ),
            ("role", self.role),
            (
                "environment",
                self.environment,
            ),
            ("stage", self.stage),
            ("status", self.status),
            ("reason", self.reason),
            ("created_at", self.created_at),
            ("updated_at", self.updated_at),
        )

        cleaned = {}

        for field_name, value in required_strings:
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string."
                )

            value = value.strip()

            if not value:
                raise ValueError(
                    f"{field_name} cannot be empty."
                )

            cleaned[field_name] = value

        execution_id = self.execution_id

        if execution_id is not None:
            if not isinstance(
                execution_id,
                str,
            ):
                raise TypeError(
                    "execution_id must be a string "
                    "or None."
                )

            execution_id = execution_id.strip()

            if not execution_id:
                raise ValueError(
                    "execution_id cannot be empty "
                    "when provided."
                )

        predicted_intent = (
            self.predicted_intent
        )

        if predicted_intent is not None:
            if not isinstance(
                predicted_intent,
                str,
            ):
                raise TypeError(
                    "predicted_intent must be a "
                    "string or None."
                )

            predicted_intent = (
                predicted_intent.strip()
            )

            if not predicted_intent:
                raise ValueError(
                    "predicted_intent cannot be "
                    "empty when provided."
                )

        confidence = self.confidence

        if confidence is not None:
            if (
                isinstance(confidence, bool)
                or not isinstance(
                    confidence,
                    (int, float),
                )
            ):
                raise TypeError(
                    "confidence must be numeric "
                    "or None."
                )

            confidence = float(confidence)

            if not 0.0 <= confidence <= 1.0:
                raise ValueError(
                    "confidence must be between "
                    "0.0 and 1.0."
                )

        self._validate_timestamp(
            cleaned["created_at"],
            "created_at",
        )
        self._validate_timestamp(
            cleaned["updated_at"],
            "updated_at",
        )

        object.__setattr__(
            self,
            "request_id",
            cleaned["request_id"],
        )
        object.__setattr__(
            self,
            "correlation_id",
            cleaned["correlation_id"],
        )
        object.__setattr__(
            self,
            "execution_id",
            execution_id,
        )
        object.__setattr__(
            self,
            "request_text",
            cleaned["request_text"],
        )
        object.__setattr__(
            self,
            "role",
            cleaned["role"].upper(),
        )
        object.__setattr__(
            self,
            "environment",
            cleaned["environment"].upper(),
        )
        object.__setattr__(
            self,
            "stage",
            cleaned["stage"].upper(),
        )
        object.__setattr__(
            self,
            "status",
            cleaned["status"].upper(),
        )
        object.__setattr__(
            self,
            "predicted_intent",
            predicted_intent,
        )
        object.__setattr__(
            self,
            "confidence",
            confidence,
        )
        object.__setattr__(
            self,
            "reason",
            cleaned["reason"],
        )
        object.__setattr__(
            self,
            "created_at",
            cleaned["created_at"],
        )
        object.__setattr__(
            self,
            "updated_at",
            cleaned["updated_at"],
        )

    @staticmethod
    def _validate_timestamp(
        value: str,
        field_name: str,
    ) -> None:
        try:
            parsed = datetime.fromisoformat(
                value
            )
        except ValueError as exc:
            raise ValueError(
                f"{field_name} must be a valid "
                "ISO-8601 timestamp."
            ) from exc

        if parsed.tzinfo is None:
            raise ValueError(
                f"{field_name} must include "
                "timezone information."
            )

    def to_dict(self) -> Dict[str, object]:
        return {
            "request_id": self.request_id,
            "correlation_id":
                self.correlation_id,
            "execution_id": self.execution_id,
            "request_text": self.request_text,
            "role": self.role,
            "environment": self.environment,
            "stage": self.stage,
            "status": self.status,
            "predicted_intent":
                self.predicted_intent,
            "confidence": self.confidence,
            "reason": self.reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
