from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional

from intentx.persistence.models import (
    LifecycleRecord,
)


class SQLiteLifecycleRepository:
    """
    SQLite persistence for IntentX lifecycle records.

    The repository is deliberately passive.

    It stores and retrieves lifecycle state only.
    It contains no authorization, policy, planning,
    command construction, or process execution logic.
    """

    def __init__(
        self,
        database_path,
    ):
        self.database_path = Path(
            database_path
        )

        if self.database_path.exists():
            if not self.database_path.is_file():
                raise ValueError(
                    "database_path must reference "
                    "a file."
                )
        else:
            self.database_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._initialize_schema()

    def _connect(self):
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=5.0,
        )

        connection.row_factory = sqlite3.Row

        return connection

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                lifecycle_records (
                    request_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    execution_id TEXT,
                    request_text TEXT NOT NULL,
                    role TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    status TEXT NOT NULL,
                    predicted_intent TEXT,
                    confidence REAL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_lifecycle_correlation
                ON lifecycle_records (
                    correlation_id,
                    created_at,
                    request_id
                )
                """
            )

    def save(
        self,
        record: LifecycleRecord,
    ) -> None:
        if not isinstance(
            record,
            LifecycleRecord,
        ):
            raise TypeError(
                "record must be a "
                "LifecycleRecord."
            )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO lifecycle_records (
                    request_id,
                    correlation_id,
                    execution_id,
                    request_text,
                    role,
                    environment,
                    stage,
                    status,
                    predicted_intent,
                    confidence,
                    reason,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(request_id)
                DO UPDATE SET
                    correlation_id =
                        excluded.correlation_id,
                    execution_id =
                        excluded.execution_id,
                    request_text =
                        excluded.request_text,
                    role =
                        excluded.role,
                    environment =
                        excluded.environment,
                    stage =
                        excluded.stage,
                    status =
                        excluded.status,
                    predicted_intent =
                        excluded.predicted_intent,
                    confidence =
                        excluded.confidence,
                    reason =
                        excluded.reason,
                    created_at =
                        excluded.created_at,
                    updated_at =
                        excluded.updated_at
                """,
                (
                    record.request_id,
                    record.correlation_id,
                    record.execution_id,
                    record.request_text,
                    record.role,
                    record.environment,
                    record.stage,
                    record.status,
                    record.predicted_intent,
                    record.confidence,
                    record.reason,
                    record.created_at,
                    record.updated_at,
                ),
            )

    def get(
        self,
        request_id: str,
    ) -> Optional[LifecycleRecord]:
        request_id = self._clean_identifier(
            request_id,
            "request_id",
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    request_id,
                    correlation_id,
                    execution_id,
                    request_text,
                    role,
                    environment,
                    stage,
                    status,
                    predicted_intent,
                    confidence,
                    reason,
                    created_at,
                    updated_at
                FROM lifecycle_records
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_record(row)

    def list_by_correlation_id(
        self,
        correlation_id: str,
    ) -> List[LifecycleRecord]:
        correlation_id = (
            self._clean_identifier(
                correlation_id,
                "correlation_id",
            )
        )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    request_id,
                    correlation_id,
                    execution_id,
                    request_text,
                    role,
                    environment,
                    stage,
                    status,
                    predicted_intent,
                    confidence,
                    reason,
                    created_at,
                    updated_at
                FROM lifecycle_records
                WHERE correlation_id = ?
                ORDER BY
                    created_at ASC,
                    request_id ASC
                """,
                (correlation_id,),
            ).fetchall()

        return [
            self._row_to_record(row)
            for row in rows
        ]

    @staticmethod
    def _clean_identifier(
        value: str,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string."
            )

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                f"{field_name} cannot be empty."
            )

        return cleaned

    @staticmethod
    def _row_to_record(
        row: sqlite3.Row,
    ) -> LifecycleRecord:
        return LifecycleRecord(
            request_id=row["request_id"],
            correlation_id=(
                row["correlation_id"]
            ),
            execution_id=row["execution_id"],
            request_text=row["request_text"],
            role=row["role"],
            environment=row["environment"],
            stage=row["stage"],
            status=row["status"],
            predicted_intent=(
                row["predicted_intent"]
            ),
            confidence=row["confidence"],
            reason=row["reason"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
