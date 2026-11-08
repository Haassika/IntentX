"""SQLite persistence for normalized IntentX security telemetry."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable

from intentx.telemetry.events import (
    AuthenticationContext,
    CollectionStatus,
    EvidenceProvenance,
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
)


class SecurityEventRepository:
    """
    Persistent storage for normalized security events.

    This repository is observational only. It has no detection,
    authorization, mitigation, or command-execution authority.
    """

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)

    def initialize(self) -> None:
        self._database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    observed_at TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    collection_status TEXT NOT NULL,
                    process_json TEXT,
                    network_json TEXT,
                    authentication_json TEXT,
                    attributes_json TEXT NOT NULL,
                    evidence_json TEXT
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_security_events_observed_at
                ON security_events(observed_at)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_security_events_source_type
                ON security_events(source, event_type)
                """
            )

    def save(self, event: SecurityEvent) -> None:
        self.save_many((event,))

    def save_many(
        self,
        events: Iterable[SecurityEvent],
    ) -> int:
        rows = [self._event_to_row(event) for event in events]

        if not rows:
            return 0

        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO security_events (
                    event_id,
                    observed_at,
                    hostname,
                    source,
                    event_type,
                    collection_status,
                    process_json,
                    network_json,
                    authentication_json,
                    attributes_json,
                    evidence_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

        return len(rows)

    def get_recent(
        self,
        *,
        limit: int = 100,
    ) -> tuple[SecurityEvent, ...]:
        if limit < 1 or limit > 10_000:
            raise ValueError(
                "limit must be between 1 and 10000."
            )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    event_id,
                    observed_at,
                    hostname,
                    source,
                    event_type,
                    collection_status,
                    process_json,
                    network_json,
                    authentication_json,
                    attributes_json,
                    evidence_json
                FROM security_events
                ORDER BY observed_at DESC, rowid DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return tuple(
            self._row_to_event(row)
            for row in rows
        )

    def get_window(
        self,
        *,
        hostname: str,
        start_time: datetime,
        end_time: datetime,
        max_events: int = 10_000,
    ) -> tuple[SecurityEvent, ...]:
        """
        Return one host's events in [start_time, end_time).

        The safety bound is explicit: if the window contains more than
        max_events, retrieval fails rather than silently truncating behavioral
        evidence that may later be consumed by anomaly detection.
        """

        if not hostname.strip():
            raise ValueError(
                "hostname must not be empty."
            )

        if start_time.tzinfo is None:
            raise ValueError(
                "start_time must be timezone-aware."
            )

        if end_time.tzinfo is None:
            raise ValueError(
                "end_time must be timezone-aware."
            )

        if end_time <= start_time:
            raise ValueError(
                "end_time must be greater than start_time."
            )

        if max_events < 1 or max_events > 100_000:
            raise ValueError(
                "max_events must be between 1 and 100000."
            )

        start_value = start_time.isoformat()
        end_value = end_time.isoformat()

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    event_id,
                    observed_at,
                    hostname,
                    source,
                    event_type,
                    collection_status,
                    process_json,
                    network_json,
                    authentication_json,
                    attributes_json,
                    evidence_json
                FROM security_events
                WHERE hostname = ?
                  AND observed_at >= ?
                  AND observed_at < ?
                ORDER BY observed_at ASC, rowid ASC
                LIMIT ?
                """,
                (
                    hostname,
                    start_value,
                    end_value,
                    max_events + 1,
                ),
            ).fetchall()

        if len(rows) > max_events:
            raise RuntimeError(
                "security event window exceeds max_events; "
                "refusing to silently truncate behavioral evidence."
            )

        return tuple(
            self._row_to_event(row)
            for row in rows
        )

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()

        if row is None:
            return 0

        return int(row[0])

    def enforce_retention(
        self,
        *,
        max_events: int,
    ) -> int:
        if max_events < 1:
            raise ValueError(
                "max_events must be greater than zero."
            )

        with self._connect() as connection:
            before = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events"
                ).fetchone()[0]
            )

            connection.execute(
                """
                DELETE FROM security_events
                WHERE rowid NOT IN (
                    SELECT rowid
                    FROM security_events
                    ORDER BY observed_at DESC, rowid DESC
                    LIMIT ?
                )
                """,
                (max_events,),
            )

            after = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events"
                ).fetchone()[0]
            )

        return before - after

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(
            self._database_path,
            timeout=5.0,
        )

    @staticmethod
    def _event_to_row(
        event: SecurityEvent,
    ) -> tuple[object, ...]:
        return (
            event.event_id,
            event.observed_at.isoformat(),
            event.hostname,
            event.source.value,
            event.event_type.value,
            event.collection_status.value,
            SecurityEventRepository._context_json(
                event.process
            ),
            SecurityEventRepository._context_json(
                event.network
            ),
            SecurityEventRepository._context_json(
                event.authentication
            ),
            json.dumps(
                dict(event.attributes),
                sort_keys=True,
                separators=(",", ":"),
            ),
            SecurityEventRepository._context_json(
                event.evidence
            ),
        )

    @staticmethod
    def _context_json(context: object | None) -> str | None:
        if context is None:
            return None

        fields = getattr(context, "__dataclass_fields__", None)

        if fields is None:
            raise TypeError(
                "Telemetry context must be a dataclass."
            )

        payload = {
            name: getattr(context, name)
            for name in fields
        }

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _decode_json(
        value: str | None,
    ) -> dict[str, object] | None:
        if value is None:
            return None

        decoded = json.loads(value)

        if not isinstance(decoded, dict):
            raise ValueError(
                "Stored telemetry context is invalid."
            )

        return decoded

    @classmethod
    def _row_to_event(
        cls,
        row: tuple[object, ...],
    ) -> SecurityEvent:
        process_data = cls._decode_json(row[6])
        network_data = cls._decode_json(row[7])
        authentication_data = cls._decode_json(row[8])
        attributes = cls._decode_json(row[9])
        evidence_data = cls._decode_json(row[10])

        return SecurityEvent(
            event_id=str(row[0]),
            observed_at=datetime.fromisoformat(
                str(row[1])
            ),
            hostname=str(row[2]),
            source=TelemetrySource(str(row[3])),
            event_type=SecurityEventType(str(row[4])),
            collection_status=CollectionStatus(
                str(row[5])
            ),
            process=(
                ProcessContext(**process_data)
                if process_data is not None
                else None
            ),
            network=(
                NetworkContext(**network_data)
                if network_data is not None
                else None
            ),
            authentication=(
                AuthenticationContext(
                    **authentication_data
                )
                if authentication_data is not None
                else None
            ),
            attributes=attributes or {},
            evidence=(
                EvidenceProvenance(**evidence_data)
                if evidence_data is not None
                else None
            ),
        )
