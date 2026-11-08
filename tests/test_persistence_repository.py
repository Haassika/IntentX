from dataclasses import FrozenInstanceError

import pytest

from intentx.persistence.models import (
    LifecycleRecord,
)
from intentx.persistence.repository import (
    SQLiteLifecycleRepository,
)


def make_record(
    request_id="req-001",
    correlation_id="corr-001",
    execution_id=None,
    stage="ANALYSIS",
    status="READY_FOR_PLANNING",
):
    return LifecycleRecord(
        request_id=request_id,
        correlation_id=correlation_id,
        execution_id=execution_id,
        request_text="show memory usage",
        role="VIEWER",
        environment="DEV",
        stage=stage,
        status=status,
        predicted_intent="memory_inspection",
        confidence=0.98,
        reason="Lifecycle checkpoint.",
        created_at="2026-09-21T10:00:00+00:00",
        updated_at="2026-09-21T10:00:00+00:00",
    )


def test_lifecycle_record_is_immutable():
    record = make_record()

    with pytest.raises(FrozenInstanceError):
        record.status = "EXECUTED"


def test_lifecycle_record_normalizes_context():
    record = LifecycleRecord(
        request_id=" req-001 ",
        correlation_id=" corr-001 ",
        execution_id=" exec-001 ",
        request_text=" show memory usage ",
        role=" viewer ",
        environment=" dev ",
        stage=" planning ",
        status=" plan_created ",
        predicted_intent=" memory_inspection ",
        confidence=0.98,
        reason=" Plan created. ",
        created_at="2026-09-21T10:00:00+00:00",
        updated_at="2026-09-21T10:00:00+00:00",
    )

    assert record.request_id == "req-001"
    assert record.correlation_id == "corr-001"
    assert record.execution_id == "exec-001"
    assert record.request_text == "show memory usage"
    assert record.role == "VIEWER"
    assert record.environment == "DEV"
    assert record.stage == "PLANNING"
    assert record.status == "PLAN_CREATED"
    assert record.predicted_intent == "memory_inspection"
    assert record.reason == "Plan created."


@pytest.mark.parametrize(
    "field",
    [
        "request_id",
        "correlation_id",
        "request_text",
        "role",
        "environment",
        "stage",
        "status",
        "reason",
    ],
)
def test_lifecycle_record_rejects_empty_required_strings(
    field,
):
    values = {
        "request_id": "req-001",
        "correlation_id": "corr-001",
        "execution_id": None,
        "request_text": "show memory usage",
        "role": "VIEWER",
        "environment": "DEV",
        "stage": "ANALYSIS",
        "status": "READY_FOR_PLANNING",
        "predicted_intent": "memory_inspection",
        "confidence": 0.98,
        "reason": "Ready.",
        "created_at": "2026-09-21T10:00:00+00:00",
        "updated_at": "2026-09-21T10:00:00+00:00",
    }
    values[field] = "   "

    with pytest.raises(ValueError):
        LifecycleRecord(**values)


@pytest.mark.parametrize(
    "confidence",
    [-0.01, 1.01],
)
def test_lifecycle_record_rejects_invalid_confidence(
    confidence,
):
    values = {
        "request_id": "req-001",
        "correlation_id": "corr-001",
        "execution_id": None,
        "request_text": "show memory usage",
        "role": "VIEWER",
        "environment": "DEV",
        "stage": "ANALYSIS",
        "status": "READY_FOR_PLANNING",
        "predicted_intent": "memory_inspection",
        "confidence": confidence,
        "reason": "Ready.",
        "created_at": "2026-09-21T10:00:00+00:00",
        "updated_at": "2026-09-21T10:00:00+00:00",
    }

    with pytest.raises(ValueError):
        LifecycleRecord(**values)


def test_repository_initializes_database(tmp_path):
    database_path = tmp_path / "intentx.db"

    repository = SQLiteLifecycleRepository(
        database_path
    )

    assert database_path.exists()
    assert repository.database_path == database_path


def test_repository_saves_and_reads_record(tmp_path):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    record = make_record()

    repository.save(record)

    loaded = repository.get(
        record.request_id
    )

    assert loaded == record


def test_repository_returns_none_for_unknown_request(
    tmp_path,
):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    assert repository.get("missing") is None


def test_repository_updates_same_request_id(tmp_path):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    original = make_record()

    updated = LifecycleRecord(
        request_id=original.request_id,
        correlation_id=original.correlation_id,
        execution_id="exec-001",
        request_text=original.request_text,
        role=original.role,
        environment=original.environment,
        stage="EXECUTION",
        status="EXECUTED",
        predicted_intent=original.predicted_intent,
        confidence=original.confidence,
        reason="Execution completed.",
        created_at=original.created_at,
        updated_at="2026-09-21T10:01:00+00:00",
    )

    repository.save(original)
    repository.save(updated)

    loaded = repository.get(
        original.request_id
    )

    assert loaded == updated


def test_repository_lists_correlation_lifecycle(
    tmp_path,
):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    first = make_record(
        request_id="req-001",
        correlation_id="corr-shared",
    )

    second = LifecycleRecord(
        request_id="req-002",
        correlation_id="corr-shared",
        execution_id="exec-002",
        request_text="show memory usage",
        role="VIEWER",
        environment="DEV",
        stage="EXECUTION",
        status="EXECUTED",
        predicted_intent="memory_inspection",
        confidence=0.98,
        reason="Completed.",
        created_at="2026-09-21T10:02:00+00:00",
        updated_at="2026-09-21T10:02:00+00:00",
    )

    repository.save(first)
    repository.save(second)

    records = repository.list_by_correlation_id(
        "corr-shared"
    )

    assert records == [first, second]


def test_repository_does_not_expose_execution_method(
    tmp_path,
):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    assert not hasattr(repository, "execute")
    assert not hasattr(repository, "authorize")
    assert not hasattr(repository, "run")


@pytest.mark.parametrize(
    "timestamp_field",
    [
        "created_at",
        "updated_at",
    ],
)
def test_lifecycle_record_rejects_invalid_timestamp(
    timestamp_field,
):
    values = make_record().to_dict()
    values[timestamp_field] = "not-a-timestamp"

    with pytest.raises(ValueError):
        LifecycleRecord(**values)


@pytest.mark.parametrize(
    "timestamp_field",
    [
        "created_at",
        "updated_at",
    ],
)
def test_lifecycle_record_rejects_timestamp_without_timezone(
    timestamp_field,
):
    values = make_record().to_dict()
    values[timestamp_field] = "2026-09-21T10:00:00"

    with pytest.raises(ValueError):
        LifecycleRecord(**values)


def test_repository_persists_across_instances(
    tmp_path,
):
    database_path = tmp_path / "intentx.db"

    first_repository = SQLiteLifecycleRepository(
        database_path
    )
    record = make_record()

    first_repository.save(record)

    second_repository = SQLiteLifecycleRepository(
        database_path
    )

    assert second_repository.get(
        record.request_id
    ) == record


def test_repository_treats_sql_like_identifier_as_data(
    tmp_path,
):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    suspicious_id = (
        "req'; DROP TABLE lifecycle_records; --"
    )

    record = make_record(
        request_id=suspicious_id,
    )

    repository.save(record)

    assert repository.get(
        suspicious_id
    ) == record

    normal_record = make_record(
        request_id="req-after",
    )
    repository.save(normal_record)

    assert repository.get(
        "req-after"
    ) == normal_record


def test_repository_rejects_non_record_save(
    tmp_path,
):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    with pytest.raises(TypeError):
        repository.save(
            {
                "request_id": "req-001",
            }
        )


@pytest.mark.parametrize(
    "method_name",
    [
        "get",
        "list_by_correlation_id",
    ],
)
def test_repository_rejects_empty_lookup_identifier(
    tmp_path,
    method_name,
):
    repository = SQLiteLifecycleRepository(
        tmp_path / "intentx.db"
    )

    method = getattr(
        repository,
        method_name,
    )

    with pytest.raises(ValueError):
        method("   ")
