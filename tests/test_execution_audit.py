import json
from dataclasses import FrozenInstanceError
from datetime import datetime
from pathlib import Path

import pytest

from intentx.execution.audit import (
    ExecutionAuditRecord,
    JsonlAuditWriter,
    VALID_AUDIT_EVENT_TYPES,
    utc_timestamp,
)


def make_record(**overrides):
    values = {
        "timestamp": "2026-09-21T05:44:56+00:00",
        "correlation_id": "corr-test-001",
        "execution_id": "exec-test-001",
        "event_type": "EXECUTION_COMPLETED",
        "role": "VIEWER",
        "environment": "DEV",
        "intent": "memory_inspection",
        "action": "memory_usage",
        "executable": "free",
        "arguments": ("-h",),
        "policy_decision": "ALLOW",
        "execution_status": "EXECUTED",
        "return_code": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "duration_ms": 5,
        "reason_code": "EXECUTION_COMPLETED",
        "reason": "Execution completed.",
        "metadata": {
            "risk_score": 0,
            "risk_level": "LOW",
        },
    }

    values.update(overrides)

    return ExecutionAuditRecord(**values)


# ============================================================
# Basic model behavior
# ============================================================


def test_execution_audit_record_valid():
    record = make_record()

    assert record.correlation_id == "corr-test-001"
    assert record.execution_id == "exec-test-001"
    assert record.event_type == "EXECUTION_COMPLETED"
    assert record.policy_decision == "ALLOW"
    assert record.execution_status == "EXECUTED"
    assert record.argv == ["free", "-h"]


def test_execution_audit_record_is_frozen():
    record = make_record()

    with pytest.raises(FrozenInstanceError):
        record.intent = "changed"


def test_arguments_are_converted_to_tuple():
    arguments = ["-h"]

    record = make_record(
        arguments=arguments,
    )

    arguments.append("--changed")

    assert record.arguments == ("-h",)


def test_argv_returns_defensive_copy():
    record = make_record()

    first = record.argv
    first.append("--tampered")

    assert record.argv == ["free", "-h"]


def test_metadata_is_defensively_copied():
    metadata = {
        "risk_score": 0,
    }

    record = make_record(
        metadata=metadata,
    )

    metadata["risk_score"] = 100

    assert record.metadata["risk_score"] == 0


def test_metadata_is_immutable():
    record = make_record()

    with pytest.raises(TypeError):
        record.metadata["risk_score"] = 100


def test_to_dict_returns_mutable_defensive_copies():
    record = make_record()

    payload = record.to_dict()

    payload["arguments"].append(
        "--tampered"
    )
    payload["metadata"]["risk_score"] = 100

    assert record.arguments == ("-h",)
    assert record.metadata["risk_score"] == 0


# ============================================================
# Normalization
# ============================================================


@pytest.mark.parametrize(
    "event_type",
    VALID_AUDIT_EVENT_TYPES,
)
def test_all_supported_event_types_are_accepted(
    event_type,
):
    record = make_record(
        event_type=event_type.lower(),
    )

    assert record.event_type == event_type


def test_policy_decision_is_normalized():
    record = make_record(
        policy_decision="allow",
    )

    assert record.policy_decision == "ALLOW"


def test_execution_status_is_normalized():
    record = make_record(
        execution_status="executed",
    )

    assert record.execution_status == "EXECUTED"


def test_event_type_is_normalized():
    record = make_record(
        event_type="execution_failed",
    )

    assert record.event_type == "EXECUTION_FAILED"


# ============================================================
# Required string validation
# ============================================================


@pytest.mark.parametrize(
    "field_name",
    [
        "timestamp",
        "correlation_id",
        "execution_id",
        "event_type",
        "role",
        "environment",
        "intent",
        "action",
        "executable",
        "policy_decision",
        "execution_status",
        "reason_code",
        "reason",
    ],
)
def test_required_strings_reject_non_string(
    field_name,
):
    with pytest.raises(TypeError):
        make_record(
            **{
                field_name: 123,
            }
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "timestamp",
        "correlation_id",
        "execution_id",
        "event_type",
        "role",
        "environment",
        "intent",
        "action",
        "executable",
        "policy_decision",
        "execution_status",
        "reason_code",
        "reason",
    ],
)
def test_required_strings_reject_empty_values(
    field_name,
):
    with pytest.raises(ValueError):
        make_record(
            **{
                field_name: "   ",
            }
        )


def test_unsupported_event_type_is_rejected():
    with pytest.raises(ValueError):
        make_record(
            event_type="SOMETHING_UNKNOWN",
        )


# ============================================================
# Timestamp validation
# ============================================================


def test_timestamp_requires_valid_iso8601():
    with pytest.raises(ValueError):
        make_record(
            timestamp="not-a-timestamp",
        )


def test_timestamp_requires_timezone():
    with pytest.raises(ValueError):
        make_record(
            timestamp="2026-09-21T05:44:56",
        )


def test_timestamp_accepts_utc_z_suffix():
    record = make_record(
        timestamp="2026-09-21T05:44:56Z",
    )

    assert record.timestamp.endswith("Z")


def test_utc_timestamp_is_timezone_aware():
    value = utc_timestamp()

    parsed = datetime.fromisoformat(
        value
    )

    assert parsed.tzinfo is not None
    assert parsed.utcoffset() is not None


# ============================================================
# Arguments
# ============================================================


def test_arguments_reject_non_string_member():
    with pytest.raises(TypeError):
        make_record(
            arguments=(
                "-h",
                123,
            )
        )


def test_empty_arguments_are_allowed():
    record = make_record(
        arguments=(),
    )

    assert record.argv == ["free"]


# ============================================================
# Return code
# ============================================================


@pytest.mark.parametrize(
    "return_code",
    [
        True,
        False,
        "0",
        1.5,
    ],
)
def test_return_code_rejects_invalid_types(
    return_code,
):
    with pytest.raises(TypeError):
        make_record(
            return_code=return_code,
        )


def test_return_code_allows_none():
    record = make_record(
        return_code=None,
    )

    assert record.return_code is None


def test_return_code_allows_nonzero_integer():
    record = make_record(
        return_code=1,
    )

    assert record.return_code == 1


# ============================================================
# Truncation flags
# ============================================================


@pytest.mark.parametrize(
    "field_name",
    [
        "stdout_truncated",
        "stderr_truncated",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        "false",
        None,
    ],
)
def test_truncation_flags_require_boolean(
    field_name,
    value,
):
    with pytest.raises(TypeError):
        make_record(
            **{
                field_name: value,
            }
        )


# ============================================================
# Duration
# ============================================================


@pytest.mark.parametrize(
    "duration_ms",
    [
        True,
        False,
        "5",
        1.5,
    ],
)
def test_duration_rejects_invalid_types(
    duration_ms,
):
    with pytest.raises(TypeError):
        make_record(
            duration_ms=duration_ms,
        )


def test_duration_rejects_negative_value():
    with pytest.raises(ValueError):
        make_record(
            duration_ms=-1,
        )


def test_duration_allows_none():
    record = make_record(
        duration_ms=None,
    )

    assert record.duration_ms is None


def test_duration_allows_zero():
    record = make_record(
        duration_ms=0,
    )

    assert record.duration_ms == 0


# ============================================================
# Metadata
# ============================================================


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        [],
        "metadata",
        123,
    ],
)
def test_metadata_must_be_mapping(
    metadata,
):
    with pytest.raises(TypeError):
        make_record(
            metadata=metadata,
        )


# ============================================================
# JSONL writer
# ============================================================


def test_writer_creates_parent_directory(
    tmp_path,
):
    audit_path = (
        tmp_path
        / "nested"
        / "audit"
        / "execution.jsonl"
    )

    writer = JsonlAuditWriter(
        audit_path
    )

    writer.write(
        make_record()
    )

    assert audit_path.is_file()


def test_writer_persists_valid_json_line(
    tmp_path,
):
    audit_path = (
        tmp_path
        / "execution.jsonl"
    )

    writer = JsonlAuditWriter(
        audit_path
    )

    writer.write(
        make_record()
    )

    lines = audit_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    stored = json.loads(
        lines[0]
    )

    assert (
        stored["correlation_id"]
        == "corr-test-001"
    )
    assert (
        stored["execution_id"]
        == "exec-test-001"
    )
    assert stored["argv"] == [
        "free",
        "-h",
    ]


def test_writer_appends_records(
    tmp_path,
):
    audit_path = (
        tmp_path
        / "execution.jsonl"
    )

    writer = JsonlAuditWriter(
        audit_path
    )

    writer.write(
        make_record(
            execution_id="exec-001",
        )
    )

    writer.write(
        make_record(
            execution_id="exec-002",
        )
    )

    lines = audit_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 2

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert (
        first["execution_id"]
        == "exec-001"
    )
    assert (
        second["execution_id"]
        == "exec-002"
    )


def test_writer_preserves_unicode(
    tmp_path,
):
    audit_path = (
        tmp_path
        / "execution.jsonl"
    )

    writer = JsonlAuditWriter(
        audit_path
    )

    writer.write(
        make_record(
            reason="పరీక్ష audit event",
        )
    )

    stored = json.loads(
        audit_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        stored["reason"]
        == "పరీక్ష audit event"
    )


def test_writer_rejects_wrong_record_type(
    tmp_path,
):
    writer = JsonlAuditWriter(
        tmp_path
        / "execution.jsonl"
    )

    with pytest.raises(TypeError):
        writer.write(
            {
                "execution_id":
                    "exec-test",
            }
        )


def test_writer_rejects_existing_directory_as_path(
    tmp_path,
):
    directory = (
        tmp_path
        / "audit"
    )

    directory.mkdir()

    with pytest.raises(ValueError):
        JsonlAuditWriter(
            directory
        )


def test_writer_does_not_overwrite_existing_records(
    tmp_path,
):
    audit_path = (
        tmp_path
        / "execution.jsonl"
    )

    first_writer = JsonlAuditWriter(
        audit_path
    )

    first_writer.write(
        make_record(
            execution_id="exec-first",
        )
    )

    second_writer = JsonlAuditWriter(
        audit_path
    )

    second_writer.write(
        make_record(
            execution_id="exec-second",
        )
    )

    lines = audit_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 2

    assert (
        json.loads(
            lines[0]
        )["execution_id"]
        == "exec-first"
    )

    assert (
        json.loads(
            lines[1]
        )["execution_id"]
        == "exec-second"
    )


# ============================================================
# Security-oriented audit tests
# ============================================================


def test_structured_argv_is_preserved_without_shell_joining():
    record = make_record(
        executable="find",
        arguments=(
            "/tmp/example path",
            "-name",
            "*.log",
        ),
    )

    assert record.argv == [
        "find",
        "/tmp/example path",
        "-name",
        "*.log",
    ]

    assert isinstance(
        record.arguments,
        tuple,
    )


def test_writer_does_not_require_shell_execution(
    tmp_path,
):
    audit_path = (
        tmp_path
        / "execution.jsonl"
    )

    writer = JsonlAuditWriter(
        audit_path
    )

    writer.write(
        make_record()
    )

    assert audit_path.exists()


def test_audit_payload_contains_execution_reconstruction_fields():
    payload = make_record().to_dict()

    required_fields = {
        "timestamp",
        "correlation_id",
        "execution_id",
        "event_type",
        "role",
        "environment",
        "intent",
        "action",
        "executable",
        "arguments",
        "argv",
        "policy_decision",
        "execution_status",
        "return_code",
        "stdout_truncated",
        "stderr_truncated",
        "duration_ms",
        "reason_code",
        "reason",
        "metadata",
    }

    assert required_fields.issubset(
        payload.keys()
    )