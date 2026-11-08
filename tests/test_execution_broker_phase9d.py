from pathlib import Path
from unittest.mock import MagicMock

import pytest

from intentx.execution.audit import ExecutionAuditRecord
from intentx.execution.broker import ExecutionBroker
from intentx.execution.process_runner import (
    ProcessExecutionResult,
    ProcessLaunchError,
)
from intentx.planning.models import OperationPlan


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "security_policy.yaml"
CATALOG_PATH = ROOT / "configs" / "intent_catalog.yaml"


def memory_plan():
    return OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="free",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )


def restart_service_plan():
    return OperationPlan(
        intent="service_management",
        action="restart",
        executable="systemctl",
        arguments=("restart", "nginx"),
        entities={"SERVICE": "nginx"},
        state_changing=True,
        privilege_required="conditional",
        critical_operation=False,
    )


class RecordingAuditWriter:
    def __init__(self):
        self.records = []

    def write(self, record):
        assert isinstance(record, ExecutionAuditRecord)
        self.records.append(record)


class FailingAuditWriter:
    def write(self, record):
        raise OSError("simulated audit failure")


@pytest.fixture
def broker():
    return ExecutionBroker(
        policy_path=POLICY_PATH,
        catalog_path=CATALOG_PATH,
    )


def configure_execution_dependencies(
    broker,
    *,
    resolved_path="/usr/bin/free",
    process_result=None,
    audit_writer=None,
):
    resolver = MagicMock()
    resolver.resolve.return_value = resolved_path

    runner = MagicMock()
    runner.timeout_seconds = 10
    runner.stdout_max_bytes = 65536
    runner.stderr_max_bytes = 65536

    if process_result is None:
        process_result = ProcessExecutionResult(
            return_code=0,
            stdout=b"ok\n",
            stderr=b"",
            timed_out=False,
            duration_ms=7,
            metadata={
                "stdout_original_bytes": 3,
                "stdout_retained_bytes": 3,
                "stdout_truncated": False,
                "stderr_original_bytes": 0,
                "stderr_retained_bytes": 0,
                "stderr_truncated": False,
                "shell": False,
                "parent_environment_inherited": False,
                "stdin": "DEVNULL",
                "start_new_session": True,
            },
        )

    runner.run.return_value = process_result

    if audit_writer is None:
        audit_writer = RecordingAuditWriter()

    broker.resolver = resolver
    broker.runner = runner
    broker.audit_writer = audit_writer

    return resolver, runner, audit_writer


def test_execute_rejects_non_operation_plan_before_execution(broker):
    configure_execution_dependencies(broker)

    with pytest.raises(TypeError):
        broker.execute(
            plan="free -h",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-001",
        )

    broker.runner.run.assert_not_called()


def test_execute_requires_nonempty_correlation_id(broker):
    configure_execution_dependencies(broker)

    with pytest.raises(ValueError):
        broker.execute(
            plan=memory_plan(),
            role="VIEWER",
            environment="DEV",
            correlation_id="   ",
        )

    broker.runner.run.assert_not_called()


def test_execute_blocks_non_allow_policy_before_resolution_or_runner(broker):
    resolver, runner, audit_writer = configure_execution_dependencies(
        broker
    )

    result = broker.execute(
        plan=restart_service_plan(),
        role="OPERATOR",
        environment="DEV",
        correlation_id="corr-policy-block",
        execution_id="exec-policy-block",
    )

    assert result.status == "BLOCKED"
    assert result.process_started is False
    assert result.reason_code == "POLICY_NOT_ALLOW"

    resolver.resolve.assert_not_called()
    runner.run.assert_not_called()

    assert len(audit_writer.records) == 1
    assert audit_writer.records[0].event_type == "EXECUTION_BLOCKED"
    assert audit_writer.records[0].policy_decision == "REQUIRE_APPROVAL"


def test_execute_revalidates_tampered_plan_before_process_boundary(broker):
    resolver, runner, audit_writer = configure_execution_dependencies(
        broker
    )

    tampered = OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="uname",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    result = broker.execute(
        plan=tampered,
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-tampered",
        execution_id="exec-tampered",
    )

    assert result.status == "BLOCKED"
    assert result.reason_code == "OPERATION_VALIDATION_FAILED"
    resolver.resolve.assert_not_called()
    runner.run.assert_not_called()

    assert len(audit_writer.records) == 1
    assert audit_writer.records[0].event_type == "EXECUTION_BLOCKED"


def test_execute_resolves_only_after_allow(broker):
    resolver, runner, audit_writer = configure_execution_dependencies(
        broker
    )

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-allow",
        execution_id="exec-allow",
    )

    assert result.status == "EXECUTED"
    resolver.resolve.assert_called_once_with("free")
    runner.run.assert_called_once()
    assert len(audit_writer.records) == 2


def test_execute_builds_process_request_from_runner_owned_limits(broker):
    resolver, runner, _ = configure_execution_dependencies(broker)

    runner.timeout_seconds = 11
    runner.stdout_max_bytes = 12345
    runner.stderr_max_bytes = 23456

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-limits",
        execution_id="exec-limits",
    )

    assert result.status == "EXECUTED"

    process_request = runner.run.call_args.args[0]

    assert process_request.executable_path == "/usr/bin/free"
    assert process_request.arguments == ("-h",)
    assert process_request.timeout_seconds == 11
    assert process_request.stdout_max_bytes == 12345
    assert process_request.stderr_max_bytes == 23456


def test_attempt_audit_is_written_before_runner_is_called(broker):
    call_order = []

    class OrderedAuditWriter:
        def write(self, record):
            call_order.append(("audit", record.event_type))

    resolver, runner, _ = configure_execution_dependencies(
        broker,
        audit_writer=OrderedAuditWriter(),
    )

    runner.run.side_effect = lambda request: (
        call_order.append(("runner", "run"))
        or ProcessExecutionResult(
            return_code=0,
            stdout=b"",
            stderr=b"",
            timed_out=False,
            duration_ms=1,
            metadata={
                "stdout_original_bytes": 0,
                "stdout_retained_bytes": 0,
                "stdout_truncated": False,
                "stderr_original_bytes": 0,
                "stderr_retained_bytes": 0,
                "stderr_truncated": False,
            },
        )
    )

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-order",
        execution_id="exec-order",
    )

    assert result.status == "EXECUTED"
    assert call_order[0] == ("audit", "EXECUTION_ATTEMPTED")
    assert call_order[1] == ("runner", "run")
    assert call_order[2] == ("audit", "EXECUTION_COMPLETED")


def test_audit_prewrite_failure_fails_closed_before_process_launch(broker):
    resolver, runner, _ = configure_execution_dependencies(
        broker,
        audit_writer=FailingAuditWriter(),
    )

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-audit-fail",
        execution_id="exec-audit-fail",
    )

    assert result.status == "BLOCKED"
    assert result.process_started is False
    assert result.reason_code == "AUDIT_PREWRITE_FAILED"

    resolver.resolve.assert_called_once_with("free")
    runner.run.assert_not_called()


def test_success_writes_attempt_and_completed_audit_events(broker):
    _, _, audit_writer = configure_execution_dependencies(broker)

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-success",
        execution_id="exec-success",
    )

    assert result.status == "EXECUTED"
    assert result.return_code == 0
    assert result.stdout == "ok\n"

    assert [record.event_type for record in audit_writer.records] == [
        "EXECUTION_ATTEMPTED",
        "EXECUTION_COMPLETED",
    ]

    completed = audit_writer.records[-1]
    assert completed.execution_status == "EXECUTED"
    assert completed.policy_decision == "ALLOW"
    assert completed.return_code == 0
    assert completed.duration_ms == 7


def test_nonzero_exit_is_executed_process_not_launch_failure(broker):
    process_result = ProcessExecutionResult(
        return_code=2,
        stdout=b"",
        stderr=b"command failed\n",
        timed_out=False,
        duration_ms=4,
        metadata={
            "stdout_original_bytes": 0,
            "stdout_retained_bytes": 0,
            "stdout_truncated": False,
            "stderr_original_bytes": 15,
            "stderr_retained_bytes": 15,
            "stderr_truncated": False,
        },
    )

    _, _, audit_writer = configure_execution_dependencies(
        broker,
        process_result=process_result,
    )

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-nonzero",
        execution_id="exec-nonzero",
    )

    assert result.status == "FAILED"
    assert result.process_started is True
    assert result.return_code == 2
    assert result.stderr == "command failed\n"

    assert audit_writer.records[-1].event_type == "EXECUTION_FAILED"


def test_timeout_maps_to_timed_out_and_writes_terminal_audit(broker):
    process_result = ProcessExecutionResult(
        return_code=None,
        stdout=b"partial",
        stderr=b"",
        timed_out=True,
        duration_ms=10000,
        metadata={
            "stdout_original_bytes": 7,
            "stdout_retained_bytes": 7,
            "stdout_truncated": False,
            "stderr_original_bytes": 0,
            "stderr_retained_bytes": 0,
            "stderr_truncated": False,
        },
    )

    _, _, audit_writer = configure_execution_dependencies(
        broker,
        process_result=process_result,
    )

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-timeout",
        execution_id="exec-timeout",
    )

    assert result.status == "TIMED_OUT"
    assert result.process_started is True
    assert result.return_code is None
    assert result.stdout == "partial"

    assert audit_writer.records[-1].event_type == "EXECUTION_TIMED_OUT"


def test_runner_launch_failure_is_reported_without_fabricating_output(broker):
    _, runner, audit_writer = configure_execution_dependencies(broker)

    runner.run.side_effect = ProcessLaunchError(
        "simulated process launch failure"
    )

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-launch-fail",
        execution_id="exec-launch-fail",
    )

    assert result.return_code is None
    assert result.stdout == ""
    assert result.stderr == ""
    assert result.reason_code == "PROCESS_LAUNCH_FAILED"

    assert audit_writer.records[0].event_type == "EXECUTION_ATTEMPTED"
    assert audit_writer.records[-1].event_type == "EXECUTION_FAILED"


def test_output_truncation_metadata_is_preserved(broker):
    process_result = ProcessExecutionResult(
        return_code=0,
        stdout=b"abc",
        stderr=b"xy",
        timed_out=False,
        duration_ms=3,
        metadata={
            "stdout_original_bytes": 100,
            "stdout_retained_bytes": 3,
            "stdout_truncated": True,
            "stderr_original_bytes": 50,
            "stderr_retained_bytes": 2,
            "stderr_truncated": True,
        },
    )

    _, _, audit_writer = configure_execution_dependencies(
        broker,
        process_result=process_result,
    )

    result = broker.execute(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        correlation_id="corr-truncated",
        execution_id="exec-truncated",
    )

    assert result.status == "EXECUTED"
    assert result.stdout == "abc"
    assert result.stderr == "xy"
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True

    completed = audit_writer.records[-1]
    assert completed.stdout_truncated is True
    assert completed.stderr_truncated is True


def test_execute_does_not_accept_prior_execution_request_as_authority(broker):
    configure_execution_dependencies(broker)

    request, blocked = broker.authorize(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        execution_id="exec-old-request",
    )

    assert blocked is None
    assert request is not None

    with pytest.raises(TypeError):
        broker.execute(
            plan=request,
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-old-request",
        )

    broker.runner.run.assert_not_called()
