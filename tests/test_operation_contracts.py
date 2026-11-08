import pytest

from intentx.planning.models import OperationPlan
from intentx.validation.operation_contracts import (
    OperationContractValidator,
)


@pytest.fixture
def validator():
    return OperationContractValidator()


def service_plan(
    service="nginx",
    arguments=None,
    executable="systemctl",
):
    if arguments is None:
        arguments = [
            "restart",
            service,
        ]

    return OperationPlan(
        intent="service_management",
        action="restart",
        executable=executable,
        arguments=arguments,
        entities={
            "SERVICE": service,
        },
        state_changing=True,
        privilege_required="conditional",
        critical_operation=False,
    )


def test_valid_service_contract(
    validator,
):
    issues = validator.validate(
        service_plan()
    )

    assert issues == []


def test_service_argument_entity_mismatch(
    validator,
):
    plan = service_plan(
        service="nginx",
        arguments=[
            "restart",
            "ssh",
        ],
    )

    issues = validator.validate(plan)

    assert any(
        issue.code
        == "ARGUMENT_CONTRACT_MISMATCH"
        for issue in issues
    )


def test_service_action_argument_mismatch(
    validator,
):
    plan = service_plan(
        arguments=[
            "stop",
            "nginx",
        ],
    )

    issues = validator.validate(plan)

    assert any(
        issue.code
        == "ARGUMENT_CONTRACT_MISMATCH"
        for issue in issues
    )


def test_executable_contract_mismatch(
    validator,
):
    plan = service_plan(
        executable="bash"
    )

    issues = validator.validate(plan)

    assert any(
        issue.code
        == "EXECUTABLE_CONTRACT_MISMATCH"
        for issue in issues
    )


def test_valid_file_copy_contract(
    validator,
):
    plan = OperationPlan(
        intent="file_copy",
        action="copy",
        executable="cp",
        arguments=[
            "--",
            "/tmp/a.txt",
            "/tmp/b.txt",
        ],
        entities={
            "SOURCE_PATH": "/tmp/a.txt",
            "DESTINATION_PATH": "/tmp/b.txt",
        },
        state_changing=True,
        privilege_required=False,
        critical_operation=False,
    )

    assert validator.validate(plan) == []


def test_copy_argument_tampering_detected(
    validator,
):
    plan = OperationPlan(
        intent="file_copy",
        action="copy",
        executable="cp",
        arguments=[
            "--",
            "/tmp/a.txt",
            "/etc/passwd",
        ],
        entities={
            "SOURCE_PATH": "/tmp/a.txt",
            "DESTINATION_PATH": "/tmp/b.txt",
        },
        state_changing=True,
        privilege_required=False,
        critical_operation=False,
    )

    issues = validator.validate(plan)

    assert any(
        issue.code
        == "ARGUMENT_CONTRACT_MISMATCH"
        for issue in issues
    )


def test_valid_force_termination_contract(
    validator,
):
    plan = OperationPlan(
        intent="process_termination",
        action="force_terminate",
        executable="kill",
        arguments=[
            "-KILL",
            "--",
            "1234",
        ],
        entities={
            "PID": "1234",
        },
        state_changing=True,
        privilege_required="conditional",
        critical_operation=False,
    )

    assert validator.validate(plan) == []


def test_pid_argument_tampering_detected(
    validator,
):
    plan = OperationPlan(
        intent="process_termination",
        action="terminate",
        executable="kill",
        arguments=[
            "-TERM",
            "--",
            "9999",
        ],
        entities={
            "PID": "1234",
        },
        state_changing=True,
        privilege_required="conditional",
        critical_operation=False,
    )

    issues = validator.validate(plan)

    assert any(
        issue.code
        == "ARGUMENT_CONTRACT_MISMATCH"
        for issue in issues
    )


def test_valid_package_contract(
    validator,
):
    plan = OperationPlan(
        intent="package_management",
        action="install",
        executable="apt-get",
        arguments=[
            "install",
            "nginx",
        ],
        entities={
            "PACKAGE": "nginx",
        },
        state_changing=True,
        privilege_required=True,
        critical_operation=False,
    )

    assert validator.validate(plan) == []


def test_valid_disk_contract(
    validator,
):
    plan = OperationPlan(
        intent="disk_management",
        action="format",
        executable="mkfs",
        arguments=[
            "/dev/sdb",
        ],
        entities={
            "DEVICE": "/dev/sdb",
        },
        state_changing=True,
        privilege_required=True,
        critical_operation=True,
    )

    assert validator.validate(plan) == []


def test_unsupported_contract_fails_closed(
    validator,
):
    plan = OperationPlan(
        intent="out_of_scope",
        action="made_up",
        executable="echo",
        arguments=["hello"],
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    issues = validator.validate(plan)

    assert any(
        issue.code
        == "UNSUPPORTED_OPERATION_CONTRACT"
        for issue in issues
    )


def test_plan_type_enforced(
    validator,
):
    with pytest.raises(TypeError):
        validator.validate(
            {"intent": "something"}
        )