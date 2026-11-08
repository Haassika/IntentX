import pytest

from intentx.planning.models import (
    OperationPlan,
)
from intentx.validation.models import (
    OperationValidationResult,
)
from intentx.validation.operation_validator import (
    OperationValidator,
)


@pytest.fixture
def validator():
    return OperationValidator()


def make_plan(
    intent="service_management",
    action="restart",
    executable="systemctl",
    arguments=None,
    entities=None,
    state_changing=True,
    privilege_required="conditional",
    critical_operation=False,
):
    if arguments is None:
        arguments = [
            "restart",
            "nginx",
        ]

    if entities is None:
        entities = {
            "SERVICE": "nginx",
        }

    return OperationPlan(
        intent=intent,
        action=action,
        executable=executable,
        arguments=arguments,
        entities=entities,
        state_changing=state_changing,
        privilege_required=privilege_required,
        critical_operation=critical_operation,
    )


def test_valid_service_operation(
    validator,
):
    result = validator.validate(
        make_plan()
    )

    assert result.valid is True
    assert (
        result.decision
        == "VALIDATED_OPERATION"
    )
    assert result.issues == []


def test_result_type(validator):
    result = validator.validate(
        make_plan()
    )

    assert isinstance(
        result,
        OperationValidationResult,
    )


def test_unknown_intent_rejected(
    validator,
):
    plan = make_plan(
        intent="unknown_intent",
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code == "UNKNOWN_INTENT"
        for issue in result.issues
    )


def test_action_not_allowed(
    validator,
):
    plan = make_plan(
        action="delete",
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code == "ACTION_NOT_ALLOWED"
        for issue in result.issues
    )


def test_executable_not_allowlisted(
    validator,
):
    plan = make_plan(
        executable="bash",
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "EXECUTABLE_NOT_ALLOWED"
        for issue in result.issues
    )


def test_unexpected_entity_rejected(
    validator,
):
    plan = make_plan(
        entities={
            "SERVICE": "nginx",
            "PID": "1234",
        }
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code == "ENTITY_NOT_ALLOWED"
        for issue in result.issues
    )


def test_required_entity_missing(
    validator,
):
    plan = make_plan(
        entities={}
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "REQUIRED_ENTITY_MISSING"
        for issue in result.issues
    )


def test_invalid_service_semantics(
    validator,
):
    plan = make_plan(
        entities={
            "SERVICE": "nginx;reboot"
        }
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code == "INVALID_SERVICE"
        for issue in result.issues
    )


def test_source_equals_destination(
    validator,
):
    plan = OperationPlan(
        intent="file_copy",
        action="copy",
        executable="cp",
        arguments=[
            "--",
            "/tmp/a.txt",
            "/tmp/a.txt",
        ],
        entities={
            "SOURCE_PATH": "/tmp/a.txt",
            "DESTINATION_PATH": "/tmp/a.txt",
        },
        state_changing=True,
        privilege_required=False,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "SOURCE_EQUALS_DESTINATION"
        for issue in result.issues
    )


def test_state_metadata_mismatch(
    validator,
):
    plan = make_plan(
        state_changing=False,
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "STATE_METADATA_MISMATCH"
        for issue in result.issues
    )


def test_privilege_metadata_mismatch(
    validator,
):
    plan = make_plan(
        privilege_required=False,
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "PRIVILEGE_METADATA_MISMATCH"
        for issue in result.issues
    )


def test_critical_metadata_mismatch(
    validator,
):
    plan = make_plan(
        critical_operation=True,
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "CRITICAL_METADATA_MISMATCH"
        for issue in result.issues
    )


def test_invalid_pid_detected(
    validator,
):
    plan = OperationPlan(
        intent="process_termination",
        action="terminate",
        executable="kill",
        arguments=[
            "-TERM",
            "--",
            "0",
        ],
        entities={
            "PID": "0",
        },
        state_changing=True,
        privilege_required="conditional",
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code == "INVALID_PID"
        for issue in result.issues
    )


def test_null_byte_argument_rejected(
    validator,
):
    plan = make_plan(
        arguments=[
            "restart",
            "nginx\x00evil",
        ]
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "NULL_BYTE_ARGUMENT"
        for issue in result.issues
    )


def test_plan_must_be_operation_plan(
    validator,
):
    with pytest.raises(TypeError):
        validator.validate(
            {
                "intent":
                "service_management"
            }
        )


def test_critical_plan_can_validate(
    validator,
):
    """
    Validation and authorization are separate.

    A structurally valid critical operation can
    pass validation. The later policy layer is
    responsible for denying it.
    """

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

    result = validator.validate(plan)

    assert result.valid is True
    assert (
        result.decision
        == "VALIDATED_OPERATION"
    )


def test_validation_does_not_authorize(
    validator,
):
    result = validator.validate(
        make_plan()
    )

    assert result.valid is True

    assert result.decision not in {
        "ALLOW",
        "EXECUTE",
        "AUTHORIZED",
    }


def test_validator_has_no_execution_method():
    prohibited = {
        "execute",
        "run",
        "run_command",
        "run_shell",
    }

    for method in prohibited:
        assert not hasattr(
            OperationValidator,
            method,
        )
def test_argument_entity_mismatch_rejected(
    validator,
):
    """
    A valid entity cannot be paired with
    arguments targeting a different entity.
    """

    plan = make_plan(
        entities={
            "SERVICE": "nginx",
        },
        arguments=[
            "restart",
            "ssh",
        ],
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "ARGUMENT_CONTRACT_MISMATCH"
        for issue in result.issues
    )


def test_action_argument_mismatch_rejected(
    validator,
):
    """
    The argv action must agree with the
    declared OperationPlan action.
    """

    plan = make_plan(
        action="restart",
        arguments=[
            "stop",
            "nginx",
        ],
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "ARGUMENT_CONTRACT_MISMATCH"
        for issue in result.issues
    )


def test_validated_plan_is_preserved(
    validator,
):
    plan = make_plan()

    result = validator.validate(plan)

    assert result.valid is True
    assert result.plan == plan


def test_invalid_plan_is_not_authorized(
    validator,
):
    plan = make_plan(
        arguments=[
            "restart",
            "ssh",
        ],
    )

    result = validator.validate(plan)

    assert result.valid is False
    assert (
        result.decision
        == "VALIDATION_FAILED"
    )

    assert result.decision not in {
        "ALLOW",
        "AUTHORIZED",
        "EXECUTE",
    }

def test_normalized_source_equals_destination_rejected(
    validator,
):
    plan = OperationPlan(
        intent="file_copy",
        action="copy",
        executable="cp",
        arguments=[
            "--",
            "/tmp/a",
            "/tmp/./a",
        ],
        entities={
            "SOURCE_PATH": "/tmp/a",
            "DESTINATION_PATH": "/tmp/./a",
        },
        state_changing=True,
        privilege_required=False,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False

    assert any(
        issue.code
        == "SOURCE_EQUALS_DESTINATION"
        for issue in result.issues
    )

def test_manual_package_update_with_package_rejected(
    validator,
):
    plan = OperationPlan(
        intent="package_management",
        action="update",
        executable="apt-get",
        arguments=["update"],
        entities={
            "PACKAGE": "nginx",
        },
        state_changing=True,
        privilege_required=True,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False
    assert result.plan is None
    assert result.decision == "VALIDATION_FAILED"

    codes = {
        issue.code
        for issue in result.issues
    }

    assert (
        "ACTION_ENTITY_CONTRACT_VIOLATION"
        in codes
    )


def test_manual_package_update_without_package_validates(
    validator,
):
    plan = OperationPlan(
        intent="package_management",
        action="update",
        executable="apt-get",
        arguments=["update"],
        entities={},
        state_changing=True,
        privilege_required=True,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is True
    assert result.plan is not None


def test_manual_listening_ports_with_port_rejected(
    validator,
):
    plan = OperationPlan(
        intent="network_inspection",
        action="listening_ports",
        executable="ss",
        arguments=["-lnt"],
        entities={
            "PORT": "443",
        },
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False
    assert result.plan is None

    codes = {
        issue.code
        for issue in result.issues
    }

    assert (
        "ACTION_ENTITY_CONTRACT_VIOLATION"
        in codes
    )


def test_manual_process_list_with_pid_rejected(
    validator,
):
    plan = OperationPlan(
        intent="process_inspection",
        action="list",
        executable="ps",
        arguments=["-ef"],
        entities={
            "PID": "4321",
        },
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False
    assert result.plan is None

    codes = {
        issue.code
        for issue in result.issues
    }

    assert (
        "ACTION_ENTITY_CONTRACT_VIOLATION"
        in codes
    )


def test_manual_process_inspect_with_pattern_rejected(
    validator,
):
    plan = OperationPlan(
        intent="process_inspection",
        action="inspect",
        executable="ps",
        arguments=["-p", "4321"],
        entities={
            "PATTERN": "nginx",
        },
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False
    assert result.plan is None

    codes = {
        issue.code
        for issue in result.issues
    }

    assert (
        "ACTION_ENTITY_CONTRACT_VIOLATION"
        in codes
    )


def test_manual_directory_size_without_path_rejected(
    validator,
):
    plan = OperationPlan(
        intent="storage_inspection",
        action="directory_size",
        executable="du",
        arguments=["-sh", "--", "/tmp"],
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    result = validator.validate(plan)

    assert result.valid is False
    assert result.plan is None

    codes = {
        issue.code
        for issue in result.issues
    }

    assert (
        "ACTION_ENTITY_CONTRACT_VIOLATION"
        in codes
    )