import pytest

from intentx.validation.entity_semantics import (
    EntitySemanticValidator,
)
from intentx.validation.models import (
    ValidationIssue,
)


@pytest.fixture
def validator():
    return EntitySemanticValidator()


def test_valid_pid(validator):
    assert validator.validate(
        {"PID": "1234"}
    ) == []


def test_zero_pid_rejected(validator):
    issues = validator.validate(
        {"PID": "0"}
    )

    assert len(issues) == 1
    assert issues[0].code == "INVALID_PID"


def test_negative_pid_rejected(validator):
    issues = validator.validate(
        {"PID": "-10"}
    )

    assert issues[0].code == "INVALID_PID"


def test_valid_port(validator):
    assert validator.validate(
        {"PORT": "443"}
    ) == []


def test_port_zero_rejected(validator):
    issues = validator.validate(
        {"PORT": "0"}
    )

    assert issues[0].code == "INVALID_PORT"


def test_port_above_65535_rejected(
    validator,
):
    issues = validator.validate(
        {"PORT": "65536"}
    )

    assert issues[0].code == "INVALID_PORT"


def test_valid_numeric_permission(
    validator,
):
    assert validator.validate(
        {"PERMISSION": "644"}
    ) == []


def test_valid_four_digit_permission(
    validator,
):
    assert validator.validate(
        {"PERMISSION": "0755"}
    ) == []


def test_invalid_numeric_permission(
    validator,
):
    issues = validator.validate(
        {"PERMISSION": "999"}
    )

    assert (
        issues[0].code
        == "INVALID_PERMISSION"
    )


def test_valid_symbolic_permission(
    validator,
):
    assert validator.validate(
        {"PERMISSION": "u+rw"}
    ) == []


def test_valid_service_name(validator):
    assert validator.validate(
        {"SERVICE": "nginx.service"}
    ) == []


def test_invalid_service_name(
    validator,
):
    issues = validator.validate(
        {"SERVICE": "nginx;reboot"}
    )

    assert (
        issues[0].code
        == "INVALID_SERVICE"
    )


def test_valid_package_name(validator):
    assert validator.validate(
        {"PACKAGE": "python3-dev"}
    ) == []


def test_invalid_package_name(
    validator,
):
    issues = validator.validate(
        {"PACKAGE": "nginx && reboot"}
    )

    assert (
        issues[0].code
        == "INVALID_PACKAGE"
    )


def test_valid_username(validator):
    assert validator.validate(
        {"USERNAME": "alice"}
    ) == []


def test_invalid_username(validator):
    issues = validator.validate(
        {"USERNAME": "alice;root"}
    )

    assert (
        issues[0].code
        == "INVALID_USERNAME"
    )


def test_valid_device(validator):
    assert validator.validate(
        {"DEVICE": "/dev/sdb1"}
    ) == []


def test_invalid_device(validator):
    issues = validator.validate(
        {"DEVICE": "/tmp/disk.img"}
    )

    assert (
        issues[0].code
        == "INVALID_DEVICE"
    )


def test_valid_path(validator):
    assert validator.validate(
        {"PATH": "/tmp/report.txt"}
    ) == []


def test_path_beginning_with_dash_rejected(
    validator,
):
    issues = validator.validate(
        {"PATH": "-rf"}
    )

    assert (
        issues[0].code
        == "INVALID_PATH"
    )


def test_source_and_destination_valid(
    validator,
):
    issues = validator.validate(
        {
            "SOURCE_PATH": "/tmp/a.txt",
            "DESTINATION_PATH": "/tmp/b.txt",
        }
    )

    assert issues == []


def test_valid_pattern(validator):
    assert validator.validate(
        {"PATTERN": "ERROR"}
    ) == []


def test_control_character_rejected(
    validator,
):
    issues = validator.validate(
        {"PACKAGE": "nginx\nreboot"}
    )

    assert (
        issues[0].code
        == "CONTROL_CHARACTER"
    )


def test_unknown_entity_fails_closed(
    validator,
):
    issues = validator.validate(
        {"MADE_UP_ENTITY": "something"}
    )

    assert (
        issues[0].code
        == "UNSUPPORTED_ENTITY"
    )


def test_non_string_value_rejected(
    validator,
):
    issues = validator.validate(
        {"PID": 1234}
    )

    assert (
        issues[0].code
        == "INVALID_ENTITY_TYPE"
    )


def test_empty_entity_rejected(
    validator,
):
    issues = validator.validate(
        {"SERVICE": "   "}
    )

    assert issues[0].code == "EMPTY_ENTITY"


def test_entities_must_be_dictionary(
    validator,
):
    with pytest.raises(TypeError):
        validator.validate(
            ["PID", "1234"]
        )


def test_issue_type(validator):
    issues = validator.validate(
        {"PID": "invalid"}
    )

    assert isinstance(
        issues[0],
        ValidationIssue,
    )
def test_valid_nested_mapper_device(
    validator,
):
    issues = validator.validate(
        {
            "DEVICE": "/dev/mapper/vg-root",
        }
    )

    assert issues == []


def test_valid_nested_disk_by_id_device(
    validator,
):
    issues = validator.validate(
        {
            "DEVICE": (
                "/dev/disk/by-id/example"
            ),
        }
    )

    assert issues == []


def test_device_parent_traversal_rejected(
    validator,
):
    issues = validator.validate(
        {
            "DEVICE": "/dev/../etc/passwd",
        }
    )

    assert any(
        issue.code == "INVALID_DEVICE"
        for issue in issues
    )


def test_device_current_directory_rejected(
    validator,
):
    issues = validator.validate(
        {
            "DEVICE": "/dev/./sdb",
        }
    )

    assert any(
        issue.code == "INVALID_DEVICE"
        for issue in issues
    )


def test_device_empty_component_rejected(
    validator,
):
    issues = validator.validate(
        {
            "DEVICE": "/dev//sdb",
        }
    )

    assert any(
        issue.code == "INVALID_DEVICE"
        for issue in issues
    )


def test_empty_dev_path_rejected(
    validator,
):
    issues = validator.validate(
        {
            "DEVICE": "/dev/",
        }
    )

    assert any(
        issue.code == "INVALID_DEVICE"
        for issue in issues
    )


def test_device_outside_dev_rejected(
    validator,
):
    issues = validator.validate(
        {
            "DEVICE": "/etc/sdb",
        }
    )

    assert any(
        issue.code == "INVALID_DEVICE"
        for issue in issues
    )