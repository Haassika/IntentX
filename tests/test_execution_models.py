from dataclasses import FrozenInstanceError

import pytest

from intentx.execution.models import (
    ExecutionRequest,
    ExecutionResult,
    VALID_EXECUTION_STATUSES,
)


def make_request(**overrides):
    values = {
        "execution_id": "exec-test-001",
        "role": "VIEWER",
        "environment": "DEV",
        "intent": "memory_inspection",
        "action": "memory_usage",
        "executable": "free",
        "arguments": ("-h",),
    }
    values.update(overrides)
    return ExecutionRequest(**values)


def make_result(**overrides):
    values = {
        "execution_id": "exec-test-001",
        "status": "BLOCKED",
        "executable": "free",
        "arguments": ("-h",),
        "return_code": None,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "reason_code": "TEST_REASON",
        "reason": "Deterministic execution test.",
        "metadata": {"test": True},
    }
    values.update(overrides)
    return ExecutionResult(**values)


def test_valid_execution_statuses_are_exact():
    assert VALID_EXECUTION_STATUSES == frozenset(
        {
            "EXECUTED",
            "BLOCKED",
            "FAILED",
            "TIMED_OUT",
        }
    )


def test_execution_request_is_immutable():
    request = make_request()

    with pytest.raises(FrozenInstanceError):
        request.role = "ADMINISTRATOR"


def test_execution_request_arguments_are_converted_to_tuple():
    arguments = ["-h"]

    request = make_request(
        arguments=arguments,
    )

    arguments.append("--changed")

    assert request.arguments == ("-h",)


def test_execution_request_argv_is_defensive_copy():
    request = make_request()

    argv = request.argv
    argv.append("MUTATION")

    assert request.argv == [
        "free",
        "-h",
    ]


def test_execution_request_to_dict_is_defensive():
    request = make_request()

    data = request.to_dict()

    data["arguments"].append("MUTATION")
    data["argv"].append("MUTATION")

    assert request.arguments == ("-h",)
    assert request.argv == [
        "free",
        "-h",
    ]


@pytest.mark.parametrize(
    "field_name",
    [
        "execution_id",
        "role",
        "environment",
        "intent",
        "action",
        "executable",
    ],
)
def test_execution_request_rejects_empty_required_strings(
    field_name,
):
    with pytest.raises(ValueError):
        make_request(
            **{field_name: "   "}
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "execution_id",
        "role",
        "environment",
        "intent",
        "action",
        "executable",
    ],
)
def test_execution_request_rejects_non_string_required_fields(
    field_name,
):
    with pytest.raises(TypeError):
        make_request(
            **{field_name: 123}
        )


def test_execution_request_rejects_non_string_argument():
    with pytest.raises(TypeError):
        make_request(
            arguments=(
                "-h",
                123,
            )
        )


def test_execution_result_is_immutable():
    result = make_result()

    with pytest.raises(FrozenInstanceError):
        result.status = "EXECUTED"


def test_execution_result_normalizes_status():
    result = make_result(
        status=" blocked ",
    )

    assert result.status == "BLOCKED"


def test_execution_result_rejects_unknown_status():
    with pytest.raises(ValueError):
        make_result(
            status="UNKNOWN",
        )


def test_execution_result_arguments_are_defensive():
    arguments = ["-h"]

    result = make_result(
        arguments=arguments,
    )

    arguments.append("MUTATION")

    assert result.arguments == ("-h",)


def test_execution_result_metadata_is_immutable():
    result = make_result()

    with pytest.raises(TypeError):
        result.metadata["changed"] = True


def test_execution_result_metadata_is_defensively_copied():
    metadata = {
        "test": True,
    }

    result = make_result(
        metadata=metadata,
    )

    metadata["changed"] = True

    assert dict(result.metadata) == {
        "test": True,
    }


def test_execution_result_to_dict_is_defensive():
    result = make_result()

    data = result.to_dict()

    data["arguments"].append("MUTATION")
    data["argv"].append("MUTATION")
    data["metadata"]["changed"] = True

    assert result.arguments == ("-h",)
    assert result.argv == [
        "free",
        "-h",
    ]
    assert dict(result.metadata) == {
        "test": True,
    }


def test_blocked_result_means_process_not_started():
    result = make_result(
        status="BLOCKED",
        return_code=None,
    )

    assert result.process_started is False
    assert result.successful is False


@pytest.mark.parametrize(
    "status",
    [
        "EXECUTED",
        "FAILED",
        "TIMED_OUT",
    ],
)
def test_non_blocked_result_represents_process_boundary_crossed(
    status,
):
    result = make_result(
        status=status,
    )

    assert result.process_started is True


def test_successful_requires_executed_and_zero_return_code():
    result = make_result(
        status="EXECUTED",
        return_code=0,
    )

    assert result.successful is True


def test_nonzero_return_code_is_not_successful():
    result = make_result(
        status="EXECUTED",
        return_code=1,
    )

    assert result.successful is False


def test_failed_result_is_not_successful():
    result = make_result(
        status="FAILED",
        return_code=1,
    )

    assert result.successful is False


def test_timed_out_result_is_not_successful():
    result = make_result(
        status="TIMED_OUT",
        return_code=None,
    )

    assert result.successful is False


@pytest.mark.parametrize(
    "return_code",
    [
        True,
        False,
        "0",
        1.5,
    ],
)
def test_execution_result_rejects_invalid_return_code(
    return_code,
):
    with pytest.raises(TypeError):
        make_result(
            return_code=return_code,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "stdout_truncated",
        "stderr_truncated",
    ],
)
def test_execution_result_requires_boolean_truncation_flags(
    field_name,
):
    with pytest.raises(TypeError):
        make_result(
            **{field_name: 1}
        )


def test_execution_result_rejects_non_mapping_metadata():
    with pytest.raises(TypeError):
        make_result(
            metadata=[
                ("test", True),
            ]
        )


def test_execution_result_rejects_non_string_argument():
    with pytest.raises(TypeError):
        make_result(
            arguments=(
                "-h",
                123,
            )
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "execution_id",
        "executable",
        "reason_code",
        "reason",
    ],
)
def test_execution_result_rejects_empty_required_strings(
    field_name,
):
    with pytest.raises(ValueError):
        make_result(
            **{field_name: "   "}
        )