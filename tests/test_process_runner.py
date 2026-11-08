from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import MagicMock, patch
import io
import subprocess
import signal

import pytest
import yaml

from intentx.execution.process_runner import (
    ALLOWED_PROCESS_ENVIRONMENT_VARIABLES,
    DEFAULT_POLICY_PATH,
    MAX_OUTPUT_BYTES,
    MAX_TIMEOUT_SECONDS,
    ProcessExecutionRequest,
    ProcessLaunchError,
    ProcessExecutionResult,
    ProcessRunner,
    ProcessRuntimePolicy,
)


FIXED_PATH = (
    "/usr/local/sbin:"
    "/usr/local/bin:"
    "/usr/sbin:"
    "/usr/bin:"
    "/sbin:"
    "/bin"
)


FIXED_ENVIRONMENT = {
    "PATH": FIXED_PATH,
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def make_request(**overrides):
    values = {
        "executable_path": "/usr/bin/free",
        "arguments": ("-h",),
        "timeout_seconds": 10,
        "stdout_max_bytes": 65536,
        "stderr_max_bytes": 65536,
    }

    values.update(overrides)

    return ProcessExecutionRequest(
        **values
    )


def make_runner():
    return ProcessRunner()


def load_default_policy():
    with Path(DEFAULT_POLICY_PATH).open(
        "r",
        encoding="utf-8",
    ) as handle:
        policy = yaml.safe_load(handle)

    return deepcopy(policy)


def write_policy(
    tmp_path,
    policy,
):
    policy_path = (
        tmp_path
        / "security_policy.yaml"
    )

    policy_path.write_text(
        yaml.safe_dump(
            policy,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    return policy_path


def make_result(**overrides):
    values = {
        "return_code": 0,
        "stdout": b"output",
        "stderr": b"",
        "timed_out": False,
        "duration_ms": 5,
        "metadata": {
            "source": "test",
        },
    }

    values.update(overrides)

    return ProcessExecutionResult(
        **values
    )


# ============================================================
# ProcessExecutionRequest
# ============================================================


def test_process_request_valid():
    request = make_request()

    assert (
        request.executable_path
        == "/usr/bin/free"
    )
    assert request.arguments == ("-h",)
    assert request.timeout_seconds == 10
    assert request.stdout_max_bytes == 65536
    assert request.stderr_max_bytes == 65536


def test_process_request_does_not_have_environment():
    request = make_request()

    assert not hasattr(
        request,
        "environment",
    )


def test_process_request_cannot_accept_environment():
    with pytest.raises(
        TypeError
    ):
        ProcessExecutionRequest(
            executable_path="/usr/bin/free",
            arguments=("-h",),
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            environment=FIXED_ENVIRONMENT,
        )


def test_process_request_is_frozen():
    request = make_request()

    with pytest.raises(
        FrozenInstanceError
    ):
        request.timeout_seconds = 20


def test_arguments_are_defensively_copied():
    arguments = ["-h"]

    request = make_request(
        arguments=arguments,
    )

    arguments.append(
        "--unexpected"
    )

    assert request.arguments == ("-h",)


def test_arguments_become_tuple():
    request = make_request(
        arguments=[
            "-h",
            "--example",
        ]
    )

    assert request.arguments == (
        "-h",
        "--example",
    )

    assert isinstance(
        request.arguments,
        tuple,
    )


def test_argv_returns_fresh_copy():
    request = make_request()

    first = request.argv
    second = request.argv

    assert first == [
        "/usr/bin/free",
        "-h",
    ]

    assert second == first
    assert second is not first

    first.append(
        "unexpected"
    )

    assert request.argv == [
        "/usr/bin/free",
        "-h",
    ]


def test_request_to_dict():
    request = make_request()

    result = request.to_dict()

    assert result == {
        "executable_path":
            "/usr/bin/free",
        "arguments":
            ["-h"],
        "argv":
            [
                "/usr/bin/free",
                "-h",
            ],
        "timeout_seconds":
            10,
        "stdout_max_bytes":
            65536,
        "stderr_max_bytes":
            65536,
    }


def test_request_to_dict_returns_defensive_values():
    request = make_request()

    first = request.to_dict()

    first["arguments"].append(
        "unexpected"
    )

    first["argv"].append(
        "unexpected"
    )

    second = request.to_dict()

    assert second[
        "arguments"
    ] == ["-h"]

    assert second["argv"] == [
        "/usr/bin/free",
        "-h",
    ]


# ============================================================
# Executable validation
# ============================================================


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        [],
    ],
)
def test_executable_requires_string(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_request(
            executable_path=value,
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "\t",
        "\n",
    ],
)
def test_executable_rejects_empty_value(
    value,
):
    with pytest.raises(
        ValueError
    ):
        make_request(
            executable_path=value,
        )


@pytest.mark.parametrize(
    "value",
    [
        "free",
        "./free",
        "../bin/free",
        "usr/bin/free",
    ],
)
def test_executable_must_be_absolute(
    value,
):
    with pytest.raises(
        ValueError,
        match="absolute",
    ):
        make_request(
            executable_path=value,
        )


def test_executable_rejects_nul():
    with pytest.raises(
        ValueError,
        match="NUL",
    ):
        make_request(
            executable_path=(
                "/usr/bin/fr\x00ee"
            ),
        )


def test_absolute_executable_is_allowed():
    request = make_request(
        executable_path="/bin/ps",
    )

    assert (
        request.executable_path
        == "/bin/ps"
    )


# ============================================================
# Argument validation
# ============================================================


def test_empty_arguments_allowed():
    request = make_request(
        arguments=(),
    )

    assert request.arguments == ()


@pytest.mark.parametrize(
    "value",
    [
        "single string",
        b"bytes",
        bytearray(b"bytes"),
    ],
)
def test_arguments_reject_string_like_containers(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_request(
            arguments=value,
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        {"argument": "value"},
        {"one", "two"},
    ],
)
def test_arguments_require_sequence(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_request(
            arguments=value,
        )


@pytest.mark.parametrize(
    "value",
    [
        123,
        True,
        None,
        b"bytes",
    ],
)
def test_argument_elements_require_strings(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_request(
            arguments=(
                value,
            ),
        )


def test_empty_argument_string_allowed():
    request = make_request(
        arguments=("",)
    )

    assert request.arguments == ("",)


def test_argument_rejects_nul():
    with pytest.raises(
        ValueError,
        match="NUL",
    ):
        make_request(
            arguments=(
                "hello\x00world",
            )
        )


def test_arguments_remain_structured():
    request = make_request(
        executable_path="/usr/bin/find",
        arguments=(
            "/tmp/example path",
            "-name",
            "*.log",
        ),
    )

    assert request.argv == [
        "/usr/bin/find",
        "/tmp/example path",
        "-name",
        "*.log",
    ]


def test_shell_metacharacters_remain_literal():
    request = make_request(
        executable_path="/usr/bin/printf",
        arguments=(
            "%s",
            "hello; rm -rf /",
        ),
    )

    assert request.argv == [
        "/usr/bin/printf",
        "%s",
        "hello; rm -rf /",
    ]


# ============================================================
# Runtime limits
# ============================================================


@pytest.mark.parametrize(
    "field_name",
    [
        "timeout_seconds",
        "stdout_max_bytes",
        "stderr_max_bytes",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        None,
        "10",
        1.5,
        True,
        False,
    ],
)
def test_runtime_limits_require_integer(
    field_name,
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_request(
            **{
                field_name: value,
            }
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "timeout_seconds",
        "stdout_max_bytes",
        "stderr_max_bytes",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        0,
        -1,
        -100,
    ],
)
def test_runtime_limits_require_positive_value(
    field_name,
    value,
):
    with pytest.raises(
        ValueError
    ):
        make_request(
            **{
                field_name: value,
            }
        )


def test_runtime_limits_preserved():
    request = make_request(
        timeout_seconds=7,
        stdout_max_bytes=1024,
        stderr_max_bytes=2048,
    )

    assert request.timeout_seconds == 7
    assert request.stdout_max_bytes == 1024
    assert request.stderr_max_bytes == 2048


# ============================================================
# ProcessRunner authoritative runtime policy
# ============================================================


def test_allowed_environment_names_are_exact():
    assert (
        ALLOWED_PROCESS_ENVIRONMENT_VARIABLES
        == frozenset(
            {
                "PATH",
                "LANG",
                "LC_ALL",
            }
        )
    )


def test_maximum_runtime_safety_caps_are_fixed():
    assert MAX_TIMEOUT_SECONDS == 30
    assert MAX_OUTPUT_BYTES == 1024 * 1024


def test_runner_loads_default_runtime_policy():
    runner = make_runner()

    assert runner.timeout_seconds == 10
    assert runner.stdout_max_bytes == 65536
    assert runner.stderr_max_bytes == 65536


def test_runner_loads_default_fixed_environment():
    runner = make_runner()

    assert dict(
        runner.fixed_environment
    ) == FIXED_ENVIRONMENT


def test_runner_runtime_policy_is_immutable():
    runner = make_runner()

    with pytest.raises(
        FrozenInstanceError
    ):
        runner.runtime_policy.timeout_seconds = 20


def test_runner_environment_is_immutable():
    runner = make_runner()

    with pytest.raises(
        TypeError
    ):
        runner.fixed_environment[
            "PATH"
        ] = "/tmp"


def test_runtime_policy_environment_is_defensively_copied():
    environment = dict(
        FIXED_ENVIRONMENT
    )

    policy = ProcessRuntimePolicy(
        timeout_seconds=10,
        stdout_max_bytes=65536,
        stderr_max_bytes=65536,
        fixed_environment=environment,
    )

    environment["PATH"] = "/tmp"

    assert (
        policy.fixed_environment[
            "PATH"
        ]
        == FIXED_PATH
    )


def test_runtime_policy_to_dict_returns_defensive_environment():
    policy = ProcessRuntimePolicy(
        timeout_seconds=10,
        stdout_max_bytes=65536,
        stderr_max_bytes=65536,
        fixed_environment=FIXED_ENVIRONMENT,
    )

    first = policy.to_dict()
    first["fixed_environment"]["PATH"] = "/tmp"

    second = policy.to_dict()

    assert (
        second["fixed_environment"]["PATH"]
        == FIXED_PATH
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "timeout_seconds",
        "stdout_max_bytes",
        "stderr_max_bytes",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        None,
        "10",
        1.5,
        True,
        False,
    ],
)
def test_runtime_policy_limits_require_integer(
    field_name,
    value,
):
    values = {
        "timeout_seconds": 10,
        "stdout_max_bytes": 65536,
        "stderr_max_bytes": 65536,
        "fixed_environment": FIXED_ENVIRONMENT,
    }

    values[field_name] = value

    with pytest.raises(
        TypeError
    ):
        ProcessRuntimePolicy(
            **values
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "timeout_seconds",
        "stdout_max_bytes",
        "stderr_max_bytes",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        0,
        -1,
        -100,
    ],
)
def test_runtime_policy_limits_require_positive_value(
    field_name,
    value,
):
    values = {
        "timeout_seconds": 10,
        "stdout_max_bytes": 65536,
        "stderr_max_bytes": 65536,
        "fixed_environment": FIXED_ENVIRONMENT,
    }

    values[field_name] = value

    with pytest.raises(
        ValueError
    ):
        ProcessRuntimePolicy(
            **values
        )


def test_runtime_policy_rejects_timeout_above_safe_cap():
    with pytest.raises(
        ValueError,
        match="maximum safe timeout",
    ):
        ProcessRuntimePolicy(
            timeout_seconds=(
                MAX_TIMEOUT_SECONDS + 1
            ),
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=FIXED_ENVIRONMENT,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "stdout_max_bytes",
        "stderr_max_bytes",
    ],
)
def test_runtime_policy_rejects_output_above_safe_cap(
    field_name,
):
    values = {
        "timeout_seconds": 10,
        "stdout_max_bytes": 65536,
        "stderr_max_bytes": 65536,
        "fixed_environment": FIXED_ENVIRONMENT,
    }

    values[field_name] = (
        MAX_OUTPUT_BYTES + 1
    )

    with pytest.raises(
        ValueError,
        match="maximum safe output limit",
    ):
        ProcessRuntimePolicy(
            **values
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        [],
        "PATH=/usr/bin",
    ],
)
def test_runtime_policy_environment_requires_mapping(
    value,
):
    with pytest.raises(
        TypeError
    ):
        ProcessRuntimePolicy(
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=value,
        )


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {
            "PATH": FIXED_PATH,
        },
        {
            "PATH": FIXED_PATH,
            "LANG": "C.UTF-8",
        },
        {
            "PATH": FIXED_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": "/tmp",
        },
        {
            "PATH": FIXED_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_PRELOAD": "/tmp/evil.so",
        },
    ],
)
def test_runtime_policy_environment_requires_exact_keys(
    environment,
):
    with pytest.raises(
        ValueError,
        match="exactly",
    ):
        ProcessRuntimePolicy(
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=environment,
        )


@pytest.mark.parametrize(
    "key",
    [
        "PATH",
        "LANG",
        "LC_ALL",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        b"bytes",
    ],
)
def test_runtime_policy_environment_values_require_strings(
    key,
    value,
):
    environment = dict(
        FIXED_ENVIRONMENT
    )

    environment[key] = value

    with pytest.raises(
        TypeError
    ):
        ProcessRuntimePolicy(
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=environment,
        )


@pytest.mark.parametrize(
    "key",
    [
        "PATH",
        "LANG",
        "LC_ALL",
    ],
)
def test_runtime_policy_environment_values_reject_nul(
    key,
):
    environment = dict(
        FIXED_ENVIRONMENT
    )

    environment[key] = "value\x00bad"

    with pytest.raises(
        ValueError,
        match="NUL",
    ):
        ProcessRuntimePolicy(
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=environment,
        )


@pytest.mark.parametrize(
    "key",
    [
        "PATH",
        "LANG",
        "LC_ALL",
    ],
)
def test_runtime_policy_environment_values_reject_empty(
    key,
):
    environment = dict(
        FIXED_ENVIRONMENT
    )

    environment[key] = ""

    with pytest.raises(
        ValueError,
        match="empty",
    ):
        ProcessRuntimePolicy(
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=environment,
        )


@pytest.mark.parametrize(
    "path_value",
    [
        "usr/bin:/bin",
        "./bin:/usr/bin",
        ".:/usr/bin",
        "../bin:/usr/bin",
    ],
)
def test_runtime_policy_path_rejects_relative_components(
    path_value,
):
    environment = dict(
        FIXED_ENVIRONMENT
    )

    environment["PATH"] = path_value

    with pytest.raises(
        ValueError,
        match="absolute",
    ):
        ProcessRuntimePolicy(
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=environment,
        )


@pytest.mark.parametrize(
    "path_value",
    [
        "",
        ":/usr/bin",
        "/usr/bin:",
        "/usr/bin::/bin",
    ],
)
def test_runtime_policy_path_rejects_empty_components(
    path_value,
):
    environment = dict(
        FIXED_ENVIRONMENT
    )

    environment["PATH"] = path_value

    with pytest.raises(
        ValueError
    ):
        ProcessRuntimePolicy(
            timeout_seconds=10,
            stdout_max_bytes=65536,
            stderr_max_bytes=65536,
            fixed_environment=environment,
        )


def test_runner_rejects_missing_policy_file(
    tmp_path,
):
    missing_path = (
        tmp_path
        / "missing-security-policy.yaml"
    )

    with pytest.raises(
        FileNotFoundError,
        match="Security policy not found",
    ):
        ProcessRunner(
            policy_path=missing_path
        )


def test_runner_rejects_non_mapping_policy(
    tmp_path,
):
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "- not\n- a\n- mapping\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="YAML mapping",
    ):
        ProcessRunner(
            policy_path=policy_path
        )


@pytest.mark.parametrize(
    "control_name",
    [
        "require_intent_validation",
        "require_entity_validation",
        "require_risk_assessment",
        "require_policy_evaluation",
        "require_allowlisted_executable",
        "require_validated_arguments",
        "execution_timeout_required",
        "output_limit_required",
        "audit_record_required",
    ],
)
def test_runner_rejects_disabled_required_control(
    tmp_path,
    control_name,
):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][control_name] = False

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    with pytest.raises(
        ValueError,
        match=control_name,
    ):
        ProcessRunner(
            policy_path=policy_path
        )


def test_runner_rejects_enabled_shell_mode(
    tmp_path,
):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ]["shell_mode_allowed"] = True

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    with pytest.raises(
        ValueError,
        match="shell_mode_allowed",
    ):
        ProcessRunner(
            policy_path=policy_path
        )


def test_runner_rejects_parent_environment_inheritance(
    tmp_path,
):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][
        "process_environment"
    ][
        "inherit_parent_environment"
    ] = True

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    with pytest.raises(
        ValueError,
        match="inheritance",
    ):
        ProcessRunner(
            policy_path=policy_path
        )


def test_runner_rejects_timeout_above_safe_cap_from_policy(
    tmp_path,
):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][
        "runtime_limits"
    ][
        "timeout_seconds"
    ] = MAX_TIMEOUT_SECONDS + 1

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    with pytest.raises(
        ValueError,
        match="maximum safe timeout",
    ):
        ProcessRunner(
            policy_path=policy_path
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "stdout_max_bytes",
        "stderr_max_bytes",
    ],
)
def test_runner_rejects_output_above_safe_cap_from_policy(
    tmp_path,
    field_name,
):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][
        "runtime_limits"
    ][field_name] = MAX_OUTPUT_BYTES + 1

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    with pytest.raises(
        ValueError,
        match="maximum safe output limit",
    ):
        ProcessRunner(
            policy_path=policy_path
        )


def test_runner_rejects_unexpected_runtime_limit_key(
    tmp_path,
):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][
        "runtime_limits"
    ]["unexpected_limit"] = 1

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    with pytest.raises(
        ValueError,
        match="must contain exactly",
    ):
        ProcessRunner(
            policy_path=policy_path
        )


def test_runner_rejects_missing_fixed_environment(
    tmp_path,
):
    policy = load_default_policy()

    del policy[
        "execution_requirements"
    ][
        "process_environment"
    ][
        "fixed_environment"
    ]

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    with pytest.raises(
        ValueError,
        match="fixed_environment",
    ):
        ProcessRunner(
            policy_path=policy_path
        )


def test_matching_request_reaches_process_launch_boundary():
    runner = make_runner()

    process = MagicMock()
    process.stdout = io.BytesIO(b"output")
    process.stderr = io.BytesIO(b"")
    process.returncode = 0
    process.wait.return_value = 0

    with patch.object(
        runner,
        "_validate_executable_for_launch",
        return_value="/usr/bin/free",
    ), patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ) as popen:
        result = runner.run(
            make_request()
        )

    assert result.return_code == 0
    assert result.stdout == b"output"
    assert result.stderr == b""
    assert result.timed_out is False
    assert popen.call_count == 1


def test_runner_rejects_request_timeout_mismatch():
    runner = make_runner()

    with pytest.raises(
        ValueError,
        match="timeout_seconds",
    ):
        runner.run(
            make_request(
                timeout_seconds=11
            )
        )


def test_runner_rejects_request_stdout_limit_mismatch():
    runner = make_runner()

    with pytest.raises(
        ValueError,
        match="stdout_max_bytes",
    ):
        runner.run(
            make_request(
                stdout_max_bytes=65537
            )
        )


def test_runner_rejects_request_stderr_limit_mismatch():
    runner = make_runner()

    with pytest.raises(
        ValueError,
        match="stderr_max_bytes",
    ):
        runner.run(
            make_request(
                stderr_max_bytes=65537
            )
        )


def test_runner_reports_all_runtime_policy_mismatches():
    runner = make_runner()

    request = make_request(
        timeout_seconds=11,
        stdout_max_bytes=65537,
        stderr_max_bytes=65538,
    )

    with pytest.raises(
        ValueError
    ) as exc_info:
        runner.run(request)

    message = str(exc_info.value)

    assert "timeout_seconds" in message
    assert "stdout_max_bytes" in message
    assert "stderr_max_bytes" in message


# ============================================================
# ProcessExecutionResult
# ============================================================


def test_process_result_valid():
    result = make_result()

    assert result.return_code == 0
    assert result.stdout == b"output"
    assert result.stderr == b""
    assert result.timed_out is False
    assert result.duration_ms == 5
    assert result.metadata == {
        "source": "test",
    }


def test_process_result_is_frozen():
    result = make_result()

    with pytest.raises(
        FrozenInstanceError
    ):
        result.return_code = 1


@pytest.mark.parametrize(
    "value",
    [
        "0",
        1.5,
        True,
        False,
    ],
)
def test_return_code_requires_integer_or_none(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_result(
            return_code=value,
        )


def test_return_code_allows_none():
    result = make_result(
        return_code=None,
    )

    assert result.return_code is None


@pytest.mark.parametrize(
    "field_name",
    [
        "stdout",
        "stderr",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "text",
        bytearray(b"data"),
        None,
        123,
    ],
)
def test_process_output_requires_bytes(
    field_name,
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_result(
            **{
                field_name: value,
            }
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
def test_timed_out_requires_boolean(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_result(
            timed_out=value,
        )


@pytest.mark.parametrize(
    "value",
    [
        "5",
        1.5,
        True,
        False,
        None,
    ],
)
def test_duration_requires_integer(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_result(
            duration_ms=value,
        )


def test_duration_cannot_be_negative():
    with pytest.raises(
        ValueError
    ):
        make_result(
            duration_ms=-1,
        )


def test_zero_duration_allowed():
    result = make_result(
        duration_ms=0,
    )

    assert result.duration_ms == 0


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        [],
        "metadata",
    ],
)
def test_metadata_requires_mapping(
    value,
):
    with pytest.raises(
        TypeError
    ):
        make_result(
            metadata=value,
        )


def test_result_metadata_is_defensively_copied():
    metadata = {
        "source": "original",
    }

    result = make_result(
        metadata=metadata,
    )

    metadata["source"] = "changed"

    assert (
        result.metadata["source"]
        == "original"
    )


def test_result_metadata_is_immutable():
    result = make_result()

    with pytest.raises(
        TypeError
    ):
        result.metadata[
            "source"
        ] = "changed"


def test_timed_out_result_requires_none_return_code():
    with pytest.raises(
        ValueError
    ):
        make_result(
            return_code=1,
            timed_out=True,
        )


def test_valid_timed_out_result():
    result = make_result(
        return_code=None,
        timed_out=True,
        duration_ms=10000,
    )

    assert result.return_code is None
    assert result.timed_out is True


def test_result_to_dict_returns_defensive_metadata():
    result = make_result()

    first = result.to_dict()

    first["metadata"][
        "source"
    ] = "changed"

    second = result.to_dict()

    assert (
        second["metadata"]["source"]
        == "test"
    )


# ============================================================
# ProcessRunner execution boundary
# ============================================================


@pytest.mark.parametrize(
    "value",
    [
        None,
        "free -h",
        ["/usr/bin/free", "-h"],
        {},
        123,
    ],
)
def test_runner_rejects_wrong_request_type(
    value,
):
    runner = make_runner()

    with pytest.raises(
        TypeError
    ):
        runner.run(
            value
        )


def test_process_execution_uses_controlled_popen_boundary():
    runner = make_runner()

    process = MagicMock()
    process.stdout = io.BytesIO(b"hello")
    process.stderr = io.BytesIO(b"warning")
    process.returncode = 0
    process.wait.return_value = 0

    with patch.object(
        runner,
        "_validate_executable_for_launch",
        return_value="/usr/bin/free",
    ), patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ) as popen:
        result = runner.run(
            make_request()
        )

    popen.assert_called_once_with(
        ["/usr/bin/free", "-h"],
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=FIXED_ENVIRONMENT,
        text=False,
        close_fds=True,
        start_new_session=True,
    )

    process.wait.assert_called_once_with(
        timeout=10
    )

    assert result.return_code == 0
    assert result.stdout == b"hello"
    assert result.stderr == b"warning"
    assert result.timed_out is False
    assert result.metadata["shell"] is False
    assert (
        result.metadata[
            "parent_environment_inherited"
        ]
        is False
    )
    assert result.metadata["stdin"] == "DEVNULL"
    assert (
        result.metadata["start_new_session"]
        is True
    )


def test_raw_command_string_cannot_cross_boundary():
    runner = make_runner()

    with pytest.raises(
        TypeError
    ):
        runner.run(
            "free -h"
        )

# ============================================================
# Phase 9C controlled process execution
# ============================================================

@pytest.fixture
def mock_prelaunch_validation(monkeypatch):
    """
    Keep mocked process-boundary tests platform-independent.

    Linux's /usr/bin/free does not exist on macOS. These tests
    are intended to exercise Popen mechanics rather than the
    filesystem validator, so only that validator is mocked.

    Dedicated pre-launch validation tests below use the real
    implementation.
    """
    monkeypatch.setattr(
        ProcessRunner,
        "_validate_executable_for_launch",
        staticmethod(
            lambda executable_path: executable_path
        ),
    )




def make_mock_process(
    *,
    stdout=b"",
    stderr=b"",
    return_code=0,
):
    process = MagicMock()
    process.stdout = io.BytesIO(stdout)
    process.stderr = io.BytesIO(stderr)
    process.returncode = return_code
    process.pid = 4321
    process.wait.return_value = return_code
    return process


def test_runner_passes_structured_arguments_without_shell_parsing(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    request = make_request(
        executable_path="/usr/bin/free",
        arguments=(
            "literal;value",
            "$(not-a-shell)",
            "value with spaces",
        ),
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ) as popen:
        runner.run(request)

    assert popen.call_args.args[0] == [
        "/usr/bin/free",
        "literal;value",
        "$(not-a-shell)",
        "value with spaces",
    ]

    assert (
        popen.call_args.kwargs["shell"]
        is False
    )


def test_runner_uses_only_fixed_environment(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ) as popen:
        runner.run(
            make_request()
        )

    environment = (
        popen.call_args.kwargs["env"]
    )

    assert environment == FIXED_ENVIRONMENT
    assert set(environment) == {
        "PATH",
        "LANG",
        "LC_ALL",
    }


def test_runner_does_not_pass_parent_stdin(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ) as popen:
        runner.run(
            make_request()
        )

    assert (
        popen.call_args.kwargs["stdin"]
        is subprocess.DEVNULL
    )


def test_runner_creates_new_process_session(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ) as popen:
        runner.run(
            make_request()
        )

    assert (
        popen.call_args.kwargs[
            "start_new_session"
        ]
        is True
    )


def test_runner_closes_unneeded_file_descriptors(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ) as popen:
        runner.run(
            make_request()
        )

    assert (
        popen.call_args.kwargs["close_fds"]
        is True
    )


def test_runner_captures_stdout_and_stderr_independently(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process(
        stdout=b"stdout-data",
        stderr=b"stderr-data",
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ):
        result = runner.run(
            make_request()
        )

    assert result.stdout == b"stdout-data"
    assert result.stderr == b"stderr-data"

    assert (
        result.metadata[
            "stdout_original_bytes"
        ]
        == len(b"stdout-data")
    )

    assert (
        result.metadata[
            "stderr_original_bytes"
        ]
        == len(b"stderr-data")
    )


def test_runner_bounds_stdout_retention_while_tracking_original_size(tmp_path,
    mock_prelaunch_validation):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][
        "runtime_limits"
    ][
        "stdout_max_bytes"
    ] = 4

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    runner = ProcessRunner(
        policy_path=policy_path
    )

    process = make_mock_process(
        stdout=b"abcdefghij",
    )

    request = make_request(
        stdout_max_bytes=4,
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ):
        result = runner.run(request)

    assert result.stdout == b"abcd"

    assert (
        result.metadata[
            "stdout_original_bytes"
        ]
        == 10
    )

    assert (
        result.metadata[
            "stdout_retained_bytes"
        ]
        == 4
    )

    assert (
        result.metadata[
            "stdout_truncated"
        ]
        is True
    )


def test_runner_bounds_stderr_retention_while_tracking_original_size(tmp_path,
    mock_prelaunch_validation):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][
        "runtime_limits"
    ][
        "stderr_max_bytes"
    ] = 3

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    runner = ProcessRunner(
        policy_path=policy_path
    )

    process = make_mock_process(
        stderr=b"123456789",
    )

    request = make_request(
        stderr_max_bytes=3,
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ):
        result = runner.run(request)

    assert result.stderr == b"123"

    assert (
        result.metadata[
            "stderr_original_bytes"
        ]
        == 9
    )

    assert (
        result.metadata[
            "stderr_retained_bytes"
        ]
        == 3
    )

    assert (
        result.metadata[
            "stderr_truncated"
        ]
        is True
    )


def test_runner_marks_exact_limit_output_as_not_truncated(tmp_path,
    mock_prelaunch_validation):
    policy = load_default_policy()

    policy[
        "execution_requirements"
    ][
        "runtime_limits"
    ][
        "stdout_max_bytes"
    ] = 4

    policy_path = write_policy(
        tmp_path,
        policy,
    )

    runner = ProcessRunner(
        policy_path=policy_path
    )

    process = make_mock_process(
        stdout=b"abcd",
    )

    request = make_request(
        stdout_max_bytes=4,
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ):
        result = runner.run(request)

    assert result.stdout == b"abcd"

    assert (
        result.metadata[
            "stdout_truncated"
        ]
        is False
    )


def test_runner_nonzero_exit_is_process_result_not_launch_error(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process(
        stderr=b"operation failed",
        return_code=7,
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ):
        result = runner.run(
            make_request()
        )

    assert result.return_code == 7
    assert result.timed_out is False
    assert result.stderr == b"operation failed"


@pytest.mark.parametrize(
    "exception",
    [
        FileNotFoundError("missing"),
        PermissionError("denied"),
        OSError("os failure"),
        ValueError("bad popen input"),
        subprocess.SubprocessError(
            "subprocess failure"
        ),
    ],
)
def test_runner_wraps_process_creation_failures(exception,
    mock_prelaunch_validation):
    runner = make_runner()

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        side_effect=exception,
    ):
        with pytest.raises(
            ProcessLaunchError,
            match="process launch failed",
        ):
            runner.run(
                make_request()
            )


def test_runner_rejects_missing_executable_before_popen(
    tmp_path,
):
    runner = make_runner()

    missing = (
        tmp_path
        / "missing-executable"
    )

    request = make_request(
        executable_path=str(
            missing.resolve()
        ),
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
    ) as popen:
        with pytest.raises(
            ProcessLaunchError,
            match="does not exist",
        ):
            runner.run(request)

    popen.assert_not_called()


def test_runner_rejects_non_executable_file_before_popen(
    tmp_path,
):
    runner = make_runner()

    executable = (
        tmp_path
        / "not-executable"
    )

    executable.write_text(
        "test",
        encoding="utf-8",
    )

    executable.chmod(0o600)

    request = make_request(
        executable_path=str(
            executable.resolve()
        ),
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
    ) as popen:
        with pytest.raises(
            ProcessLaunchError,
            match="not executable",
        ):
            runner.run(request)

    popen.assert_not_called()


def test_runner_rejects_directory_as_executable(
    tmp_path,
):
    runner = make_runner()

    directory = (
        tmp_path
        / "directory"
    )

    directory.mkdir()

    request = make_request(
        executable_path=str(
            directory.resolve()
        ),
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
    ) as popen:
        with pytest.raises(
            ProcessLaunchError,
            match="regular file",
        ):
            runner.run(request)

    popen.assert_not_called()


def test_runner_rejects_noncanonical_executable_path_before_popen(
    tmp_path,
):
    runner = make_runner()

    directory = tmp_path / "bin"
    directory.mkdir()

    executable = directory / "tool"
    executable.write_text(
    "#!/bin/sh\nexit 0\n",
    encoding="utf-8",
    )

    executable.chmod(0o700)

    noncanonical = (
        directory
        / ".."
        / "bin"
        / "tool"
    )

    request = make_request(
        executable_path=str(
            noncanonical
        ),
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
    ) as popen:
        with pytest.raises(
            ProcessLaunchError,
            match="changed",
        ):
            runner.run(request)

    popen.assert_not_called()


def test_runner_timeout_returns_timed_out_result(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process(
        stdout=b"partial-output",
        stderr=b"partial-error",
    )

    process.wait.side_effect = [
        subprocess.TimeoutExpired(
            cmd=["/usr/bin/free", "-h"],
            timeout=10,
        ),
        0,
    ]

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ), patch(
        "intentx.execution.process_runner.os.killpg",
    ) as killpg:
        result = runner.run(
            make_request()
        )

    assert result.timed_out is True
    assert result.return_code is None
    assert result.stdout == b"partial-output"
    assert result.stderr == b"partial-error"

    killpg.assert_called_once_with(
        4321,
        signal.SIGTERM,
    )


def test_runner_timeout_escalates_to_sigkill_after_grace_timeout(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    process.wait.side_effect = [
        subprocess.TimeoutExpired(
            cmd=["/usr/bin/free", "-h"],
            timeout=10,
        ),
        subprocess.TimeoutExpired(
            cmd=["/usr/bin/free", "-h"],
            timeout=1.0,
        ),
        0,
    ]

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ), patch(
        "intentx.execution.process_runner.os.killpg",
    ) as killpg:
        result = runner.run(
            make_request()
        )

    assert result.timed_out is True
    assert result.return_code is None

    assert killpg.call_args_list == [
        ((4321, signal.SIGTERM),),
        ((4321, signal.SIGKILL),),
    ]


def test_runner_timeout_falls_back_to_process_terminate(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    process.wait.side_effect = [
        subprocess.TimeoutExpired(
            cmd=["/usr/bin/free", "-h"],
            timeout=10,
        ),
        0,
    ]

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ), patch(
        "intentx.execution.process_runner.os.killpg",
        side_effect=ProcessLookupError,
    ):
        result = runner.run(
            make_request()
        )

    assert result.timed_out is True
    process.terminate.assert_called_once_with()


def test_runner_timeout_falls_back_to_process_kill_on_sigkill_failure(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    process.wait.side_effect = [
        subprocess.TimeoutExpired(
            cmd=["/usr/bin/free", "-h"],
            timeout=10,
        ),
        subprocess.TimeoutExpired(
            cmd=["/usr/bin/free", "-h"],
            timeout=1.0,
        ),
        0,
    ]

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ), patch(
        "intentx.execution.process_runner.os.killpg",
        side_effect=[
            None,
            ProcessLookupError,
        ],
    ):
        result = runner.run(
            make_request()
        )

    assert result.timed_out is True
    process.kill.assert_called_once_with()


def test_runner_rejects_missing_stdout_pipe_after_launch(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()
    process.stdout = None

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ), patch.object(
        runner,
        "_terminate_process_group",
    ) as terminate:
        with pytest.raises(
            ProcessLaunchError,
            match="output pipes",
        ):
            runner.run(
                make_request()
            )

    terminate.assert_called_once_with(
        process
    )


def test_runner_rejects_missing_stderr_pipe_after_launch(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()
    process.stderr = None

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ), patch.object(
        runner,
        "_terminate_process_group",
    ) as terminate:
        with pytest.raises(
            ProcessLaunchError,
            match="output pipes",
        ):
            runner.run(
                make_request()
            )

    terminate.assert_called_once_with(
        process
    )


def test_runner_duration_is_nonnegative(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process()

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ):
        result = runner.run(
            make_request()
        )

    assert result.duration_ms >= 0


def test_runner_result_metadata_reports_untruncated_output(
    mock_prelaunch_validation
):
    runner = make_runner()

    process = make_mock_process(
        stdout=b"abc",
        stderr=b"xy",
    )

    with patch(
        "intentx.execution.process_runner.subprocess.Popen",
        return_value=process,
    ):
        result = runner.run(
            make_request()
        )

    assert result.metadata == {
        "stdout_original_bytes": 3,
        "stdout_retained_bytes": 3,
        "stdout_truncated": False,
        "stderr_original_bytes": 2,
        "stderr_retained_bytes": 2,
        "stderr_truncated": False,
        "shell": False,
        "parent_environment_inherited": False,
        "stdin": "DEVNULL",
        "start_new_session": True,
    }
