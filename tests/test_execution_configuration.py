from pathlib import Path

import pytest
import yaml


POLICY_PATH = Path(
    "configs/security_policy.yaml"
)


@pytest.fixture(scope="module")
def security_policy():
    with POLICY_PATH.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def execution_requirements(
    security_policy,
):
    return security_policy[
        "execution_requirements"
    ]


@pytest.fixture(scope="module")
def runtime_limits(
    execution_requirements,
):
    return execution_requirements[
        "runtime_limits"
    ]


@pytest.fixture(scope="module")
def process_environment(
    execution_requirements,
):
    return execution_requirements[
        "process_environment"
    ]


# ============================================================
# Core execution requirements
# ============================================================


def test_execution_requirements_exist(
    security_policy,
):
    assert "execution_requirements" in security_policy


@pytest.mark.parametrize(
    "requirement",
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
def test_required_execution_controls_are_enabled(
    execution_requirements,
    requirement,
):
    assert (
        execution_requirements[
            requirement
        ]
        is True
    )


def test_shell_mode_is_disabled(
    execution_requirements,
):
    assert (
        execution_requirements[
            "shell_mode_allowed"
        ]
        is False
    )


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
def test_runtime_limits_are_positive_integers(
    runtime_limits,
    field_name,
):
    value = runtime_limits[
        field_name
    ]

    assert isinstance(value, int)
    assert not isinstance(value, bool)
    assert value > 0


def test_execution_timeout_is_exactly_ten_seconds(
    runtime_limits,
):
    assert (
        runtime_limits[
            "timeout_seconds"
        ]
        == 10
    )


def test_execution_timeout_has_safe_upper_bound(
    runtime_limits,
):
    assert (
        runtime_limits[
            "timeout_seconds"
        ]
        <= 30
    )


def test_stdout_limit_is_64_kib(
    runtime_limits,
):
    assert (
        runtime_limits[
            "stdout_max_bytes"
        ]
        == 65536
    )


def test_stderr_limit_is_64_kib(
    runtime_limits,
):
    assert (
        runtime_limits[
            "stderr_max_bytes"
        ]
        == 65536
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "stdout_max_bytes",
        "stderr_max_bytes",
    ],
)
def test_output_limits_have_safe_upper_bound(
    runtime_limits,
    field_name,
):
    assert (
        runtime_limits[field_name]
        <= 1024 * 1024
    )


# ============================================================
# Process environment
# ============================================================


def test_process_environment_exists(
    execution_requirements,
):
    assert (
        "process_environment"
        in execution_requirements
    )


def test_parent_environment_is_not_inherited(
    process_environment,
):
    assert (
        process_environment[
            "inherit_parent_environment"
        ]
        is False
    )


def test_legacy_environment_allowlist_is_removed(
    process_environment,
):
    assert (
        "allowed_environment_variables"
        not in process_environment
    )


# ============================================================
# Trusted executable directories
# ============================================================


def test_trusted_executable_directories_are_exact(
    process_environment,
):
    assert process_environment[
        "trusted_executable_directories"
    ] == [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]


def test_trusted_executable_directories_are_nonempty_strings(
    process_environment,
):
    directories = process_environment[
        "trusted_executable_directories"
    ]

    assert directories

    for directory in directories:
        assert isinstance(
            directory,
            str,
        )
        assert directory.strip()


def test_trusted_executable_directories_are_absolute(
    process_environment,
):
    directories = process_environment[
        "trusted_executable_directories"
    ]

    for directory in directories:
        assert Path(
            directory
        ).is_absolute()


def test_trusted_executable_directories_have_no_duplicates(
    process_environment,
):
    directories = process_environment[
        "trusted_executable_directories"
    ]

    assert (
        len(directories)
        == len(set(directories))
    )


@pytest.mark.parametrize(
    "dangerous_directory",
    [
        ".",
        "..",
        "/tmp",
        "/var/tmp",
        "/private/tmp",
        "/Users",
        "/home",
    ],
)
def test_untrusted_writable_locations_are_not_trusted(
    process_environment,
    dangerous_directory,
):
    directories = process_environment[
        "trusted_executable_directories"
    ]

    assert (
        dangerous_directory
        not in directories
    )


# ============================================================
# Fixed process environment
# ============================================================


def test_fixed_environment_exists(
    process_environment,
):
    assert (
        "fixed_environment"
        in process_environment
    )


def test_fixed_environment_is_exact(
    process_environment,
):
    fixed = process_environment[
        "fixed_environment"
    ]

    assert fixed == {
        "PATH": (
            "/usr/local/sbin:"
            "/usr/local/bin:"
            "/usr/sbin:"
            "/usr/bin:"
            "/sbin:"
            "/bin"
        ),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def test_fixed_environment_contains_only_strings(
    process_environment,
):
    fixed = process_environment[
        "fixed_environment"
    ]

    for key, value in fixed.items():
        assert isinstance(key, str)
        assert key.strip()

        assert isinstance(value, str)
        assert value.strip()


def test_fixed_path_matches_trusted_directories(
    process_environment,
):
    directories = process_environment[
        "trusted_executable_directories"
    ]

    fixed_path = process_environment[
        "fixed_environment"
    ]["PATH"]

    assert (
        fixed_path.split(":")
        == directories
    )


def test_fixed_path_contains_no_empty_component(
    process_environment,
):
    fixed_path = process_environment[
        "fixed_environment"
    ]["PATH"]

    assert all(
        component
        for component
        in fixed_path.split(":")
    )


def test_fixed_path_contains_no_relative_component(
    process_environment,
):
    fixed_path = process_environment[
        "fixed_environment"
    ]["PATH"]

    for component in (
        fixed_path.split(":")
    ):
        assert Path(
            component
        ).is_absolute()


@pytest.mark.parametrize(
    "dangerous_component",
    [
        ".",
        "..",
        "/tmp",
        "/var/tmp",
        "/private/tmp",
        "/Users",
        "/home",
    ],
)
def test_fixed_path_excludes_untrusted_locations(
    process_environment,
    dangerous_component,
):
    components = process_environment[
        "fixed_environment"
    ]["PATH"].split(":")

    assert (
        dangerous_component
        not in components
    )


# ============================================================
# Sensitive environment isolation
# ============================================================


@pytest.mark.parametrize(
    "dangerous_name",
    [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DATABASE_URL",
        "SSH_AUTH_SOCK",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    ],
)
def test_sensitive_or_process_influencing_variables_are_absent(
    process_environment,
    dangerous_name,
):
    fixed = process_environment[
        "fixed_environment"
    ]

    assert (
        dangerous_name
        not in fixed
    )


def test_fixed_environment_has_only_expected_keys(
    process_environment,
):
    fixed = process_environment[
        "fixed_environment"
    ]

    assert set(
        fixed.keys()
    ) == {
        "PATH",
        "LANG",
        "LC_ALL",
    }


# ============================================================
# Pre-execution security chain
# ============================================================


def test_complete_preexecution_chain_is_required(
    execution_requirements,
):
    required_chain = {
        "require_intent_validation": True,
        "require_entity_validation": True,
        "require_risk_assessment": True,
        "require_policy_evaluation": True,
        "require_allowlisted_executable": True,
        "require_validated_arguments": True,
    }

    for (
        requirement,
        expected_value,
    ) in required_chain.items():
        assert (
            execution_requirements[
                requirement
            ]
            is expected_value
        )


def test_execution_safety_controls_are_all_required(
    execution_requirements,
):
    required_controls = {
        "shell_mode_allowed": False,
        "execution_timeout_required": True,
        "output_limit_required": True,
        "audit_record_required": True,
    }

    for (
        requirement,
        expected_value,
    ) in required_controls.items():
        assert (
            execution_requirements[
                requirement
            ]
            is expected_value
        )