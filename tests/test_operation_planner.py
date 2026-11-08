from pathlib import Path

import pytest
import yaml

from intentx.planning.models import (
    OperationPlan,
)
from intentx.planning.planner import (
    OperationPlanner,
    PlanningResult,
)


@pytest.fixture
def planner():
    return OperationPlanner()


# =========================================================
# Core planning tests
# =========================================================


def test_restart_service_plan(planner):
    result = planner.plan(
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    assert result.planned is True
    assert result.decision == "PLAN_CREATED"

    assert result.plan.argv == [
        "systemctl",
        "restart",
        "nginx",
    ]


def test_service_plan_preserves_metadata(
    planner,
):
    result = planner.plan(
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    plan = result.plan

    assert plan.state_changing is True
    assert (
        plan.privilege_required
        == "conditional"
    )
    assert plan.critical_operation is False


def test_file_delete_plan(planner):
    result = planner.plan(
        "delete /tmp/report.txt",
        "file_delete",
        {"PATH": "/tmp/report.txt"},
    )

    assert result.planned is True

    assert result.plan.argv == [
        "rm",
        "--",
        "/tmp/report.txt",
    ]


def test_file_copy_plan(planner):
    result = planner.plan(
        "copy /tmp/a.txt to /tmp/b.txt",
        "file_copy",
        {
            "SOURCE_PATH": "/tmp/a.txt",
            "DESTINATION_PATH": "/tmp/b.txt",
        },
    )

    assert result.planned is True

    assert result.plan.argv == [
        "cp",
        "--",
        "/tmp/a.txt",
        "/tmp/b.txt",
    ]


def test_force_terminate_plan(planner):
    result = planner.plan(
        "force kill process 1234",
        "process_termination",
        {"PID": "1234"},
    )

    assert result.planned is True

    assert result.plan.argv == [
        "kill",
        "-KILL",
        "--",
        "1234",
    ]


def test_normal_terminate_plan(planner):
    result = planner.plan(
        "kill process 1234",
        "process_termination",
        {"PID": "1234"},
    )

    assert result.planned is True

    assert result.plan.argv == [
        "kill",
        "-TERM",
        "--",
        "1234",
    ]


def test_chmod_plan(planner):
    result = planner.plan(
        "chmod 644 /tmp/test.txt",
        "permission_change",
        {
            "PERMISSION": "644",
            "PATH": "/tmp/test.txt",
        },
    )

    assert result.planned is True

    assert result.plan.argv == [
        "chmod",
        "644",
        "--",
        "/tmp/test.txt",
    ]


def test_missing_service_fails_closed(
    planner,
):
    result = planner.plan(
        "restart nginx",
        "service_management",
        {},
    )

    assert result.planned is False

    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )

    assert result.plan is None


def test_ambiguous_action_fails_closed(
    planner,
):
    result = planner.plan(
        "manage nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    assert result.planned is False

    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )


def test_memory_plan(planner):
    result = planner.plan(
        "show memory usage",
        "memory_inspection",
        {},
    )

    assert result.planned is True

    assert result.plan.argv == [
        "free",
        "-h",
    ]


def test_system_power_marked_critical(
    planner,
):
    result = planner.plan(
        "reboot system",
        "system_power",
        {},
    )

    assert result.planned is True
    assert result.plan.critical_operation is True
    assert result.plan.state_changing is True

    assert (
        result.plan.privilege_required
        is True
    )

    # Planning is NOT authorization.
    assert result.decision == "PLAN_CREATED"


def test_disk_format_marked_critical(
    planner,
):
    result = planner.plan(
        "format /dev/sdb",
        "disk_management",
        {"DEVICE": "/dev/sdb"},
    )

    assert result.planned is True
    assert result.plan.critical_operation is True

    assert result.plan.argv == [
        "mkfs",
        "/dev/sdb",
    ]


def test_unknown_intent_rejected(
    planner,
):
    with pytest.raises(ValueError):
        planner.plan(
            "something",
            "made_up_intent",
            {},
        )


def test_entities_must_be_dictionary(
    planner,
):
    with pytest.raises(TypeError):
        planner.plan(
            "restart nginx",
            "service_management",
            ["nginx"],
        )


def test_result_type(planner):
    result = planner.plan(
        "show memory usage",
        "memory_inspection",
        {},
    )

    assert isinstance(
        result,
        PlanningResult,
    )

    assert isinstance(
        result.plan,
        OperationPlan,
    )


def test_planner_has_no_execution_method():
    prohibited = [
        "execute",
        "run",
        "run_command",
        "run_shell",
    ]

    for method in prohibited:
        assert not hasattr(
            OperationPlanner,
            method,
        )


# =========================================================
# Catalog/planner consistency
# =========================================================


def test_every_catalog_action_has_planner_support(
    planner,
):
    """
    Every executable-producing action declared
    by the intent catalog must have deterministic
    planner support.

    Shared actions such as 'list' are handled
    explicitly by the planner.
    """

    catalog_path = Path(
        "configs/intent_catalog.yaml"
    )

    with catalog_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        catalog = yaml.safe_load(file)

    unsupported = []

    for intent, config in catalog[
        "intents"
    ].items():

        for action in config.get(
            "actions",
            [],
        ):
            if action == "list":
                continue

            if (
                action
                not in planner.ACTION_EXECUTABLES
            ):
                unsupported.append(
                    (
                        intent,
                        action,
                    )
                )

    assert unsupported == []


def test_every_static_executable_mapping_is_allowlisted(
    planner,
):
    """
    Static action-to-executable mappings must
    agree with the catalog allowlist.

    Intent-dependent mappings such as 'list'
    are checked separately.
    """

    violations = []

    for intent, config in (
        planner.intents.items()
    ):
        allowed_actions = config.get(
            "actions",
            [],
        )

        allowed_executables = config.get(
            "allowed_executables",
            [],
        )

        for action in allowed_actions:
            if action == "list":
                continue

            executable = (
                planner.ACTION_EXECUTABLES.get(
                    action
                )
            )

            if (
                executable
                and executable
                not in allowed_executables
            ):
                violations.append(
                    (
                        intent,
                        action,
                        executable,
                    )
                )

    assert violations == []


def test_process_list_executable_is_allowlisted(
    planner,
):
    config = planner.intents[
        "process_inspection"
    ]

    executable = (
        planner._resolve_executable(
            intent="process_inspection",
            action="list",
            entities={},
        )
    )

    assert (
        executable
        in config["allowed_executables"]
    )


def test_file_list_executable_is_allowlisted(
    planner,
):
    config = planner.intents[
        "file_listing"
    ]

    executable = (
        planner._resolve_executable(
            intent="file_listing",
            action="list",
            entities={},
        )
    )

    assert (
        executable
        in config["allowed_executables"]
    )


# =========================================================
# Security invariants
# =========================================================


def test_out_of_scope_cannot_be_planned(
    planner,
):
    result = planner.plan(
        "tell me a joke",
        "out_of_scope",
        {},
    )

    assert result.planned is False
    assert result.plan is None


def test_operation_plan_never_contains_sudo(
    planner,
):
    result = planner.plan(
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    assert result.planned is True
    assert result.plan.executable != "sudo"
    assert "sudo" not in result.plan.arguments
    assert "sudo" not in result.plan.argv


# =========================================================
# Process inspection
# =========================================================


def test_process_pattern_search_plan(planner):
    result = planner.plan(
        text="find nginx processes",
        intent="process_inspection",
        entities={
            "PATTERN": "nginx",
        },
    )

    assert result.planned is True
    assert result.plan is not None

    assert result.plan.action == "list"
    assert result.plan.executable == "pgrep"

    assert result.plan.arguments == (
        "-a",
        "nginx",
    )


def test_process_pid_inspection_plan(planner):
    result = planner.plan(
        text="show process 4321",
        intent="process_inspection",
        entities={
            "PID": "4321",
        },
    )

    assert result.planned is True
    assert result.plan is not None

    assert result.plan.action == "inspect"
    assert result.plan.executable == "ps"

    assert result.plan.arguments == (
        "-p",
        "4321",
    )


def test_process_inspection_without_pid_fails_closed(
    planner,
):
    result = planner.plan(
        text="inspect process",
        intent="process_inspection",
        entities={},
    )

    assert result.planned is False
    assert result.plan is None

    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )


# =========================================================
# Action/entity contract integration
# =========================================================


def test_package_update_with_package_fails_closed(
    planner,
):
    result = planner.plan(
        text="update nginx",
        intent="package_management",
        entities={
            "PACKAGE": "nginx",
        },
    )

    assert result.planned is False
    assert result.plan is None

    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )

    assert "PACKAGE" in result.reason


def test_package_update_without_package_plans(
    planner,
):
    result = planner.plan(
        text="update packages",
        intent="package_management",
        entities={},
    )

    assert result.planned is True
    assert result.plan is not None
    assert result.plan.action == "update"

    assert result.plan.argv == [
        "apt-get",
        "update",
    ]


def test_listening_ports_with_port_fails_closed(
    planner,
):
    result = planner.plan(
        text="show listening ports",
        intent="network_inspection",
        entities={
            "PORT": "443",
        },
    )

    assert result.planned is False
    assert result.plan is None

    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )

    assert "PORT" in result.reason


def test_listening_ports_without_port_plans(
    planner,
):
    result = planner.plan(
        text="show listening ports",
        intent="network_inspection",
        entities={},
    )

    assert result.planned is True
    assert result.plan is not None

    assert (
        result.plan.action
        == "listening_ports"
    )

    assert result.plan.argv == [
        "ss",
        "-lnt",
    ]


def test_process_list_with_pid_fails_closed(
    planner,
):
    result = planner.plan(
        text="list processes",
        intent="process_inspection",
        entities={
            "PID": "4321",
        },
    )

    assert result.planned is False
    assert result.plan is None

    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )

    assert "PID" in result.reason


# =========================================================
# Option-termination hardening
# =========================================================


@pytest.mark.parametrize(
    (
        "text",
        "intent",
        "entities",
        "expected_argv",
    ),
    [
        (
            "read /tmp/report.txt",
            "file_read",
            {"PATH": "/tmp/report.txt"},
            [
                "cat",
                "--",
                "/tmp/report.txt",
            ],
        ),
        (
            "show head /tmp/report.txt",
            "file_read",
            {"PATH": "/tmp/report.txt"},
            [
                "head",
                "--",
                "/tmp/report.txt",
            ],
        ),
        (
            "show tail /tmp/report.txt",
            "file_read",
            {"PATH": "/tmp/report.txt"},
            [
                "tail",
                "--",
                "/tmp/report.txt",
            ],
        ),
        (
            "create file /tmp/report.txt",
            "file_create",
            {"PATH": "/tmp/report.txt"},
            [
                "touch",
                "--",
                "/tmp/report.txt",
            ],
        ),
        (
            "create directory /tmp/reports",
            "file_create",
            {"PATH": "/tmp/reports"},
            [
                "mkdir",
                "--",
                "/tmp/reports",
            ],
        ),
        (
            "delete /tmp/report.txt",
            "file_delete",
            {"PATH": "/tmp/report.txt"},
            [
                "rm",
                "--",
                "/tmp/report.txt",
            ],
        ),
    ],
)
def test_path_only_operations_use_option_termination(
    planner,
    text,
    intent,
    entities,
    expected_argv,
):
    """
    Supported path-only GNU/Linux operations must
    terminate option parsing before the path operand.

    This is defense in depth in addition to PATH
    semantic validation.
    """

    result = planner.plan(
        text=text,
        intent=intent,
        entities=entities,
    )

    assert result.planned is True
    assert result.plan is not None

    assert (
        result.plan.argv
        == expected_argv
    )