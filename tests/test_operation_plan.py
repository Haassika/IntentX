import pytest

from intentx.planning.models import (
    OperationPlan,
)


def make_service_plan():
    return OperationPlan(
        intent="service_management",
        action="restart",
        executable="systemctl",
        arguments=[
            "restart",
            "nginx",
        ],
        entities={
            "SERVICE": "nginx",
        },
        state_changing=True,
        privilege_required=True,
        critical_operation=False,
    )


def test_operation_plan_creation():
    plan = make_service_plan()

    assert (
        plan.intent
        == "service_management"
    )

    assert plan.action == "restart"

    assert (
        plan.executable
        == "systemctl"
    )

    assert plan.arguments == (
        "restart",
        "nginx",
    )

    assert dict(plan.entities) == {
        "SERVICE": "nginx",
    }


def test_operation_plan_arguments_are_immutable():
    plan = make_service_plan()

    assert isinstance(
        plan.arguments,
        tuple,
    )

    with pytest.raises(
        AttributeError
    ):
        plan.arguments.append(
            "unexpected"
        )


def test_operation_plan_entities_are_immutable():
    plan = make_service_plan()

    with pytest.raises(
        TypeError
    ):
        plan.entities[
            "SERVICE"
        ] = "apache"


def test_original_arguments_cannot_mutate_plan():
    arguments = [
        "restart",
        "nginx",
    ]

    plan = OperationPlan(
        intent="service_management",
        action="restart",
        executable="systemctl",
        arguments=arguments,
        entities={
            "SERVICE": "nginx",
        },
        state_changing=True,
        privilege_required=True,
        critical_operation=False,
    )

    arguments.append(
        "unexpected"
    )

    assert plan.arguments == (
        "restart",
        "nginx",
    )


def test_original_entities_cannot_mutate_plan():
    entities = {
        "SERVICE": "nginx",
    }

    plan = OperationPlan(
        intent="service_management",
        action="restart",
        executable="systemctl",
        arguments=[
            "restart",
            "nginx",
        ],
        entities=entities,
        state_changing=True,
        privilege_required=True,
        critical_operation=False,
    )

    entities[
        "SERVICE"
    ] = "apache"

    assert (
        plan.entities.get(
            "SERVICE"
        )
        == "nginx"
    )


def test_operation_plan_argv():
    plan = make_service_plan()

    assert plan.argv == [
        "systemctl",
        "restart",
        "nginx",
    ]


def test_argv_mutation_cannot_mutate_plan():
    plan = make_service_plan()

    argv = plan.argv

    argv.append(
        "unexpected"
    )

    assert plan.argv == [
        "systemctl",
        "restart",
        "nginx",
    ]

    assert plan.arguments == (
        "restart",
        "nginx",
    )


def test_operation_plan_to_dictionary():
    plan = OperationPlan(
        intent="file_delete",
        action="delete",
        executable="rm",
        arguments=[
            "--",
            "/tmp/report.txt",
        ],
        entities={
            "PATH": "/tmp/report.txt",
        },
        state_changing=True,
        privilege_required=False,
        critical_operation=False,
    )

    result = plan.to_dict()

    assert isinstance(
        result,
        dict,
    )

    assert (
        result["intent"]
        == "file_delete"
    )

    assert result["arguments"] == [
        "--",
        "/tmp/report.txt",
    ]

    assert result["entities"] == {
        "PATH": "/tmp/report.txt"
    }


def test_to_dictionary_returns_defensive_copies():
    plan = make_service_plan()

    result = plan.to_dict()

    result["arguments"].append(
        "unexpected"
    )

    result["entities"][
        "SERVICE"
    ] = "apache"

    assert plan.arguments == (
        "restart",
        "nginx",
    )

    assert (
        plan.entities.get(
            "SERVICE"
        )
        == "nginx"
    )


def test_operation_plan_contains_no_shell_string():
    plan = OperationPlan(
        intent="file_read",
        action="read",
        executable="cat",
        arguments=[
            "--",
            "/etc/hosts",
        ],
        entities={
            "PATH": "/etc/hosts",
        },
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )

    assert isinstance(
        plan.arguments,
        tuple,
    )

    assert isinstance(
        plan.argv,
        list,
    )

    assert plan.argv == [
        "cat",
        "--",
        "/etc/hosts",
    ]


def test_frozen_plan_prevents_attribute_reassignment():
    plan = make_service_plan()

    with pytest.raises(
        AttributeError
    ):
        plan.executable = "sh"


def test_operation_plan_has_no_execution_method():
    prohibited_methods = [
        "execute",
        "run",
        "run_command",
        "run_shell",
    ]

    for method in prohibited_methods:
        assert not hasattr(
            OperationPlan,
            method,
        )