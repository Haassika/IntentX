from pathlib import Path

import pytest
import yaml

from intentx.policy.engine import PolicyEngine


POLICY_PATH = Path(
    "configs/security_policy.yaml"
)

CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)


@pytest.fixture
def policy():
    with POLICY_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file)

    assert isinstance(data, dict)

    return data


@pytest.fixture
def catalog():
    with CATALOG_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file)

    assert isinstance(data, dict)

    return data


@pytest.fixture
def engine():
    return PolicyEngine()


def test_policy_engine_loads_configuration(
    engine,
):
    assert engine.roles
    assert engine.risk_decisions
    assert engine.global_denials
    assert engine.hard_safety_boundaries


def test_required_decision_types_are_exact(
    policy,
):
    assert set(
        policy["decision_types"]
    ) == {
        "ALLOW",
        "REQUIRE_APPROVAL",
        "DENY",
        "CLARIFICATION_REQUIRED",
    }


def test_fail_closed_is_enabled(
    policy,
):
    assert (
        policy["principles"][
            "fail_closed"
        ]
        is True
    )


def test_least_privilege_is_enabled(
    policy,
):
    assert (
        policy["principles"][
            "least_privilege"
        ]
        is True
    )


def test_ai_cannot_authorize_execution(
    policy,
):
    assert (
        policy["principles"][
            "ai_can_authorize_execution"
        ]
        is False
    )


def test_arbitrary_shell_execution_is_disabled(
    policy,
):
    assert (
        policy["principles"][
            "arbitrary_shell_execution_allowed"
        ]
        is False
    )


def test_critical_operations_cannot_auto_execute(
    policy,
):
    assert (
        policy["principles"][
            "critical_operations_auto_execute"
        ]
        is False
    )


def test_expected_roles_exist(
    policy,
):
    assert set(
        policy["roles"]
    ) == {
        "VIEWER",
        "OPERATOR",
        "SENIOR_OPERATOR",
        "ADMINISTRATOR",
    }


def test_viewer_has_only_read_or_search_categories(
    policy,
):
    assert set(
        policy["roles"][
            "VIEWER"
        ]["allowed_categories"]
    ) == {
        "inspection",
        "search",
    }


def test_viewer_cannot_change_state(
    policy,
):
    assert (
        policy["roles"][
            "VIEWER"
        ]["state_changing_allowed"]
        is False
    )


def test_operator_categories_are_exact(
    policy,
):
    assert set(
        policy["roles"][
            "OPERATOR"
        ]["allowed_categories"]
    ) == {
        "inspection",
        "search",
        "file_operation",
        "administration",
    }


def test_operator_can_change_state(
    policy,
):
    assert (
        policy["roles"][
            "OPERATOR"
        ]["state_changing_allowed"]
        is True
    )


def test_operator_cannot_access_destructive_category(
    policy,
):
    categories = set(
        policy["roles"][
            "OPERATOR"
        ]["allowed_categories"]
    )

    assert "destructive" not in categories


def test_operator_cannot_access_critical_category(
    policy,
):
    categories = set(
        policy["roles"][
            "OPERATOR"
        ]["allowed_categories"]
    )

    assert "critical" not in categories


def test_senior_operator_categories_are_exact(
    policy,
):
    assert set(
        policy["roles"][
            "SENIOR_OPERATOR"
        ]["allowed_categories"]
    ) == {
        "inspection",
        "search",
        "file_operation",
        "administration",
        "destructive",
    }


def test_senior_operator_can_change_state(
    policy,
):
    assert (
        policy["roles"][
            "SENIOR_OPERATOR"
        ]["state_changing_allowed"]
        is True
    )


def test_senior_operator_cannot_access_critical_category(
    policy,
):
    categories = set(
        policy["roles"][
            "SENIOR_OPERATOR"
        ]["allowed_categories"]
    )

    assert "critical" not in categories


def test_administrator_categories_are_exact(
    policy,
):
    assert set(
        policy["roles"][
            "ADMINISTRATOR"
        ]["allowed_categories"]
    ) == {
        "inspection",
        "search",
        "file_operation",
        "administration",
        "destructive",
        "critical",
    }


def test_administrator_can_change_state(
    policy,
):
    assert (
        policy["roles"][
            "ADMINISTRATOR"
        ]["state_changing_allowed"]
        is True
    )


def test_no_role_can_access_unsupported_category(
    policy,
):
    for role_config in (
        policy["roles"].values()
    ):
        assert (
            "unsupported"
            not in role_config[
                "allowed_categories"
            ]
        )


def test_role_categories_exist_in_catalog(
    policy,
    catalog,
):
    catalog_categories = {
        config["category"]
        for config in (
            catalog["intents"].values()
        )
    }

    for role_name, role_config in (
        policy["roles"].items()
    ):
        for category in (
            role_config[
                "allowed_categories"
            ]
        ):
            assert (
                category
                in catalog_categories
            ), (
                f"{role_name} references "
                "unknown category "
                f"{category}"
            )


def test_destructive_category_is_restricted(
    policy,
):
    roles_with_destructive = {
        role
        for role, config in (
            policy["roles"].items()
        )
        if "destructive"
        in config[
            "allowed_categories"
        ]
    }

    assert roles_with_destructive == {
        "SENIOR_OPERATOR",
        "ADMINISTRATOR",
    }


def test_critical_category_is_admin_only(
    policy,
):
    roles_with_critical = {
        role
        for role, config in (
            policy["roles"].items()
        )
        if "critical"
        in config[
            "allowed_categories"
        ]
    }

    assert roles_with_critical == {
        "ADMINISTRATOR",
    }


def test_low_risk_default_is_allow(
    policy,
):
    assert (
        policy["risk_decisions"][
            "low"
        ]["default_decision"]
        == "ALLOW"
    )


def test_medium_risk_requires_approval(
    policy,
):
    assert (
        policy["risk_decisions"][
            "medium"
        ]["default_decision"]
        == "REQUIRE_APPROVAL"
    )


def test_high_risk_requires_approval(
    policy,
):
    assert (
        policy["risk_decisions"][
            "high"
        ]["default_decision"]
        == "REQUIRE_APPROVAL"
    )


def test_critical_risk_is_denied(
    policy,
):
    assert (
        policy["risk_decisions"][
            "critical"
        ]["default_decision"]
        == "DENY"
    )


def test_all_global_denials_are_deny(
    policy,
):
    for name, config in (
        policy[
            "global_denials"
        ].items()
    ):
        assert (
            config["decision"]
            == "DENY"
        ), (
            f"Global denial {name} "
            "must remain DENY."
        )


def test_required_global_denials_exist(
    policy,
):
    required = {
        "arbitrary_shell",
        "unsupported_intent",
        "intent_command_mismatch",
        "invalid_entity",
        "unsupported_executable",
        "unsupported_shell_construct",
    }

    assert required.issubset(
        policy["global_denials"]
    )


def test_all_hard_safety_boundaries_are_deny(
    policy,
):
    for name, config in (
        policy[
            "hard_safety_boundaries"
        ].items()
    ):
        assert (
            config["decision"]
            == "DENY"
        ), (
            f"Hard safety boundary "
            f"{name} must remain DENY."
        )


def test_required_hard_safety_boundaries_exist(
    policy,
):
    required = {
        "destructive_disk_operation",
        "arbitrary_remote_code_execution",
        "unrestricted_root_shell",
    }

    assert required.issubset(
        policy[
            "hard_safety_boundaries"
        ]
    )


def test_destructive_disk_operation_is_denied(
    policy,
):
    assert (
        policy[
            "hard_safety_boundaries"
        ][
            "destructive_disk_operation"
        ][
            "decision"
        ]
        == "DENY"
    )


def test_arbitrary_remote_code_execution_is_denied(
    policy,
):
    assert (
        policy[
            "hard_safety_boundaries"
        ][
            "arbitrary_remote_code_execution"
        ][
            "decision"
        ]
        == "DENY"
    )


def test_unrestricted_root_shell_is_denied(
    policy,
):
    assert (
        policy[
            "hard_safety_boundaries"
        ][
            "unrestricted_root_shell"
        ][
            "decision"
        ]
        == "DENY"
    )


def test_environment_set_is_exact(
    policy,
):
    assert set(
        policy["environments"]
    ) == {
        "DEV",
        "TEST",
        "PROD",
    }


def test_environment_risk_adjustments_are_ordered(
    policy,
):
    environment_policy = (
        policy[
            "environment_policy"
        ]
    )

    dev = environment_policy[
        "DEV"
    ]["risk_adjustment"]

    test = environment_policy[
        "TEST"
    ]["risk_adjustment"]

    prod = environment_policy[
        "PROD"
    ]["risk_adjustment"]

    assert dev <= test <= prod


def test_production_has_greatest_environment_adjustment(
    policy,
):
    environment_policy = (
        policy[
            "environment_policy"
        ]
    )

    adjustments = {
        environment: config[
            "risk_adjustment"
        ]
        for environment, config in (
            environment_policy.items()
        )
    }

    assert (
        adjustments["PROD"]
        == max(adjustments.values())
    )


def test_hard_boundary_mapping_exists_in_catalog(
    engine,
):
    for (
        intent,
        action,
    ), boundary in (
        engine.HARD_BOUNDARY_OPERATIONS.items()
    ):
        assert (
            boundary
            in engine.hard_safety_boundaries
        )

        assert (
            intent
            in engine.catalog["intents"]
        )

        assert (
            action
            in engine.catalog[
                "intents"
            ][intent]["actions"]
        )


def test_disk_format_maps_to_destructive_boundary(
    engine,
):
    assert (
        engine.HARD_BOUNDARY_OPERATIONS[
            (
                "disk_management",
                "format",
            )
        ]
        == "destructive_disk_operation"
    )


def test_policy_engine_normalizes_expected_roles(
    engine,
):
    assert set(engine.roles) == {
        "VIEWER",
        "OPERATOR",
        "SENIOR_OPERATOR",
        "ADMINISTRATOR",
    }


def test_policy_engine_normalizes_risk_decisions(
    engine,
):
    assert engine.risk_decisions == {
        "LOW": "ALLOW",
        "MEDIUM": "REQUIRE_APPROVAL",
        "HIGH": "REQUIRE_APPROVAL",
        "CRITICAL": "DENY",
    }


def test_policy_engine_knows_expected_environments(
    engine,
):
    assert engine.environments == frozenset(
        {
            "DEV",
            "TEST",
            "PROD",
        }
    )