from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml

from intentx.planning.models import OperationPlan
from intentx.planning.planner import OperationPlanner
from intentx.risk.engine import RiskAssessmentEngine
from intentx.risk.models import (
    RiskAssessmentResult,
    RiskFactor,
)


@pytest.fixture
def planner():
    return OperationPlanner()


@pytest.fixture
def risk_engine():
    return RiskAssessmentEngine()


def _plan(
    planner,
    text,
    intent,
    entities,
):
    result = planner.plan(
        text=text,
        intent=intent,
        entities=entities,
    )

    assert result.planned is True
    assert result.plan is not None

    return result.plan


# =========================================================
# Core assessment behavior
# =========================================================


def test_read_only_operation_is_low_risk(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "show memory usage",
        "memory_inspection",
        {},
    )

    result = risk_engine.assess(
        plan,
        environment="DEV",
    )

    assert result.score == 0
    assert result.base_score == 0
    assert result.level == "LOW"
    assert result.environment == "DEV"
    assert result.environment_adjustment == 0
    assert result.factors == ()


def test_service_restart_is_medium_risk(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(
        plan,
        environment="DEV",
    )

    assert result.base_score == 50
    assert result.score == 50
    assert result.level == "MEDIUM"

    assert result.factor_codes == [
        "ACTION_SENSITIVITY",
        "STATE_CHANGING",
        "PRIVILEGE_REQUIRED",
    ]


def test_critical_disk_operation_is_critical(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "format /dev/sdb",
        "disk_management",
        {"DEVICE": "/dev/sdb"},
    )

    result = risk_engine.assess(
        plan,
        environment="DEV",
    )

    assert result.base_score == 140
    assert result.score == 100
    assert result.level == "CRITICAL"

    assert "CRITICAL_OPERATION" in (
        result.factor_codes
    )


def test_risk_score_is_clamped_to_100(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "format /dev/sdb",
        "disk_management",
        {"DEVICE": "/dev/sdb"},
    )

    result = risk_engine.assess(
        plan,
        environment="PROD",
    )

    assert result.base_score == 140
    assert result.environment_adjustment == 15
    assert result.score == 100


# =========================================================
# Environment behavior
# =========================================================


def test_dev_environment_adjustment(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(
        plan,
        environment="DEV",
    )

    assert result.environment_adjustment == 0
    assert result.score == 50


def test_test_environment_adjustment(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(
        plan,
        environment="TEST",
    )

    assert result.environment_adjustment == 5
    assert result.score == 55
    assert result.level == "HIGH"


def test_prod_environment_adjustment(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(
        plan,
        environment="PROD",
    )

    assert result.environment_adjustment == 15
    assert result.score == 65
    assert result.level == "HIGH"


def test_environment_is_case_insensitive(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "show memory usage",
        "memory_inspection",
        {},
    )

    result = risk_engine.assess(
        plan,
        environment="prod",
    )

    assert result.environment == "PROD"
    assert result.environment_adjustment == 15
    assert result.score == 15
    assert result.level == "LOW"


def test_environment_whitespace_is_normalized(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "show memory usage",
        "memory_inspection",
        {},
    )

    result = risk_engine.assess(
        plan,
        environment="  test  ",
    )

    assert result.environment == "TEST"
    assert result.environment_adjustment == 5


def test_unknown_environment_fails_closed(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "show memory usage",
        "memory_inspection",
        {},
    )

    with pytest.raises(ValueError):
        risk_engine.assess(
            plan,
            environment="STAGING",
        )


def test_empty_environment_rejected(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "show memory usage",
        "memory_inspection",
        {},
    )

    with pytest.raises(ValueError):
        risk_engine.assess(
            plan,
            environment="   ",
        )


def test_non_string_environment_rejected(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "show memory usage",
        "memory_inspection",
        {},
    )

    with pytest.raises(TypeError):
        risk_engine.assess(
            plan,
            environment=123,
        )


# =========================================================
# Risk factor behavior
# =========================================================


def test_state_changing_factor_present(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "delete /tmp/report.txt",
        "file_delete",
        {"PATH": "/tmp/report.txt"},
    )

    result = risk_engine.assess(plan)

    assert "STATE_CHANGING" in (
        result.factor_codes
    )


def test_conditional_privilege_uses_lower_weight(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(plan)

    privilege_factors = [
        factor
        for factor in result.factors
        if factor.code == "PRIVILEGE_REQUIRED"
    ]

    assert len(privilege_factors) == 1
    assert privilege_factors[0].score == 10


def test_required_privilege_uses_full_weight(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "reboot system",
        "system_power",
        {},
    )

    result = risk_engine.assess(plan)

    privilege_factors = [
        factor
        for factor in result.factors
        if factor.code == "PRIVILEGE_REQUIRED"
    ]

    assert len(privilege_factors) == 1
    assert privilege_factors[0].score == 20


def test_critical_factor_only_for_critical_plan(
    planner,
    risk_engine,
):
    normal_plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    critical_plan = _plan(
        planner,
        "reboot system",
        "system_power",
        {},
    )

    normal_result = risk_engine.assess(
        normal_plan
    )

    critical_result = risk_engine.assess(
        critical_plan
    )

    assert "CRITICAL_OPERATION" not in (
        normal_result.factor_codes
    )

    assert "CRITICAL_OPERATION" in (
        critical_result.factor_codes
    )


# =========================================================
# Input validation / fail-closed behavior
# =========================================================


def test_plan_must_be_operation_plan(
    risk_engine,
):
    with pytest.raises(TypeError):
        risk_engine.assess(
            {
                "action": "restart",
            }
        )


def test_unknown_action_fails_closed(
    risk_engine,
):
    plan = OperationPlan(
        intent="service_management",
        action="made_up_action",
        executable="systemctl",
        arguments=(),
        entities={},
        state_changing=True,
        privilege_required="conditional",
        critical_operation=False,
    )

    with pytest.raises(ValueError):
        risk_engine.assess(plan)


def test_invalid_privilege_requirement_fails_closed(
    risk_engine,
):
    plan = OperationPlan(
        intent="service_management",
        action="restart",
        executable="systemctl",
        arguments=(
            "restart",
            "nginx",
        ),
        entities={
            "SERVICE": "nginx",
        },
        state_changing=True,
        privilege_required="sometimes",
        critical_operation=False,
    )

    with pytest.raises(ValueError):
        risk_engine.assess(plan)


def test_missing_policy_file_rejected(
    tmp_path,
):
    missing = (
        tmp_path
        / "missing-security-policy.yaml"
    )

    with pytest.raises(FileNotFoundError):
        RiskAssessmentEngine(
            policy_path=missing
        )


def test_policy_must_be_mapping(
    tmp_path,
):
    policy_path = (
        tmp_path
        / "security-policy.yaml"
    )

    policy_path.write_text(
        "- not\n- a\n- mapping\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        RiskAssessmentEngine(
            policy_path=policy_path
        )


# =========================================================
# Configuration integrity
# =========================================================


def test_configured_risk_ranges_cover_0_to_100(
    risk_engine,
):
    covered = []

    for config in (
        risk_engine.risk_levels.values()
    ):
        covered.extend(
            range(
                config["min_score"],
                config["max_score"] + 1,
            )
        )

    assert sorted(covered) == list(
        range(101)
    )


def test_overlapping_risk_ranges_rejected(
    tmp_path,
):
    source_path = Path(
        "configs/security_policy.yaml"
    )

    with source_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        policy = yaml.safe_load(file)

    policy["risk_levels"]["medium"][
        "min_score"
    ] = 25

    policy_path = (
        tmp_path
        / "security-policy.yaml"
    )

    with policy_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        yaml.safe_dump(
            policy,
            file,
            sort_keys=False,
        )

    with pytest.raises(ValueError):
        RiskAssessmentEngine(
            policy_path=policy_path
        )


def test_gap_in_risk_ranges_rejected(
    tmp_path,
):
    source_path = Path(
        "configs/security_policy.yaml"
    )

    with source_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        policy = yaml.safe_load(file)

    policy["risk_levels"]["medium"][
        "min_score"
    ] = 27

    policy_path = (
        tmp_path
        / "security-policy.yaml"
    )

    with policy_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        yaml.safe_dump(
            policy,
            file,
            sort_keys=False,
        )

    with pytest.raises(ValueError):
        RiskAssessmentEngine(
            policy_path=policy_path
        )


def test_missing_environment_policy_rejected(
    tmp_path,
):
    source_path = Path(
        "configs/security_policy.yaml"
    )

    with source_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        policy = yaml.safe_load(file)

    del policy["environment_policy"]["PROD"]

    policy_path = (
        tmp_path
        / "security-policy.yaml"
    )

    with policy_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        yaml.safe_dump(
            policy,
            file,
            sort_keys=False,
        )

    with pytest.raises(ValueError):
        RiskAssessmentEngine(
            policy_path=policy_path
        )


# =========================================================
# Immutable result models
# =========================================================


def test_risk_factor_is_immutable():
    factor = RiskFactor(
        code="TEST_FACTOR",
        description="Test factor.",
        score=10,
    )

    with pytest.raises(
        FrozenInstanceError
    ):
        factor.score = 20


def test_risk_result_is_immutable(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(plan)

    with pytest.raises(
        FrozenInstanceError
    ):
        result.score = 1


def test_risk_factors_are_tuple(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(plan)

    assert isinstance(
        result.factors,
        tuple,
    )


def test_factor_codes_returns_fresh_list(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(plan)

    codes = result.factor_codes
    codes.append("MUTATED")

    assert "MUTATED" not in (
        result.factor_codes
    )


def test_to_dict_returns_defensive_data(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(plan)

    serialized = result.to_dict()

    serialized["score"] = 1
    serialized["factors"].append(
        {
            "code": "MUTATED",
            "description": "Mutation",
            "score": 99,
        }
    )

    assert result.score == 50
    assert "MUTATED" not in (
        result.factor_codes
    )


def test_result_type(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "show memory usage",
        "memory_inspection",
        {},
    )

    result = risk_engine.assess(plan)

    assert isinstance(
        result,
        RiskAssessmentResult,
    )


# =========================================================
# Authorization separation
# =========================================================


def test_risk_result_contains_no_decision(
    planner,
    risk_engine,
):
    plan = _plan(
        planner,
        "restart nginx",
        "service_management",
        {"SERVICE": "nginx"},
    )

    result = risk_engine.assess(plan)

    assert not hasattr(
        result,
        "decision",
    )

    assert "decision" not in (
        result.to_dict()
    )


def test_risk_engine_has_no_authorization_method():
    prohibited = [
        "authorize",
        "allow",
        "deny",
        "approve",
        "execute",
        "run",
        "run_command",
        "run_shell",
    ]

    for method in prohibited:
        assert not hasattr(
            RiskAssessmentEngine,
            method,
        )