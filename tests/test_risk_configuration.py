from pathlib import Path

import pytest
import yaml

from intentx.risk.engine import RiskAssessmentEngine


INTENT_CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)

SECURITY_POLICY_PATH = Path(
    "configs/security_policy.yaml"
)


def _load_yaml(path: Path):
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def _catalog_actions():
    catalog = _load_yaml(
        INTENT_CATALOG_PATH
    )

    intents = catalog.get("intents")

    assert isinstance(
        intents,
        dict,
    )

    actions = set()

    for intent_name, config in (
        intents.items()
    ):
        assert isinstance(
            config,
            dict,
        ), intent_name

        intent_actions = config.get(
            "actions",
            [],
        )

        assert isinstance(
            intent_actions,
            list,
        ), intent_name

        for action in intent_actions:
            assert isinstance(
                action,
                str,
            ), intent_name

            assert action.strip(), (
                intent_name
            )

            assert action == action.strip(), (
                intent_name
            )

            actions.add(action)

    return actions


def test_every_catalog_action_has_risk_weight():
    engine = RiskAssessmentEngine()

    catalog_actions = _catalog_actions()

    configured_actions = set(
        engine.action_risk_scores
    )

    missing = (
        catalog_actions
        - configured_actions
    )

    assert not missing, (
        "Catalog actions missing risk weights: "
        f"{sorted(missing)}"
    )


def test_no_unknown_action_risk_weights():
    engine = RiskAssessmentEngine()

    catalog_actions = _catalog_actions()

    configured_actions = set(
        engine.action_risk_scores
    )

    unknown = (
        configured_actions
        - catalog_actions
    )

    assert not unknown, (
        "Risk weights exist for unknown actions: "
        f"{sorted(unknown)}"
    )


def test_catalog_and_risk_actions_match_exactly():
    engine = RiskAssessmentEngine()

    assert set(
        engine.action_risk_scores
    ) == _catalog_actions()


def test_all_action_weights_are_non_negative_integers():
    engine = RiskAssessmentEngine()

    for action, weight in (
        engine.action_risk_scores.items()
    ):
        assert isinstance(
            weight,
            int,
        )

        assert not isinstance(
            weight,
            bool,
        )

        assert weight >= 0, action


def test_factor_weights_are_non_negative_integers():
    engine = RiskAssessmentEngine()

    weights = [
        engine.state_changing_score,
        engine.critical_operation_score,
        *engine.privilege_scores.values(),
    ]

    for weight in weights:
        assert isinstance(
            weight,
            int,
        )

        assert not isinstance(
            weight,
            bool,
        )

        assert weight >= 0


def test_false_privilege_has_zero_weight():
    engine = RiskAssessmentEngine()

    assert (
        engine.privilege_scores[False]
        == 0
    )


def test_missing_risk_scoring_rejected(
    tmp_path,
):
    policy = _load_yaml(
        SECURITY_POLICY_PATH
    )

    del policy["risk_scoring"]

    path = (
        tmp_path
        / "security_policy.yaml"
    )

    with path.open(
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
            policy_path=path
        )


def test_missing_action_weights_rejected(
    tmp_path,
):
    policy = _load_yaml(
        SECURITY_POLICY_PATH
    )

    del policy[
        "risk_scoring"
    ][
        "action_weights"
    ]

    path = (
        tmp_path
        / "security_policy.yaml"
    )

    with path.open(
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
            policy_path=path
        )


def test_negative_action_weight_rejected(
    tmp_path,
):
    policy = _load_yaml(
        SECURITY_POLICY_PATH
    )

    policy[
        "risk_scoring"
    ][
        "action_weights"
    ][
        "restart"
    ] = -1

    path = (
        tmp_path
        / "security_policy.yaml"
    )

    with path.open(
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
            policy_path=path
        )


def test_boolean_action_weight_rejected(
    tmp_path,
):
    policy = _load_yaml(
        SECURITY_POLICY_PATH
    )

    policy[
        "risk_scoring"
    ][
        "action_weights"
    ][
        "restart"
    ] = True

    path = (
        tmp_path
        / "security_policy.yaml"
    )

    with path.open(
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
            policy_path=path
        )


def test_negative_factor_weight_rejected(
    tmp_path,
):
    policy = _load_yaml(
        SECURITY_POLICY_PATH
    )

    policy[
        "risk_scoring"
    ][
        "factor_weights"
    ][
        "state_changing"
    ] = -1

    path = (
        tmp_path
        / "security_policy.yaml"
    )

    with path.open(
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
            policy_path=path
        )


def test_boolean_factor_weight_rejected(
    tmp_path,
):
    policy = _load_yaml(
        SECURITY_POLICY_PATH
    )

    policy[
        "risk_scoring"
    ][
        "factor_weights"
    ][
        "state_changing"
    ] = True

    path = (
        tmp_path
        / "security_policy.yaml"
    )

    with path.open(
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
            policy_path=path
        )