from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
INTENT_CATALOG = ROOT / "configs" / "intent_catalog.yaml"
SECURITY_POLICY = ROOT / "configs" / "security_policy.yaml"


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def test_configuration_files_exist():
    assert INTENT_CATALOG.exists()
    assert SECURITY_POLICY.exists()


def test_intent_catalog_has_required_structure():
    catalog = load_yaml(INTENT_CATALOG)

    assert catalog["version"]
    assert "metadata" in catalog
    assert "intents" in catalog
    assert catalog["defaults"]["fail_closed"] is True


def test_out_of_scope_intent_exists():
    catalog = load_yaml(INTENT_CATALOG)

    assert "out_of_scope" in catalog["intents"]

    out_of_scope = catalog["intents"]["out_of_scope"]

    assert out_of_scope["allowed_executables"] == []
    assert out_of_scope["auto_execution_candidate"] is False


def test_every_intent_has_required_fields():
    catalog = load_yaml(INTENT_CATALOG)

    required_fields = {
        "category",
        "description",
        "examples",
        "actions",
        "entities",
        "allowed_executables",
        "state_changing",
        "privilege_required",
        "auto_execution_candidate",
    }

    for intent_name, intent in catalog["intents"].items():
        missing = required_fields - set(intent.keys())

        assert not missing, (
            f"{intent_name} is missing required fields: {sorted(missing)}"
        )


def test_critical_operations_cannot_auto_execute():
    catalog = load_yaml(INTENT_CATALOG)

    for intent_name, intent in catalog["intents"].items():
        if intent.get("critical_operation", False):
            assert intent["auto_execution_candidate"] is False, (
                f"{intent_name} is critical but allows auto execution"
            )


def test_security_policy_is_fail_closed():
    policy = load_yaml(SECURITY_POLICY)

    assert policy["principles"]["fail_closed"] is True
    assert policy["principles"]["ai_can_authorize_execution"] is False
    assert policy["principles"]["arbitrary_shell_execution_allowed"] is False


def test_risk_ranges_cover_zero_to_one_hundred():
    policy = load_yaml(SECURITY_POLICY)
    levels = policy["risk_levels"]

    expected = {
        "low": (0, 25),
        "medium": (26, 50),
        "high": (51, 75),
        "critical": (76, 100),
    }

    for level, (minimum, maximum) in expected.items():
        assert levels[level]["min_score"] == minimum
        assert levels[level]["max_score"] == maximum


def test_critical_risk_is_denied():
    policy = load_yaml(SECURITY_POLICY)

    assert (
        policy["risk_decisions"]["critical"]["default_decision"]
        == "DENY"
    )


def test_execution_requires_security_controls():
    policy = load_yaml(SECURITY_POLICY)
    requirements = policy["execution_requirements"]

    assert requirements["require_intent_validation"] is True
    assert requirements["require_entity_validation"] is True
    assert requirements["require_risk_assessment"] is True
    assert requirements["require_policy_evaluation"] is True
    assert requirements["require_allowlisted_executable"] is True
    assert requirements["require_validated_arguments"] is True
    assert requirements["audit_record_required"] is True
    assert requirements["shell_mode_allowed"] is False