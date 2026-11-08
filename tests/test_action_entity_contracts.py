from pathlib import Path

import pytest
import yaml

from intentx.planning.entity_contracts import (
    ActionEntityContracts,
)


CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)


# =========================================================
# Package management contracts
# =========================================================


def test_package_install_requires_package():
    reason = ActionEntityContracts.validate(
        "package_management",
        "install",
        {},
    )

    assert reason is not None
    assert "PACKAGE" in reason


def test_package_install_accepts_package():
    reason = ActionEntityContracts.validate(
        "package_management",
        "install",
        {
            "PACKAGE": "nginx",
        },
    )

    assert reason is None


def test_package_update_accepts_no_entities():
    reason = ActionEntityContracts.validate(
        "package_management",
        "update",
        {},
    )

    assert reason is None


def test_package_update_rejects_package():
    reason = ActionEntityContracts.validate(
        "package_management",
        "update",
        {
            "PACKAGE": "nginx",
        },
    )

    assert reason is not None
    assert "PACKAGE" in reason


# =========================================================
# Network inspection contracts
# =========================================================


def test_listening_ports_accepts_no_entities():
    reason = ActionEntityContracts.validate(
        "network_inspection",
        "listening_ports",
        {},
    )

    assert reason is None


def test_listening_ports_rejects_port():
    reason = ActionEntityContracts.validate(
        "network_inspection",
        "listening_ports",
        {
            "PORT": "443",
        },
    )

    assert reason is not None
    assert "PORT" in reason


# =========================================================
# Process inspection contracts
# =========================================================


def test_process_list_accepts_pattern():
    reason = ActionEntityContracts.validate(
        "process_inspection",
        "list",
        {
            "PATTERN": "nginx",
        },
    )

    assert reason is None


def test_process_list_rejects_pid():
    reason = ActionEntityContracts.validate(
        "process_inspection",
        "list",
        {
            "PID": "4321",
        },
    )

    assert reason is not None
    assert "PID" in reason


def test_process_inspect_requires_pid():
    reason = ActionEntityContracts.validate(
        "process_inspection",
        "inspect",
        {},
    )

    assert reason is not None
    assert "PID" in reason


def test_process_inspect_accepts_pid():
    reason = ActionEntityContracts.validate(
        "process_inspection",
        "inspect",
        {
            "PID": "4321",
        },
    )

    assert reason is None


# =========================================================
# Storage inspection contracts
# =========================================================


def test_directory_size_requires_path():
    reason = ActionEntityContracts.validate(
        "storage_inspection",
        "directory_size",
        {},
    )

    assert reason is not None
    assert "PATH" in reason


def test_filesystem_usage_path_is_optional():
    reason = ActionEntityContracts.validate(
        "storage_inspection",
        "filesystem_usage",
        {},
    )

    assert reason is None

    reason = ActionEntityContracts.validate(
        "storage_inspection",
        "filesystem_usage",
        {
            "PATH": "/var/log",
        },
    )

    assert reason is None


# =========================================================
# Fail-closed behaviour
# =========================================================


def test_unknown_contract_fails_closed():
    reason = ActionEntityContracts.validate(
        "package_management",
        "does_not_exist",
        {},
    )

    assert reason is not None


def test_entities_must_be_dictionary():
    with pytest.raises(TypeError):
        ActionEntityContracts.validate(
            "package_management",
            "update",
            [],
        )


# =========================================================
# Catalog / contract consistency invariants
# =========================================================


def test_every_catalog_action_has_entity_contract():
    """
    Every action declared in the intent catalog must
    have an explicit action/entity contract.

    This prevents a new catalog action from being
    introduced without defining its exact entity
    semantics.
    """

    with CATALOG_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        catalog = yaml.safe_load(file)

    assert isinstance(
        catalog,
        dict,
    )

    intents = catalog.get(
        "intents"
    )

    assert isinstance(
        intents,
        dict,
    )

    expected_contracts = set()

    for intent, config in intents.items():

        assert isinstance(
            config,
            dict,
        )

        actions = config.get(
            "actions",
            [],
        )

        if actions is None:
            actions = []

        assert isinstance(
            actions,
            list,
        )

        for action in actions:
            expected_contracts.add(
                (
                    intent,
                    action,
                )
            )

    actual_contracts = set(
        ActionEntityContracts.CONTRACTS.keys()
    )

    assert (
        actual_contracts
        == expected_contracts
    ), (
        "Action/entity contract registry does not "
        "exactly match the actions declared in "
        "intent_catalog.yaml."
    )


def test_required_entities_are_always_allowed():
    """
    A required entity must also be included in the
    allowed entity set for the same action.

    Otherwise the contract would be internally
    contradictory.
    """

    for (
        intent_action,
        contract,
    ) in ActionEntityContracts.CONTRACTS.items():

        assert contract.required.issubset(
            contract.allowed
        ), (
            "Required entities must also be "
            "allowed for "
            f"{intent_action}"
        )