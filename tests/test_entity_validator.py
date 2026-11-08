import pytest

from intentx.entities.validator import (
    EntityValidationResult,
    EntityValidator,
)


@pytest.fixture
def validator():
    return EntityValidator()


def test_validator_loads_catalog(
    validator,
):
    assert len(validator.intents) == 21


def test_service_required_entity(
    validator,
):
    required = (
        validator.get_required_entities(
            "service_management"
        )
    )

    assert "SERVICE" in required


def test_valid_service_entity(
    validator,
):
    result = validator.validate(
        "service_management",
        {
            "SERVICE": "nginx",
        },
    )

    assert result.valid is True
    assert (
        result.decision
        == "ENTITY_VALIDATED"
    )
    assert result.missing_entities == []
    assert result.unexpected_entities == []


def test_missing_service_requires_clarification(
    validator,
):
    result = validator.validate(
        "service_management",
        {},
    )

    assert result.valid is False
    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )
    assert result.missing_entities == [
        "SERVICE"
    ]


def test_disk_device_required(
    validator,
):
    result = validator.validate(
        "disk_management",
        {
            "DEVICE": "/dev/sdb",
        },
    )

    assert result.valid is True


def test_missing_disk_device_rejected(
    validator,
):
    result = validator.validate(
        "disk_management",
        {},
    )

    assert result.valid is False
    assert "DEVICE" in (
        result.missing_entities
    )


def test_unexpected_entity_rejected(
    validator,
):
    result = validator.validate(
        "memory_inspection",
        {
            "PATH": "/tmp",
        },
    )

    assert result.valid is False
    assert result.unexpected_entities == [
        "PATH"
    ]


def test_optional_entity_can_be_absent(
    validator,
):
    result = validator.validate(
        "network_inspection",
        {},
    )

    assert result.valid is True


def test_empty_required_value_is_missing(
    validator,
):
    result = validator.validate(
        "file_delete",
        {
            "PATH": "   ",
        },
    )

    assert result.valid is False
    assert result.missing_entities == [
        "PATH"
    ]


def test_unknown_intent_rejected(
    validator,
):
    with pytest.raises(ValueError):
        validator.validate(
            "made_up_intent",
            {},
        )


def test_non_dictionary_entities_rejected(
    validator,
):
    with pytest.raises(TypeError):
        validator.validate(
            "file_delete",
            ["PATH"],
        )


def test_result_converts_to_dictionary(
    validator,
):
    result = validator.validate(
        "file_delete",
        {
            "PATH": "/tmp/test.txt",
        },
    )

    dictionary = result.to_dict()

    assert isinstance(dictionary, dict)
    assert (
        dictionary["intent"]
        == "file_delete"
    )
    assert dictionary["valid"] is True


def test_validation_result_type(
    validator,
):
    result = validator.validate(
        "file_read",
        {
            "PATH": "/etc/hosts",
        },
    )

    assert isinstance(
        result,
        EntityValidationResult,
    )