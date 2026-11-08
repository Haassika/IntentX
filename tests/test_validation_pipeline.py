import pytest

from intentx.validation.pipeline import (
    ValidationPipeline,
    ValidationPipelineResult,
)


@pytest.fixture
def pipeline():
    return ValidationPipeline()


def test_service_request_validates(
    pipeline,
):
    result = pipeline.process(
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    assert result.planned is True
    assert result.validated is True

    assert (
        result.decision
        == "READY_FOR_RISK_ASSESSMENT"
    )

    assert result.plan is not None

    assert result.plan.argv == [
        "systemctl",
        "restart",
        "nginx",
    ]


def test_memory_request_validates(
    pipeline,
):
    result = pipeline.process(
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    assert result.planned is True
    assert result.validated is True

    assert result.plan.argv == [
        "free",
        "-h",
    ]


def test_file_copy_validates(
    pipeline,
):
    result = pipeline.process(
        text=(
            "copy /tmp/a.txt "
            "to /tmp/b.txt"
        ),
        intent="file_copy",
        entities={
            "SOURCE_PATH": "/tmp/a.txt",
            "DESTINATION_PATH": "/tmp/b.txt",
        },
    )

    assert result.planned is True
    assert result.validated is True

    assert result.plan.argv == [
        "cp",
        "--",
        "/tmp/a.txt",
        "/tmp/b.txt",
    ]


def test_force_termination_validates(
    pipeline,
):
    result = pipeline.process(
        text="force kill process 1234",
        intent="process_termination",
        entities={
            "PID": "1234",
        },
    )

    assert result.planned is True
    assert result.validated is True

    assert result.plan.argv == [
        "kill",
        "-KILL",
        "--",
        "1234",
    ]


def test_invalid_entity_fails_validation(
    pipeline,
):
    result = pipeline.process(
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx;reboot",
        },
    )

    assert result.planned is True
    assert result.validated is False

    assert (
        result.decision
        == "VALIDATION_FAILED"
    )

    assert any(
        issue.code == "INVALID_SERVICE"
        for issue in result.issues
    )


def test_missing_required_entity_stops(
    pipeline,
):
    result = pipeline.process(
        text="restart service",
        intent="service_management",
        entities={},
    )

    assert result.validated is False

    assert result.decision != (
        "READY_FOR_RISK_ASSESSMENT"
    )


def test_ambiguous_action_stops(
    pipeline,
):
    result = pipeline.process(
        text="manage nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    assert result.planned is False
    assert result.validated is False
    assert result.plan is None


def test_critical_disk_operation_can_validate(
    pipeline,
):
    """
    Critical operations may be structurally valid.

    Later risk/policy layers are responsible for
    denying execution according to policy.
    """

    result = pipeline.process(
        text="format /dev/sdb",
        intent="disk_management",
        entities={
            "DEVICE": "/dev/sdb",
        },
    )

    assert result.planned is True
    assert result.validated is True

    assert result.plan.critical_operation is True

    assert (
        result.decision
        == "READY_FOR_RISK_ASSESSMENT"
    )


def test_pipeline_does_not_authorize(
    pipeline,
):
    result = pipeline.process(
        text="restart nginx",
        intent="service_management",
        entities={
            "SERVICE": "nginx",
        },
    )

    assert result.decision not in {
        "ALLOW",
        "AUTHORIZED",
        "EXECUTE",
    }


def test_result_type(
    pipeline,
):
    result = pipeline.process(
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    assert isinstance(
        result,
        ValidationPipelineResult,
    )


def test_result_converts_to_dictionary(
    pipeline,
):
    result = pipeline.process(
        text="show memory usage",
        intent="memory_inspection",
        entities={},
    )

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["planned"] is True
    assert data["validated"] is True


def test_non_string_text_rejected(
    pipeline,
):
    with pytest.raises(TypeError):
        pipeline.process(
            text=123,
            intent="memory_inspection",
            entities={},
        )


def test_empty_text_rejected(
    pipeline,
):
    with pytest.raises(ValueError):
        pipeline.process(
            text="   ",
            intent="memory_inspection",
            entities={},
        )


def test_non_string_intent_rejected(
    pipeline,
):
    with pytest.raises(TypeError):
        pipeline.process(
            text="show memory usage",
            intent=123,
            entities={},
        )


def test_empty_intent_rejected(
    pipeline,
):
    with pytest.raises(ValueError):
        pipeline.process(
            text="show memory usage",
            intent="   ",
            entities={},
        )


def test_entities_must_be_dictionary(
    pipeline,
):
    with pytest.raises(TypeError):
        pipeline.process(
            text="show memory usage",
            intent="memory_inspection",
            entities=[],
        )


def test_pipeline_has_no_execution_method():
    prohibited = {
        "execute",
        "run",
        "run_command",
        "run_shell",
    }

    for method in prohibited:
        assert not hasattr(
            ValidationPipeline,
            method,
        )