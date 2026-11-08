import pytest

from intentx.entities.pipeline import (
    EntityPipeline,
    EntityPipelineResult,
)


@pytest.fixture
def pipeline():
    return EntityPipeline()


def test_service_management_pipeline(
    pipeline,
):
    result = pipeline.process(
        "restart nginx",
        "service_management",
    )

    assert result.entities == {
        "SERVICE": "nginx"
    }
    assert result.valid is True
    assert (
        result.decision
        == "ENTITY_VALIDATED"
    )


def test_missing_service_requires_clarification(
    pipeline,
):
    result = pipeline.process(
        "restart",
        "service_management",
    )

    assert result.entities == {}
    assert result.valid is False
    assert result.missing_entities == [
        "SERVICE"
    ]
    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )


def test_package_management_pipeline(
    pipeline,
):
    result = pipeline.process(
        "install nginx",
        "package_management",
    )

    assert result.entities == {
        "PACKAGE": "nginx"
    }
    assert result.valid is True


def test_file_delete_pipeline(
    pipeline,
):
    result = pipeline.process(
        "delete /tmp/report.txt",
        "file_delete",
    )

    assert result.entities == {
        "PATH": "/tmp/report.txt"
    }
    assert result.valid is True


def test_file_copy_pipeline(
    pipeline,
):
    result = pipeline.process(
        "copy /tmp/a.txt to /opt/a.txt",
        "file_copy",
    )

    assert result.entities == {
        "SOURCE_PATH": "/tmp/a.txt",
        "DESTINATION_PATH": "/opt/a.txt",
    }

    assert result.valid is True


def test_file_copy_missing_destination(
    pipeline,
):
    result = pipeline.process(
        "copy /tmp/a.txt",
        "file_copy",
    )

    assert result.valid is False

    assert (
        "DESTINATION_PATH"
        in result.missing_entities
    )


def test_permission_change_pipeline(
    pipeline,
):
    result = pipeline.process(
        "chmod 644 /tmp/report.txt",
        "permission_change",
    )

    assert result.entities == {
        "PATH": "/tmp/report.txt",
        "PERMISSION": "644",
    }

    assert result.valid is True


def test_disk_management_pipeline(
    pipeline,
):
    result = pipeline.process(
        "format /dev/sdb",
        "disk_management",
    )

    assert result.entities == {
        "DEVICE": "/dev/sdb"
    }

    assert result.valid is True


def test_memory_inspection_needs_no_entity(
    pipeline,
):
    result = pipeline.process(
        "show memory usage",
        "memory_inspection",
    )

    assert result.entities == {}
    assert result.valid is True


def test_text_search_pipeline(
    pipeline,
):
    result = pipeline.process(
        'search for "ERROR" in '
        '/var/log/app.log',
        "text_search",
    )

    assert result.entities == {
        "PATTERN": "ERROR",
        "PATH": "/var/log/app.log",
    }

    assert result.valid is True


def test_unknown_intent_rejected(
    pipeline,
):
    with pytest.raises(ValueError):
        pipeline.process(
            "do something",
            "unknown_intent",
        )


def test_pipeline_result_type(
    pipeline,
):
    result = pipeline.process(
        "delete /tmp/test.txt",
        "file_delete",
    )

    assert isinstance(
        result,
        EntityPipelineResult,
    )


def test_pipeline_result_to_dictionary(
    pipeline,
):
    result = pipeline.process(
        "restart nginx",
        "service_management",
    )

    dictionary = result.to_dict()

    assert isinstance(dictionary, dict)
    assert (
        dictionary["intent"]
        == "service_management"
    )
    assert dictionary["valid"] is True