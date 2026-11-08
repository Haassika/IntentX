import pytest

from intentx.analysis.pipeline import (
    IntentAnalysisPipeline,
    IntentAnalysisResult,
)


@pytest.fixture
def pipeline():
    return IntentAnalysisPipeline()


def test_package_request_ready_for_planning(
    pipeline,
):
    result = pipeline.analyze(
        "install nginx"
    )

    assert (
        result.predicted_intent
        == "package_management"
    )
    assert result.intent_accepted is True
    assert result.entities_valid is True
    assert result.entities == {
        "PACKAGE": "nginx"
    }
    assert (
        result.decision
        == "READY_FOR_PLANNING"
    )


def test_service_request_ready_for_planning(
    pipeline,
):
    result = pipeline.analyze(
        "restart nginx"
    )

    assert (
        result.predicted_intent
        == "service_management"
    )
    assert result.entities == {
        "SERVICE": "nginx"
    }
    assert (
        result.decision
        == "READY_FOR_PLANNING"
    )


def test_file_delete_ready_for_planning(
    pipeline,
):
    result = pipeline.analyze(
        "delete /tmp/report.txt"
    )

    assert (
        result.predicted_intent
        == "file_delete"
    )
    assert result.entities == {
        "PATH": "/tmp/report.txt"
    }
    assert result.entities_valid is True
    assert (
        result.decision
        == "READY_FOR_PLANNING"
    )


def test_memory_request_needs_no_entities(
    pipeline,
):
    result = pipeline.analyze(
        "show memory usage"
    )

    assert (
        result.predicted_intent
        == "memory_inspection"
    )
    assert result.entities == {}
    assert result.entities_valid is True
    assert (
        result.decision
        == "READY_FOR_PLANNING"
    )


def test_low_confidence_request_stops_pipeline(
    pipeline,
):
    result = pipeline.analyze(
        "tell me a joke"
    )

    assert result.intent_accepted is False
    assert result.entities == {}
    assert result.entities_valid is False
    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )
    assert result.missing_entities is None


def test_known_ambiguous_process_example_is_blocked(
    pipeline,
):
    result = pipeline.analyze(
        "end process 1234"
    )

    assert result.intent_accepted is False
    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )


def test_result_is_correct_type(
    pipeline,
):
    result = pipeline.analyze(
        "show memory usage"
    )

    assert isinstance(
        result,
        IntentAnalysisResult,
    )


def test_result_converts_to_dictionary(
    pipeline,
):
    result = pipeline.analyze(
        "install nginx"
    )

    dictionary = result.to_dict()

    assert isinstance(dictionary, dict)
    assert (
        dictionary["decision"]
        == "READY_FOR_PLANNING"
    )


def test_strict_threshold_blocks_request():
    pipeline = IntentAnalysisPipeline(
        confidence_threshold=1.0
    )

    result = pipeline.analyze(
        "install nginx"
    )

    assert result.intent_accepted is False
    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )


def test_empty_input_rejected(
    pipeline,
):
    with pytest.raises(ValueError):
        pipeline.analyze("")