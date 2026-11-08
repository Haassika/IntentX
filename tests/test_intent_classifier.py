from pathlib import Path

import pytest

from intentx.ml.classifier import (
    IntentClassifier,
    IntentPrediction,
)


ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    ROOT
    / "models"
    / "intent_classifier_v2.joblib"
)


@pytest.fixture(scope="module")
def classifier():
    return IntentClassifier(
        model_path=MODEL_PATH,
        confidence_threshold=0.50,
    )


def test_model_file_exists():
    assert MODEL_PATH.exists()


def test_classifier_loads_model(
    classifier,
):
    assert classifier.model is not None


def test_prediction_returns_expected_type(
    classifier,
):
    result = classifier.predict(
        "install nginx"
    )

    assert isinstance(
        result,
        IntentPrediction,
    )


def test_prediction_contains_valid_fields(
    classifier,
):
    result = classifier.predict(
        "install nginx"
    )

    assert result.text
    assert result.predicted_intent
    assert result.second_intent

    assert (
        0.0
        <= result.confidence
        <= 1.0
    )

    assert (
        0.0
        <= result.second_confidence
        <= 1.0
    )

    assert (
        0.0
        <= result.margin
        <= 1.0
    )


def test_high_confidence_request_is_accepted(
    classifier,
):
    result = classifier.predict(
        "install nginx"
    )

    assert (
        result.predicted_intent
        == "package_management"
    )

    assert result.accepted is True

    assert (
        result.decision
        == "INTENT_ACCEPTED"
    )


def test_low_confidence_request_requires_clarification():
    strict_classifier = IntentClassifier(
        model_path=MODEL_PATH,
        confidence_threshold=1.0,
    )

    result = strict_classifier.predict(
        "install nginx"
    )

    assert result.accepted is False

    assert (
        result.decision
        == "CLARIFICATION_REQUIRED"
    )


def test_empty_input_rejected(
    classifier,
):
    with pytest.raises(
        ValueError
    ):
        classifier.predict("")


def test_whitespace_input_rejected(
    classifier,
):
    with pytest.raises(
        ValueError
    ):
        classifier.predict(
            "     "
        )


def test_non_string_input_rejected(
    classifier,
):
    with pytest.raises(
        TypeError
    ):
        classifier.predict(
            12345
        )


def test_invalid_negative_threshold_rejected():
    with pytest.raises(
        ValueError
    ):
        IntentClassifier(
            model_path=MODEL_PATH,
            confidence_threshold=-0.1,
        )


def test_invalid_high_threshold_rejected():
    with pytest.raises(
        ValueError
    ):
        IntentClassifier(
            model_path=MODEL_PATH,
            confidence_threshold=1.1,
        )


def test_missing_model_rejected():
    with pytest.raises(
        FileNotFoundError
    ):
        IntentClassifier(
            model_path=(
                ROOT
                / "models"
                / "does_not_exist.joblib"
            )
        )


def test_input_is_normalized(
    classifier,
):
    result = classifier.predict(
        "   install    nginx   "
    )

    assert (
        result.text
        == "install nginx"
    )


def test_prediction_can_convert_to_dictionary(
    classifier,
):
    result = classifier.predict(
        "install nginx"
    )

    data = result.to_dict()

    assert isinstance(
        data,
        dict,
    )

    assert (
        data["predicted_intent"]
        == result.predicted_intent
    )

    assert (
        data["confidence"]
        == result.confidence
    )


def test_classifier_has_no_execution_method(
    classifier,
):
    prohibited_methods = {
        "execute",
        "run_command",
        "run_shell",
        "shell",
    }

    for method in prohibited_methods:
        assert not hasattr(
            classifier,
            method,
        )