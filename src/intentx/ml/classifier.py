from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import joblib
import numpy as np


DEFAULT_CONFIDENCE_THRESHOLD = 0.50


@dataclass(frozen=True)
class IntentPrediction:
    """
    Result returned by the IntentX intent classifier.

    Important:
    A prediction is NOT authorization to execute an
    operating-system operation.
    """

    text: str
    predicted_intent: str
    confidence: float
    second_intent: str
    second_confidence: float
    margin: float
    accepted: bool
    decision: str

    def to_dict(self):
        return asdict(self)


class IntentClassifier:
    """
    Runtime interface for the trained IntentX
    intent-classification model.
    """

    def __init__(
        self,
        model_path: Path | str,
        confidence_threshold: float = (
            DEFAULT_CONFIDENCE_THRESHOLD
        ),
    ):
        self.model_path = Path(model_path)

        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError(
                "confidence_threshold must be "
                "between 0.0 and 1.0"
            )

        self.confidence_threshold = (
            confidence_threshold
        )

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model not found: {self.model_path}"
            )

        self.model = joblib.load(
            self.model_path
        )

        if not hasattr(
            self.model,
            "predict_proba",
        ):
            raise TypeError(
                "Loaded model does not support "
                "predict_proba()."
            )

        if not hasattr(
            self.model,
            "classes_",
        ):
            raise TypeError(
                "Loaded model does not expose classes_."
            )

    def predict(
        self,
        text: str,
    ) -> IntentPrediction:

        cleaned_text = self._validate_text(
            text
        )

        probabilities = (
            self.model.predict_proba(
                [cleaned_text]
            )[0]
        )

        classes = self.model.classes_

        order = np.argsort(
            probabilities
        )[::-1]

        first_index = int(order[0])
        second_index = int(order[1])

        predicted_intent = str(
            classes[first_index]
        )

        second_intent = str(
            classes[second_index]
        )

        confidence = float(
            probabilities[first_index]
        )

        second_confidence = float(
            probabilities[second_index]
        )

        margin = (
            confidence
            - second_confidence
        )

        accepted = (
            confidence
            >= self.confidence_threshold
        )

        decision = (
            "INTENT_ACCEPTED"
            if accepted
            else "CLARIFICATION_REQUIRED"
        )

        return IntentPrediction(
            text=cleaned_text,
            predicted_intent=predicted_intent,
            confidence=confidence,
            second_intent=second_intent,
            second_confidence=second_confidence,
            margin=margin,
            accepted=accepted,
            decision=decision,
        )

    @staticmethod
    def _validate_text(
        text: str,
    ) -> str:

        if not isinstance(text, str):
            raise TypeError(
                "Input must be a string."
            )

        cleaned = " ".join(
            text.strip().split()
        )

        if not cleaned:
            raise ValueError(
                "Input text cannot be empty."
            )

        return cleaned