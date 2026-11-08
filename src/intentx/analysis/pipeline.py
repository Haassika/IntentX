from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Optional

from intentx.entities.pipeline import EntityPipeline
from intentx.ml.classifier import IntentClassifier


DEFAULT_MODEL_PATH = Path(
    "models/intent_classifier_v2.joblib"
)


@dataclass(frozen=True)
class IntentAnalysisResult:
    text: str
    predicted_intent: str
    confidence: float
    second_intent: str
    second_confidence: float
    margin: float
    entities: Dict[str, str]
    intent_accepted: bool
    entities_valid: bool
    decision: str
    reason: str
    missing_entities: Optional[list]

    def to_dict(self):
        return asdict(self)


class IntentAnalysisPipeline:
    """
    Front-half analysis pipeline for IntentX.

    Processing order:

    1. ML intent classification
    2. Confidence gating
    3. Deterministic entity extraction
    4. Deterministic entity validation

    A successful result means only that the request
    is ready for operation planning.

    It does NOT mean the request is authorized
    for execution.
    """

    def __init__(
        self,
        model_path=DEFAULT_MODEL_PATH,
        confidence_threshold=0.50,
    ):
        self.classifier = IntentClassifier(
            model_path=model_path,
            confidence_threshold=confidence_threshold,
        )

        self.entity_pipeline = EntityPipeline()

    def analyze(
        self,
        text: str,
    ) -> IntentAnalysisResult:

        prediction = self.classifier.predict(
            text
        )

        if not prediction.accepted:
            return IntentAnalysisResult(
                text=prediction.text,
                predicted_intent=(
                    prediction.predicted_intent
                ),
                confidence=prediction.confidence,
                second_intent=(
                    prediction.second_intent
                ),
                second_confidence=(
                    prediction.second_confidence
                ),
                margin=prediction.margin,
                entities={},
                intent_accepted=False,
                entities_valid=False,
                decision=(
                    "CLARIFICATION_REQUIRED"
                ),
                reason=(
                    "Intent confidence is below "
                    "the configured threshold."
                ),
                missing_entities=None,
            )

        entity_result = (
            self.entity_pipeline.process(
                prediction.text,
                prediction.predicted_intent,
            )
        )

        if not entity_result.valid:
            return IntentAnalysisResult(
                text=prediction.text,
                predicted_intent=(
                    prediction.predicted_intent
                ),
                confidence=prediction.confidence,
                second_intent=(
                    prediction.second_intent
                ),
                second_confidence=(
                    prediction.second_confidence
                ),
                margin=prediction.margin,
                entities=entity_result.entities,
                intent_accepted=True,
                entities_valid=False,
                decision=(
                    "CLARIFICATION_REQUIRED"
                ),
                reason=(
                    "Required entity information "
                    "is missing or invalid."
                ),
                missing_entities=(
                    entity_result.missing_entities
                ),
            )

        return IntentAnalysisResult(
            text=prediction.text,
            predicted_intent=(
                prediction.predicted_intent
            ),
            confidence=prediction.confidence,
            second_intent=prediction.second_intent,
            second_confidence=(
                prediction.second_confidence
            ),
            margin=prediction.margin,
            entities=entity_result.entities,
            intent_accepted=True,
            entities_valid=True,
            decision="READY_FOR_PLANNING",
            reason=(
                "Intent confidence and entity "
                "requirements are satisfied."
            ),
            missing_entities=[],
        )