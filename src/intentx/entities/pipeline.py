from dataclasses import asdict, dataclass
from typing import Dict, List

from intentx.entities.extractor import EntityExtractor
from intentx.entities.validator import EntityValidator


@dataclass(frozen=True)
class EntityPipelineResult:
    text: str
    intent: str
    entities: Dict[str, str]
    required_entities: List[str]
    missing_entities: List[str]
    valid: bool
    decision: str

    def to_dict(self):
        return asdict(self)


class EntityPipeline:
    """
    Coordinates deterministic entity extraction
    and entity validation.

    The intent catalog determines which entity
    types are allowed and required.

    This component does NOT:
    - authorize execution
    - generate shell commands
    - execute commands
    - assess operational risk
    """

    def __init__(
        self,
        extractor=None,
        validator=None,
    ):
        self.extractor = (
            extractor or EntityExtractor()
        )

        self.validator = (
            validator or EntityValidator()
        )

    def process(
        self,
        text: str,
        intent: str,
    ) -> EntityPipelineResult:

        allowed_entities = (
            self.validator.get_allowed_entities(
                intent
            )
        )

        entities = self.extractor.extract(
            text,
            allowed_entities,
        )

        validation = self.validator.validate(
            intent,
            entities,
        )

        return EntityPipelineResult(
            text=text,
            intent=intent,
            entities=entities,
            required_entities=(
                validation.required_entities
            ),
            missing_entities=(
                validation.missing_entities
            ),
            valid=validation.valid,
            decision=validation.decision,
        )