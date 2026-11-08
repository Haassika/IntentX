from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List

import yaml


DEFAULT_CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)


@dataclass(frozen=True)
class EntityValidationResult:
    intent: str
    valid: bool
    decision: str
    required_entities: List[str]
    allowed_entities: List[str]
    present_entities: List[str]
    missing_entities: List[str]
    unexpected_entities: List[str]

    def to_dict(self):
        return asdict(self)


class EntityValidator:
    """
    Deterministic entity validator for IntentX.

    The intent catalog is the authority for:
    - allowed entity types
    - required entity types

    This component does NOT:
    - execute commands
    - authorize execution
    - generate shell commands
    - assess operational risk
    """

    def __init__(
        self,
        catalog_path=DEFAULT_CATALOG_PATH,
    ):
        self.catalog_path = Path(catalog_path)

        if not self.catalog_path.exists():
            raise FileNotFoundError(
                f"Intent catalog not found: "
                f"{self.catalog_path}"
            )

        with self.catalog_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            self.catalog = yaml.safe_load(file)

        if not isinstance(self.catalog, dict):
            raise ValueError(
                "Intent catalog must contain "
                "a YAML mapping."
            )

        self.intents = self.catalog.get(
            "intents"
        )

        if not isinstance(self.intents, dict):
            raise ValueError(
                "Intent catalog must contain "
                "an 'intents' mapping."
            )

    def get_allowed_entities(
        self,
        intent: str,
    ) -> List[str]:
        config = self._get_intent_config(
            intent
        )

        return list(
            config.get("entities", [])
        )

    def get_required_entities(
        self,
        intent: str,
    ) -> List[str]:
        config = self._get_intent_config(
            intent
        )

        return list(
            config.get(
                "required_entities",
                [],
            )
        )

    def validate(
        self,
        intent: str,
        entities: Dict[str, str],
    ) -> EntityValidationResult:

        if not isinstance(entities, dict):
            raise TypeError(
                "entities must be a dictionary."
            )

        allowed = self.get_allowed_entities(
            intent
        )

        required = self.get_required_entities(
            intent
        )

        present = list(entities.keys())

        unexpected = [
            entity
            for entity in present
            if entity not in allowed
        ]

        missing = [
            entity
            for entity in required
            if (
                entity not in entities
                or not self._has_value(
                    entities[entity]
                )
            )
        ]

        valid = (
            not missing
            and not unexpected
        )

        decision = (
            "ENTITY_VALIDATED"
            if valid
            else "CLARIFICATION_REQUIRED"
        )

        return EntityValidationResult(
            intent=intent,
            valid=valid,
            decision=decision,
            required_entities=required,
            allowed_entities=allowed,
            present_entities=present,
            missing_entities=missing,
            unexpected_entities=unexpected,
        )

    def _get_intent_config(
        self,
        intent: str,
    ) -> dict:

        if not isinstance(intent, str):
            raise TypeError(
                "intent must be a string."
            )

        intent = intent.strip()

        if not intent:
            raise ValueError(
                "intent cannot be empty."
            )

        if intent not in self.intents:
            raise ValueError(
                f"Unknown intent: {intent}"
            )

        config = self.intents[intent]

        if not isinstance(config, dict):
            raise ValueError(
                f"Invalid catalog configuration "
                f"for intent: {intent}"
            )

        return config

    @staticmethod
    def _has_value(value) -> bool:
        if value is None:
            return False

        if isinstance(value, str):
            return bool(value.strip())

        return True