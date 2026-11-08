import re
from dataclasses import asdict, dataclass
from typing import Dict, List


@dataclass(frozen=True)
class ExtractedEntity:
    entity_type: str
    value: str

    def to_dict(self):
        return asdict(self)


class EntityExtractor:
    """
    Deterministic entity extractor for IntentX.

    Extraction is constrained by the entity types
    expected for the classified intent.

    Unsupported requested entity types fail closed.

    This component does NOT:
    - execute commands
    - authorize operations
    - generate shell commands
    - assess risk
    """

    SUPPORTED_ENTITY_TYPES = frozenset(
        {
            "PID",
            "PORT",
            "PERMISSION",
            "DEVICE",
            "PATH",
            "SOURCE_PATH",
            "DESTINATION_PATH",
            "SERVICE",
            "PACKAGE",
            "USERNAME",
            "PATTERN",
        }
    )

    PID_CONTEXT_PATTERN = re.compile(
        r"\b(?:pid|process)\s*(?:id\s*)?"
        r"(?:number\s*)?[:#]?\s*(\d+)\b",
        re.IGNORECASE,
    )

    PORT_CONTEXT_PATTERN = re.compile(
        r"\bport\s*[:#]?\s*(\d{1,5})\b",
        re.IGNORECASE,
    )

    # Permission extraction is intentionally
    # context-aware.
    #
    # We do not search for arbitrary 3-4 digit
    # octal-looking numbers because values inside
    # paths, PIDs, filenames, etc. must not be
    # interpreted as permissions.
    PERMISSION_PATTERNS = [
        re.compile(
            r"\bchmod\s+([0-7]{3,4})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bpermissions?\s+"
            r"(?:to\s+)?([0-7]{3,4})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bmode\s+"
            r"(?:to\s+)?([0-7]{3,4})\b",
            re.IGNORECASE,
        ),
    ]

    DEVICE_PATTERN = re.compile(
        r"(?<!\S)(/dev/[A-Za-z0-9._/-]+)"
    )

    ABSOLUTE_PATH_PATTERN = re.compile(
        r"(?<!\S)(/(?!dev/)[^\s,;]+)"
    )

    SERVICE_PATTERNS = [
        re.compile(
            r"\b(?:status|start|stop|restart|reload)"
            r"\s+(?:the\s+)?"
            r"([A-Za-z0-9_.@-]+)"
            r"(?:\s+service)?\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:check|show)\s+"
            r"([A-Za-z0-9_.@-]+)"
            r"\s+(?:service\s+)?status\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:shut\s+down)\s+(?:the\s+)?"
            r"([A-Za-z0-9_.@-]+)"
            r"\s+service\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bis\s+([A-Za-z0-9_.@-]+)"
            r"\s+(?:service\s+)?running\b",
            re.IGNORECASE,
        ),
    ]

    PACKAGE_PATTERNS = [
        re.compile(
            r"\b(?:install|remove|uninstall)"
            r"\s+(?:package\s+)?"
            r"([A-Za-z0-9_.+:-]+)\b",
            re.IGNORECASE,
        ),
    ]

    USERNAME_PATTERNS = [
        re.compile(
            r"\b(?:owner|ownership)\s+"
            r"(?:to\s+)?"
            r"([A-Za-z_][A-Za-z0-9_.-]*)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bchown\s+"
            r"([A-Za-z_][A-Za-z0-9_.-]*)\b",
            re.IGNORECASE,
        ),
    ]

    PATTERN_PATTERNS = [
        re.compile(
            r"""["']([^"']+)["']"""
        ),
        re.compile(
            r"\b(?:search|find|grep)\s+"
            r"(?:for\s+)?"
            r"([A-Za-z0-9_.-]+)\b",
            re.IGNORECASE,
        ),
    ]

    def extract(
        self,
        text: str,
        expected_entities: List[str],
    ) -> Dict[str, str]:

        cleaned_text = self._validate_text(
            text
        )

        if not isinstance(
            expected_entities,
            list,
        ):
            raise TypeError(
                "expected_entities must be a list."
            )

        self._validate_expected_entities(
            expected_entities
        )

        entities = {}

        for entity_type in expected_entities:
            extractor = getattr(
                self,
                (
                    f"_extract_"
                    f"{entity_type.lower()}"
                ),
                None,
            )

            # Defense in depth.
            #
            # SUPPORTED_ENTITY_TYPES and extractor
            # methods should always remain aligned.
            # Never silently ignore a missing
            # implementation.
            if extractor is None:
                raise ValueError(
                    "No extractor implementation "
                    f"exists for entity type: "
                    f"{entity_type}"
                )

            value = extractor(
                cleaned_text
            )

            if value is not None:
                entities[entity_type] = value

        return entities

    @classmethod
    def _validate_expected_entities(
        cls,
        expected_entities,
    ):
        """
        Validate the requested extraction contract.

        Entity extraction is a security-sensitive
        boundary. Unknown entity types must not be
        silently ignored.
        """

        for entity_type in expected_entities:

            if not isinstance(
                entity_type,
                str,
            ):
                raise TypeError(
                    "Every expected entity type "
                    "must be a string."
                )

            cleaned = entity_type.strip()

            if not cleaned:
                raise ValueError(
                    "Expected entity type cannot "
                    "be empty."
                )

            if cleaned != entity_type:
                raise ValueError(
                    "Expected entity types must use "
                    "their canonical names without "
                    "surrounding whitespace."
                )

            if (
                entity_type
                not in cls.SUPPORTED_ENTITY_TYPES
            ):
                raise ValueError(
                    "Unsupported expected entity "
                    f"type: {entity_type}"
                )

    @staticmethod
    def _validate_text(
        text: str,
    ) -> str:

        if not isinstance(
            text,
            str,
        ):
            raise TypeError(
                "Input text must be a string."
            )

        cleaned = " ".join(
            text.strip().split()
        )

        if not cleaned:
            raise ValueError(
                "Input text cannot be empty."
            )

        return cleaned

    @staticmethod
    def _first_pattern_match(
        text,
        patterns,
    ):
        for pattern in patterns:
            match = pattern.search(
                text
            )

            if match:
                return match.group(1)

        return None

    def _extract_pid(
        self,
        text,
    ):
        match = (
            self.PID_CONTEXT_PATTERN.search(
                text
            )
        )

        return (
            match.group(1)
            if match
            else None
        )

    def _extract_port(
        self,
        text,
    ):
        match = (
            self.PORT_CONTEXT_PATTERN.search(
                text
            )
        )

        if not match:
            return None

        port = int(
            match.group(1)
        )

        if 1 <= port <= 65535:
            return str(port)

        return None

    def _extract_permission(
        self,
        text,
    ):
        return self._first_pattern_match(
            text,
            self.PERMISSION_PATTERNS,
        )

    def _extract_device(
        self,
        text,
    ):
        match = self.DEVICE_PATTERN.search(
            text
        )

        if match:
            return self._clean_token(
                match.group(1)
            )

        return None

    def _extract_path(
        self,
        text,
    ):
        paths = self._find_paths(
            text
        )

        if paths:
            return paths[0]

        return None

    def _extract_source_path(
        self,
        text,
    ):
        paths = self._find_paths(
            text
        )

        if paths:
            return paths[0]

        return None

    def _extract_destination_path(
        self,
        text,
    ):
        paths = self._find_paths(
            text
        )

        if len(paths) >= 2:
            return paths[1]

        return None

    def _extract_service(
        self,
        text,
    ):
        return self._first_pattern_match(
            text,
            self.SERVICE_PATTERNS,
        )

    def _extract_package(
        self,
        text,
    ):
        return self._first_pattern_match(
            text,
            self.PACKAGE_PATTERNS,
        )

    def _extract_username(
        self,
        text,
    ):
        return self._first_pattern_match(
            text,
            self.USERNAME_PATTERNS,
        )

    def _extract_pattern(
        self,
        text,
    ):
        return self._first_pattern_match(
            text,
            self.PATTERN_PATTERNS,
        )

    def _find_paths(
        self,
        text,
    ):
        matches = (
            self.ABSOLUTE_PATH_PATTERN.findall(
                text
            )
        )

        return [
            self._clean_token(path)
            for path in matches
        ]

    @staticmethod
    def _clean_token(
        value,
    ):
        return value.rstrip(
            ".,!?;:)]}"
        )