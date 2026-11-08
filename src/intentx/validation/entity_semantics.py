import re
from collections.abc import Mapping
from typing import List

from intentx.validation.models import ValidationIssue


class EntitySemanticValidator:
    """
    Deterministically validates semantic properties
    of extracted entities.

    This validator does not:
    - execute commands
    - authorize operations
    - modify entities
    - infer missing entities
    - resolve paths against the host filesystem

    Invalid or unsupported values fail closed.
    """

    SUPPORTED_ENTITY_TYPES = {
        "PATH",
        "SOURCE_PATH",
        "DESTINATION_PATH",
        "SERVICE",
        "PID",
        "PACKAGE",
        "USERNAME",
        "PERMISSION",
        "PORT",
        "PATTERN",
        "DEVICE",
    }

    SERVICE_PATTERN = re.compile(
        r"^[A-Za-z0-9_.@-]+$"
    )

    PACKAGE_PATTERN = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9.+:-]*$"
    )

    USERNAME_PATTERN = re.compile(
        r"^[A-Za-z_][A-Za-z0-9_-]*\$?$"
    )

    NUMERIC_PERMISSION_PATTERN = re.compile(
        r"^[0-7]{3,4}$"
    )

    SYMBOLIC_PERMISSION_PATTERN = re.compile(
        r"^[ugoa]*[+=-][rwxXst]+"
        r"(?:,[ugoa]*[+=-][rwxXst]+)*$"
    )

    # Validate characters only.
    #
    # Structural / traversal validation is handled
    # separately in _validate_device().
    DEVICE_COMPONENT_PATTERN = re.compile(
        r"^[A-Za-z0-9._+:-]+$"
    )

    CONTROL_CHARACTER_PATTERN = re.compile(
        r"[\x00-\x1f\x7f]"
    )

    def validate(
        self,
        entities: Mapping[str, str],
    ) -> List[ValidationIssue]:
        """
        Validate all supplied entities.

        The validator accepts a read-only Mapping
        contract because semantic validation does not
        need to mutate the supplied entities.

        Returns an empty list when every supplied
        entity passes semantic validation.
        """

        if not isinstance(
            entities,
            Mapping,
        ):
            raise TypeError(
                "entities must be a mapping."
            )

        issues: List[ValidationIssue] = []

        for entity_type, value in entities.items():

            if entity_type not in (
                self.SUPPORTED_ENTITY_TYPES
            ):
                issues.append(
                    ValidationIssue(
                        code="UNSUPPORTED_ENTITY",
                        message=(
                            "Entity type is not "
                            "supported."
                        ),
                        field=entity_type,
                    )
                )
                continue

            if not isinstance(value, str):
                issues.append(
                    ValidationIssue(
                        code="INVALID_ENTITY_TYPE",
                        message=(
                            "Entity value must be "
                            "a string."
                        ),
                        field=entity_type,
                    )
                )
                continue

            if not value.strip():
                issues.append(
                    ValidationIssue(
                        code="EMPTY_ENTITY",
                        message=(
                            "Entity value cannot "
                            "be empty."
                        ),
                        field=entity_type,
                    )
                )
                continue

            if (
                self.CONTROL_CHARACTER_PATTERN.search(
                    value
                )
            ):
                issues.append(
                    ValidationIssue(
                        code="CONTROL_CHARACTER",
                        message=(
                            "Entity contains a "
                            "control character."
                        ),
                        field=entity_type,
                    )
                )
                continue

            validator = getattr(
                self,
                (
                    f"_validate_"
                    f"{entity_type.lower()}"
                ),
                None,
            )

            if validator is None:
                issues.append(
                    ValidationIssue(
                        code=(
                            "MISSING_ENTITY_VALIDATOR"
                        ),
                        message=(
                            "No semantic validator "
                            "exists for entity type."
                        ),
                        field=entity_type,
                    )
                )
                continue

            issue = validator(value)

            if issue is not None:
                issues.append(issue)

        return issues

    @staticmethod
    def _issue(
        code: str,
        message: str,
        field: str,
    ) -> ValidationIssue:

        return ValidationIssue(
            code=code,
            message=message,
            field=field,
        )

    def _validate_pid(
        self,
        value: str,
    ):
        if not value.isdigit():
            return self._issue(
                "INVALID_PID",
                "PID must be a positive integer.",
                "PID",
            )

        pid = int(value)

        if pid <= 0:
            return self._issue(
                "INVALID_PID",
                "PID must be greater than zero.",
                "PID",
            )

        return None

    def _validate_port(
        self,
        value: str,
    ):
        if not value.isdigit():
            return self._issue(
                "INVALID_PORT",
                "Port must be an integer.",
                "PORT",
            )

        port = int(value)

        if not 1 <= port <= 65535:
            return self._issue(
                "INVALID_PORT",
                (
                    "Port must be between "
                    "1 and 65535."
                ),
                "PORT",
            )

        return None

    def _validate_permission(
        self,
        value: str,
    ):
        if (
            self.NUMERIC_PERMISSION_PATTERN.fullmatch(
                value
            )
            or
            self.SYMBOLIC_PERMISSION_PATTERN.fullmatch(
                value
            )
        ):
            return None

        return self._issue(
            "INVALID_PERMISSION",
            "Permission format is invalid.",
            "PERMISSION",
        )

    def _validate_service(
        self,
        value: str,
    ):
        if not self.SERVICE_PATTERN.fullmatch(
            value
        ):
            return self._issue(
                "INVALID_SERVICE",
                (
                    "Service name contains "
                    "unsupported characters."
                ),
                "SERVICE",
            )

        return None

    def _validate_package(
        self,
        value: str,
    ):
        if not self.PACKAGE_PATTERN.fullmatch(
            value
        ):
            return self._issue(
                "INVALID_PACKAGE",
                (
                    "Package name contains "
                    "unsupported characters."
                ),
                "PACKAGE",
            )

        return None

    def _validate_username(
        self,
        value: str,
    ):
        if not self.USERNAME_PATTERN.fullmatch(
            value
        ):
            return self._issue(
                "INVALID_USERNAME",
                "Username format is invalid.",
                "USERNAME",
            )

        return None

    def _validate_device(
        self,
        value: str,
    ):
        """
        Validate a Linux /dev/... path lexically.

        Examples accepted:
            /dev/sdb
            /dev/nvme0n1
            /dev/mapper/vg-root
            /dev/disk/by-id/example

        Examples rejected:
            /dev/
            /dev/../etc/passwd
            /dev/./sdb
            /dev//sdb
            /etc/sdb

        No filesystem access or path resolution is
        performed.
        """

        if not value.startswith("/dev/"):
            return self._issue(
                "INVALID_DEVICE",
                (
                    "Device must be located "
                    "under /dev/."
                ),
                "DEVICE",
            )

        remainder = value[len("/dev/"):]

        if not remainder:
            return self._issue(
                "INVALID_DEVICE",
                (
                    "Device path must identify "
                    "a device below /dev/."
                ),
                "DEVICE",
            )

        # Preserve the raw components instead of
        # normalizing them first. Normalization
        # could hide '.' or '..' traversal.
        components = remainder.split("/")

        for component in components:

            if not component:
                return self._issue(
                    "INVALID_DEVICE",
                    (
                        "Device path cannot contain "
                        "empty path components."
                    ),
                    "DEVICE",
                )

            if component in {".", ".."}:
                return self._issue(
                    "INVALID_DEVICE",
                    (
                        "Device path cannot contain "
                        "'.' or '..' components."
                    ),
                    "DEVICE",
                )

            if not (
                self.DEVICE_COMPONENT_PATTERN.fullmatch(
                    component
                )
            ):
                return self._issue(
                    "INVALID_DEVICE",
                    (
                        "Device path contains "
                        "unsupported characters."
                    ),
                    "DEVICE",
                )

        return None

    def _validate_path(
        self,
        value: str,
    ):
        return self._validate_path_value(
            value,
            "PATH",
        )

    def _validate_source_path(
        self,
        value: str,
    ):
        return self._validate_path_value(
            value,
            "SOURCE_PATH",
        )

    def _validate_destination_path(
        self,
        value: str,
    ):
        return self._validate_path_value(
            value,
            "DESTINATION_PATH",
        )

    def _validate_path_value(
        self,
        value: str,
        field: str,
    ):
        if "\x00" in value:
            return self._issue(
                "INVALID_PATH",
                "Path contains a null byte.",
                field,
            )

        if value.startswith("-"):
            return self._issue(
                "INVALID_PATH",
                "Path cannot begin with '-'.",
                field,
            )

        return None

    def _validate_pattern(
        self,
        value: str,
    ):
        if "\x00" in value:
            return self._issue(
                "INVALID_PATTERN",
                (
                    "Search pattern contains "
                    "a null byte."
                ),
                "PATTERN",
            )

        return None