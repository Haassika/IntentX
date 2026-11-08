import posixpath
from collections.abc import Mapping
from pathlib import Path
from typing import List

import yaml

from intentx.planning.entity_contracts import (
    ActionEntityContracts,
)
from intentx.planning.models import OperationPlan
from intentx.validation.entity_semantics import (
    EntitySemanticValidator,
)
from intentx.validation.models import (
    OperationValidationResult,
    ValidationIssue,
)
from intentx.validation.operation_contracts import (
    OperationContractValidator,
)


DEFAULT_CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)


class OperationValidator:
    """
    Deterministically validates a proposed
    OperationPlan.

    Validation verifies that the plan remains
    consistent with:

    - the intent catalog
    - permitted actions
    - allowlisted executables
    - intent-level entity requirements
    - action-specific entity requirements
    - entity semantic rules
    - cross-entity rules
    - catalog security metadata
    - argument structure
    - the deterministic operation contract

    A valid result does NOT authorize execution.
    """

    def __init__(
        self,
        catalog_path=DEFAULT_CATALOG_PATH,
        entity_validator=None,
        contract_validator=None,
    ):
        self.catalog_path = Path(
            catalog_path
        )

        if not self.catalog_path.exists():
            raise FileNotFoundError(
                f"Intent catalog not found: "
                f"{self.catalog_path}"
            )

        with self.catalog_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            catalog = yaml.safe_load(file)

        if not isinstance(
            catalog,
            dict,
        ):
            raise ValueError(
                "Intent catalog must be a mapping."
            )

        self.intents = catalog.get(
            "intents"
        )

        if not isinstance(
            self.intents,
            dict,
        ):
            raise ValueError(
                "Intent catalog must contain "
                "an 'intents' mapping."
            )

        self.entity_validator = (
            entity_validator
            or EntitySemanticValidator()
        )

        self.contract_validator = (
            contract_validator
            or OperationContractValidator()
        )

    def validate(
        self,
        plan: OperationPlan,
    ) -> OperationValidationResult:
        """
        Validate a proposed operation plan.

        Validation is deterministic and
        fail-closed.

        Passing validation means only that the
        proposed operation is structurally and
        semantically consistent.

        It does not mean the operation is
        authorized to execute.
        """

        if not isinstance(
            plan,
            OperationPlan,
        ):
            raise TypeError(
                "plan must be an OperationPlan."
            )

        issues: List[ValidationIssue] = []

        config = self.intents.get(
            plan.intent
        )

        if not isinstance(
            config,
            dict,
        ):
            issues.append(
                self._issue(
                    "UNKNOWN_INTENT",
                    "Operation plan contains an "
                    "unknown intent.",
                    "intent",
                )
            )

            return self._invalid_result(
                issues
            )

        # -------------------------------------------------
        # Intent/action validation
        # -------------------------------------------------

        self._validate_action(
            plan,
            config,
            issues,
        )

        # -------------------------------------------------
        # Executable allowlist validation
        # -------------------------------------------------

        self._validate_executable(
            plan,
            config,
            issues,
        )

        # -------------------------------------------------
        # Intent-level entity validation
        # -------------------------------------------------

        self._validate_entities(
            plan,
            config,
            issues,
        )

        # -------------------------------------------------
        # Action-specific entity validation
        # -------------------------------------------------
        #
        # This is intentionally independent of
        # OperationPlanner.
        #
        # A caller may manually construct or tamper
        # with an OperationPlan. Validation therefore
        # re-checks the exact intent/action/entity
        # relationship rather than trusting that the
        # planner already checked it.

        self._validate_action_entity_contract(
            plan,
            issues,
        )

        # -------------------------------------------------
        # Cross-entity validation
        # -------------------------------------------------

        self._validate_cross_entity_rules(
            plan,
            issues,
        )

        # -------------------------------------------------
        # Security metadata validation
        # -------------------------------------------------

        self._validate_metadata(
            plan,
            config,
            issues,
        )

        # -------------------------------------------------
        # Structural argument validation
        # -------------------------------------------------

        self._validate_arguments(
            plan,
            issues,
        )

        # -------------------------------------------------
        # Deterministic operation contract
        # -------------------------------------------------
        #
        # Independently verify the exact relationship
        # between:
        #
        # intent
        # action
        # executable
        # arguments
        # entities
        #
        # An allowlisted executable alone is not enough.

        contract_issues = (
            self.contract_validator.validate(
                plan
            )
        )

        issues.extend(
            contract_issues
        )

        if issues:
            return self._invalid_result(
                issues
            )

        return OperationValidationResult(
            valid=True,
            decision="VALIDATED_OPERATION",
            issues=[],
            plan=plan,
        )

    def _validate_action(
        self,
        plan: OperationPlan,
        config: dict,
        issues: List[ValidationIssue],
    ):
        """
        Validate that the action is permitted for
        the declared intent.
        """

        allowed_actions = config.get(
            "actions",
            [],
        )

        if not isinstance(
            allowed_actions,
            list,
        ):
            issues.append(
                self._issue(
                    "INVALID_CATALOG_ACTIONS",
                    "Catalog actions must be "
                    "a list.",
                    "action",
                )
            )
            return

        if plan.action not in allowed_actions:
            issues.append(
                self._issue(
                    "ACTION_NOT_ALLOWED",
                    "Operation action is not "
                    "permitted for the intent.",
                    "action",
                )
            )

    def _validate_executable(
        self,
        plan: OperationPlan,
        config: dict,
        issues: List[ValidationIssue],
    ):
        """
        Validate that the selected executable is
        allowlisted for the intent.
        """

        allowed_executables = config.get(
            "allowed_executables",
            [],
        )

        if not isinstance(
            allowed_executables,
            list,
        ):
            issues.append(
                self._issue(
                    "INVALID_CATALOG_EXECUTABLES",
                    "Catalog executables must be "
                    "a list.",
                    "executable",
                )
            )
            return

        if (
            plan.executable
            not in allowed_executables
        ):
            issues.append(
                self._issue(
                    "EXECUTABLE_NOT_ALLOWED",
                    "Executable is not allowlisted "
                    "for the intent.",
                    "executable",
                )
            )

    def _validate_entities(
        self,
        plan: OperationPlan,
        config: dict,
        issues: List[ValidationIssue],
    ):
        """
        Validate entities against the broader
        intent-level entity configuration.

        Action-specific entity validation is
        performed separately.

        OperationPlan stores entities as a read-only
        Mapping. Validation requires read access only
        and must never mutate the plan.
        """

        if not isinstance(
            plan.entities,
            Mapping,
        ):
            issues.append(
                self._issue(
                    "INVALID_ENTITIES",
                    "Plan entities must be "
                    "a mapping.",
                    "entities",
                )
            )
            return

        allowed_entities = config.get(
            "entities",
            [],
        )

        required_entities = config.get(
            "required_entities",
            [],
        )

        if allowed_entities is None:
            allowed_entities = []

        if required_entities is None:
            required_entities = []

        if not isinstance(
            allowed_entities,
            list,
        ):
            issues.append(
                self._issue(
                    "INVALID_CATALOG_ENTITIES",
                    "Catalog entities must be "
                    "a list.",
                    "entities",
                )
            )
            return

        if not isinstance(
            required_entities,
            list,
        ):
            issues.append(
                self._issue(
                    "INVALID_REQUIRED_ENTITIES",
                    "Catalog required entities "
                    "must be a list.",
                    "entities",
                )
            )
            return

        # Reject entities that the classified
        # intent does not permit.
        for entity_type in plan.entities:

            if (
                entity_type
                not in allowed_entities
            ):
                issues.append(
                    self._issue(
                        "ENTITY_NOT_ALLOWED",
                        "Entity is not permitted "
                        "for the intent.",
                        entity_type,
                    )
                )

        # Verify all catalog-required entities
        # are present and non-empty.
        for entity_type in required_entities:

            value = plan.entities.get(
                entity_type
            )

            if (
                not isinstance(value, str)
                or not value.strip()
            ):
                issues.append(
                    self._issue(
                        "REQUIRED_ENTITY_MISSING",
                        "Required entity is "
                        "missing or empty.",
                        entity_type,
                    )
                )

        # Validate the semantic structure of all
        # supplied entities independently.
        semantic_issues = (
            self.entity_validator.validate(
                plan.entities
            )
        )

        issues.extend(
            semantic_issues
        )

    def _validate_action_entity_contract(
        self,
        plan: OperationPlan,
        issues: List[ValidationIssue],
    ):
        """
        Independently validate entities against the
        exact resolved intent/action combination.

        This protects the validation boundary even
        when an OperationPlan was constructed without
        using OperationPlanner.

        No supplied entity may be silently ignored.

        This method performs validation only and does
        not authorize execution.
        """

        # The broader entity validator reports the
        # structural error when entities is not a
        # Mapping. Avoid duplicate processing here.
        if not isinstance(
            plan.entities,
            Mapping,
        ):
            return

        failure = (
            ActionEntityContracts.validate(
                intent=plan.intent,
                action=plan.action,
                entities=plan.entities,
            )
        )

        if failure is not None:
            issues.append(
                self._issue(
                    "ACTION_ENTITY_CONTRACT_VIOLATION",
                    failure,
                    "entities",
                )
            )

    def _validate_cross_entity_rules(
        self,
        plan: OperationPlan,
        issues: List[ValidationIssue],
    ):
        """
        Validate relationships between entities.

        Individual entity values may each be valid
        while their combination is invalid.

        POSIX lexical normalization is used only
        for comparison.

        No filesystem access, canonicalization,
        symlink resolution or command execution
        occurs here.
        """

        # If entities has an invalid structural type,
        # _validate_entities() already reports it.
        if not isinstance(
            plan.entities,
            Mapping,
        ):
            return

        source = plan.entities.get(
            "SOURCE_PATH"
        )

        destination = plan.entities.get(
            "DESTINATION_PATH"
        )

        if not (
            isinstance(source, str)
            and isinstance(destination, str)
            and source.strip()
            and destination.strip()
        ):
            return

        normalized_source = (
            posixpath.normpath(
                source
            )
        )

        normalized_destination = (
            posixpath.normpath(
                destination
            )
        )

        if (
            normalized_source
            == normalized_destination
        ):
            issues.append(
                self._issue(
                    "SOURCE_EQUALS_DESTINATION",
                    "Source and destination paths "
                    "must be different.",
                    "DESTINATION_PATH",
                )
            )

    def _validate_metadata(
        self,
        plan: OperationPlan,
        config: dict,
        issues: List[ValidationIssue],
    ):
        """
        Verify security-relevant metadata against
        the catalog.

        A caller cannot downgrade an operation by
        altering metadata in the OperationPlan.
        """

        expected_state_changing = config.get(
            "state_changing",
            False,
        )

        expected_privilege = config.get(
            "privilege_required",
            False,
        )

        expected_critical = config.get(
            "critical_operation",
            False,
        )

        if (
            plan.state_changing
            != expected_state_changing
        ):
            issues.append(
                self._issue(
                    "STATE_METADATA_MISMATCH",
                    "state_changing does not "
                    "match the intent catalog.",
                    "state_changing",
                )
            )

        if (
            plan.privilege_required
            != expected_privilege
        ):
            issues.append(
                self._issue(
                    "PRIVILEGE_METADATA_MISMATCH",
                    "privilege_required does not "
                    "match the intent catalog.",
                    "privilege_required",
                )
            )

        if (
            plan.critical_operation
            != expected_critical
        ):
            issues.append(
                self._issue(
                    "CRITICAL_METADATA_MISMATCH",
                    "critical_operation does not "
                    "match the intent catalog.",
                    "critical_operation",
                )
            )

    def _validate_arguments(
        self,
        plan: OperationPlan,
        issues: List[ValidationIssue],
    ):
        """
        Perform structural executable and argument
        validation.

        OperationPlan stores arguments as an
        immutable tuple.

        Exact argument semantics are independently
        verified by OperationContractValidator.
        """

        if not isinstance(
            plan.executable,
            str,
        ):
            issues.append(
                self._issue(
                    "INVALID_EXECUTABLE",
                    "Executable must be "
                    "a string.",
                    "executable",
                )
            )

        elif not plan.executable.strip():
            issues.append(
                self._issue(
                    "INVALID_EXECUTABLE",
                    "Executable cannot be empty.",
                    "executable",
                )
            )

        if not isinstance(
            plan.arguments,
            tuple,
        ):
            issues.append(
                self._issue(
                    "INVALID_ARGUMENTS",
                    "Arguments must be an "
                    "immutable tuple.",
                    "arguments",
                )
            )
            return

        for index, argument in enumerate(
            plan.arguments
        ):
            if not isinstance(
                argument,
                str,
            ):
                issues.append(
                    self._issue(
                        "INVALID_ARGUMENT_TYPE",
                        "Every argument must be "
                        "a string.",
                        (
                            f"arguments[{index}]"
                        ),
                    )
                )
                continue

            if "\x00" in argument:
                issues.append(
                    self._issue(
                        "NULL_BYTE_ARGUMENT",
                        "Arguments cannot contain "
                        "null bytes.",
                        (
                            f"arguments[{index}]"
                        ),
                    )
                )

    @staticmethod
    def _issue(
        code: str,
        message: str,
        field: str = None,
    ) -> ValidationIssue:
        """
        Construct a deterministic validation issue.
        """

        return ValidationIssue(
            code=code,
            message=message,
            field=field,
        )

    @staticmethod
    def _invalid_result(
        issues: List[ValidationIssue],
    ) -> OperationValidationResult:
        """
        Produce a fail-closed validation result.

        Invalid operations do not carry a plan
        forward as an authorized operation.
        """

        return OperationValidationResult(
            valid=False,
            decision="VALIDATION_FAILED",
            issues=issues,
            plan=None,
        )