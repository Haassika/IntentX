from collections.abc import Mapping
from dataclasses import dataclass
from typing import (
    Dict,
    FrozenSet,
    Optional,
    Tuple,
)


@dataclass(frozen=True)
class ActionEntityContract:
    """
    Defines the exact entity semantics for one
    deterministic intent/action combination.

    allowed:
        Entity names that may be supplied.

    required:
        Entity names that must be supplied.

    This contract performs no execution and grants
    no authorization.
    """

    allowed: FrozenSet[str]
    required: FrozenSet[str]


class ActionEntityContracts:
    """
    Central registry of action-specific entity
    contracts.

    Intent-level entity permissions may be broader.
    Once an action has been resolved, this registry
    narrows the accepted entity set.

    No supplied entity may be silently ignored.
    """

    CONTRACTS: Dict[
        Tuple[str, str],
        ActionEntityContract,
    ] = {
        # -------------------------------------------------
        # System information
        # -------------------------------------------------
        (
            "system_information",
            "show_os",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),
        (
            "system_information",
            "show_kernel",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),
        (
            "system_information",
            "show_architecture",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),
        (
            "system_information",
            "show_hostname",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),

        # -------------------------------------------------
        # Storage inspection
        # -------------------------------------------------
        (
            "storage_inspection",
            "filesystem_usage",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset(),
        ),
        (
            "storage_inspection",
            "directory_size",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset({"PATH"}),
        ),

        # -------------------------------------------------
        # Memory inspection
        # -------------------------------------------------
        (
            "memory_inspection",
            "memory_usage",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),

        # -------------------------------------------------
        # Process inspection
        # -------------------------------------------------
        (
            "process_inspection",
            "list",
        ): ActionEntityContract(
            allowed=frozenset({"PATTERN"}),
            required=frozenset(),
        ),
        (
            "process_inspection",
            "inspect",
        ): ActionEntityContract(
            allowed=frozenset({"PID"}),
            required=frozenset({"PID"}),
        ),

        # -------------------------------------------------
        # Service inspection
        # -------------------------------------------------
        (
            "service_inspection",
            "status",
        ): ActionEntityContract(
            allowed=frozenset({"SERVICE"}),
            required=frozenset({"SERVICE"}),
        ),

        # -------------------------------------------------
        # Network inspection
        # -------------------------------------------------
        #
        # V1 does not implement PORT-specific filtering.
        # Therefore PORT must not be accepted and then
        # silently ignored.
        (
            "network_inspection",
            "interfaces",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),
        (
            "network_inspection",
            "connections",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),
        (
            "network_inspection",
            "listening_ports",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),

        # -------------------------------------------------
        # File listing
        # -------------------------------------------------
        (
            "file_listing",
            "list",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset(),
        ),

        # -------------------------------------------------
        # File reading
        # -------------------------------------------------
        (
            "file_read",
            "read",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset({"PATH"}),
        ),
        (
            "file_read",
            "head",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset({"PATH"}),
        ),
        (
            "file_read",
            "tail",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset({"PATH"}),
        ),

        # -------------------------------------------------
        # File search
        # -------------------------------------------------
        (
            "file_search",
            "find",
        ): ActionEntityContract(
            allowed=frozenset({
                "PATH",
                "PATTERN",
            }),
            required=frozenset({
                "PATTERN",
            }),
        ),

        # -------------------------------------------------
        # Text search
        # -------------------------------------------------
        (
            "text_search",
            "search",
        ): ActionEntityContract(
            allowed=frozenset({
                "PATTERN",
                "PATH",
            }),
            required=frozenset({
                "PATTERN",
                "PATH",
            }),
        ),

        # -------------------------------------------------
        # File creation
        # -------------------------------------------------
        (
            "file_create",
            "create_file",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset({"PATH"}),
        ),
        (
            "file_create",
            "create_directory",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset({"PATH"}),
        ),

        # -------------------------------------------------
        # File copy
        # -------------------------------------------------
        (
            "file_copy",
            "copy",
        ): ActionEntityContract(
            allowed=frozenset({
                "SOURCE_PATH",
                "DESTINATION_PATH",
            }),
            required=frozenset({
                "SOURCE_PATH",
                "DESTINATION_PATH",
            }),
        ),

        # -------------------------------------------------
        # File move / rename
        # -------------------------------------------------
        (
            "file_move",
            "move",
        ): ActionEntityContract(
            allowed=frozenset({
                "SOURCE_PATH",
                "DESTINATION_PATH",
            }),
            required=frozenset({
                "SOURCE_PATH",
                "DESTINATION_PATH",
            }),
        ),
        (
            "file_move",
            "rename",
        ): ActionEntityContract(
            allowed=frozenset({
                "SOURCE_PATH",
                "DESTINATION_PATH",
            }),
            required=frozenset({
                "SOURCE_PATH",
                "DESTINATION_PATH",
            }),
        ),

        # -------------------------------------------------
        # File deletion
        # -------------------------------------------------
        (
            "file_delete",
            "delete",
        ): ActionEntityContract(
            allowed=frozenset({"PATH"}),
            required=frozenset({"PATH"}),
        ),

        # -------------------------------------------------
        # Permission changes
        # -------------------------------------------------
        (
            "permission_change",
            "chmod",
        ): ActionEntityContract(
            allowed=frozenset({
                "PATH",
                "PERMISSION",
            }),
            required=frozenset({
                "PATH",
                "PERMISSION",
            }),
        ),
        (
            "permission_change",
            "chown",
        ): ActionEntityContract(
            allowed=frozenset({
                "PATH",
                "USERNAME",
            }),
            required=frozenset({
                "PATH",
                "USERNAME",
            }),
        ),

        # -------------------------------------------------
        # Process termination
        # -------------------------------------------------
        (
            "process_termination",
            "terminate",
        ): ActionEntityContract(
            allowed=frozenset({"PID"}),
            required=frozenset({"PID"}),
        ),
        (
            "process_termination",
            "force_terminate",
        ): ActionEntityContract(
            allowed=frozenset({"PID"}),
            required=frozenset({"PID"}),
        ),

        # -------------------------------------------------
        # Service management
        # -------------------------------------------------
        (
            "service_management",
            "start",
        ): ActionEntityContract(
            allowed=frozenset({"SERVICE"}),
            required=frozenset({"SERVICE"}),
        ),
        (
            "service_management",
            "stop",
        ): ActionEntityContract(
            allowed=frozenset({"SERVICE"}),
            required=frozenset({"SERVICE"}),
        ),
        (
            "service_management",
            "restart",
        ): ActionEntityContract(
            allowed=frozenset({"SERVICE"}),
            required=frozenset({"SERVICE"}),
        ),
        (
            "service_management",
            "reload",
        ): ActionEntityContract(
            allowed=frozenset({"SERVICE"}),
            required=frozenset({"SERVICE"}),
        ),

        # -------------------------------------------------
        # Package management
        # -------------------------------------------------
        (
            "package_management",
            "install",
        ): ActionEntityContract(
            allowed=frozenset({"PACKAGE"}),
            required=frozenset({"PACKAGE"}),
        ),
        (
            "package_management",
            "remove",
        ): ActionEntityContract(
            allowed=frozenset({"PACKAGE"}),
            required=frozenset({"PACKAGE"}),
        ),

        # apt-get update refreshes package metadata.
        # V1 does not support a package-specific
        # interpretation for this action.
        (
            "package_management",
            "update",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),

        # -------------------------------------------------
        # System power
        # -------------------------------------------------
        (
            "system_power",
            "reboot",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),
        (
            "system_power",
            "shutdown",
        ): ActionEntityContract(
            allowed=frozenset(),
            required=frozenset(),
        ),

        # -------------------------------------------------
        # Disk management
        # -------------------------------------------------
        (
            "disk_management",
            "format",
        ): ActionEntityContract(
            allowed=frozenset({"DEVICE"}),
            required=frozenset({"DEVICE"}),
        ),
    }

    @classmethod
    def get(
        cls,
        intent: str,
        action: str,
    ) -> Optional[ActionEntityContract]:
        """
        Return the action-specific entity contract.

        None means that no supported contract exists.
        """

        return cls.CONTRACTS.get(
            (
                intent,
                action,
            )
        )

    @classmethod
    def validate(
        cls,
        intent: str,
        action: str,
        entities: Mapping[str, str],
    ) -> Optional[str]:
        """
        Validate the supplied entities against the
        exact resolved intent/action combination.

        A read-only Mapping is sufficient because
        contract validation never mutates entities.

        Returns:
            None
                The entity set satisfies the contract.

            str
                Deterministic failure reason.

        Validation is deliberately fail-closed.
        """

        if not isinstance(
            entities,
            Mapping,
        ):
            raise TypeError(
                "entities must be a mapping."
            )

        contract = cls.get(
            intent=intent,
            action=action,
        )

        if contract is None:
            return (
                "No action-specific entity contract "
                "exists for the resolved operation."
            )

        supplied = set(
            entities.keys()
        )

        unexpected = (
            supplied - contract.allowed
        )

        if unexpected:
            names = ", ".join(
                sorted(unexpected)
            )

            return (
                "Entity not permitted for resolved "
                f"action: {names}"
            )

        missing = []

        for name in sorted(
            contract.required
        ):
            value = entities.get(name)

            if (
                not isinstance(value, str)
                or not value.strip()
            ):
                missing.append(name)

        if missing:
            names = ", ".join(
                missing
            )

            return (
                "Required entity missing for "
                f"resolved action: {names}"
            )

        return None