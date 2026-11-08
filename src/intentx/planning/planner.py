from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml

from intentx.planning.action_resolver import ActionResolver
from intentx.planning.entity_contracts import (
    ActionEntityContracts,
)
from intentx.planning.models import OperationPlan


DEFAULT_CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)


@dataclass(frozen=True)
class PlanningResult:
    """
    Result produced by the deterministic
    OperationPlanner.

    planned=True means that a structured
    OperationPlan was successfully created.

    Planning does NOT authorize execution.
    """

    planned: bool
    decision: str
    reason: str
    plan: Optional[OperationPlan]


class OperationPlanner:
    """
    Convert a validated intent and entity set into a
    structured OperationPlan.

    Security properties:
    - no shell command strings
    - no shell execution
    - no authorization
    - action must be catalog-approved
    - action/entity combination must be approved
    - executable must be catalog-approved
    - arguments are represented as a list
    - missing required planning entities fail closed
    - unexpected action-specific entities fail closed
    - supported path operands use explicit option
      termination where appropriate
    """

    ACTION_EXECUTABLES = {
        "show_os": "uname",
        "show_kernel": "uname",
        "show_architecture": "uname",
        "show_hostname": "hostname",

        "filesystem_usage": "df",
        "directory_size": "du",

        "memory_usage": "free",

        "list": None,
        "inspect": "ps",

        "status": "systemctl",

        "interfaces": "ip",
        "connections": "ss",
        "listening_ports": "ss",

        "read": "cat",
        "head": "head",
        "tail": "tail",

        "find": "find",
        "search": "grep",

        "create_file": "touch",
        "create_directory": "mkdir",

        "copy": "cp",
        "move": "mv",
        "rename": "mv",
        "delete": "rm",

        "chmod": "chmod",
        "chown": "chown",

        "terminate": "kill",
        "force_terminate": "kill",

        "start": "systemctl",
        "stop": "systemctl",
        "restart": "systemctl",
        "reload": "systemctl",

        "install": "apt-get",
        "remove": "apt-get",
        "update": "apt-get",

        "reboot": "reboot",
        "shutdown": "shutdown",

        "format": "mkfs",
    }

    def __init__(
        self,
        catalog_path=DEFAULT_CATALOG_PATH,
        action_resolver=None,
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

        self.action_resolver = (
            action_resolver
            or ActionResolver(
                catalog_path=self.catalog_path
            )
        )

        self.argument_builders: Dict[
            str,
            Callable[
                [Dict[str, str]],
                List[str],
            ],
        ] = {
            "show_os": (
                lambda entities: ["-s"]
            ),
            "show_kernel": (
                lambda entities: ["-r"]
            ),
            "show_architecture": (
                lambda entities: ["-m"]
            ),
            "show_hostname": (
                lambda entities: []
            ),

            "filesystem_usage": (
                self._build_filesystem_usage
            ),
            "directory_size": (
                self._build_directory_size
            ),

            "memory_usage": (
                lambda entities: ["-h"]
            ),

            "inspect": (
                self._build_process_inspect
            ),

            "status": (
                self._build_service_status
            ),

            "interfaces": (
                lambda entities: ["addr"]
            ),
            "connections": (
                lambda entities: ["-tun"]
            ),
            "listening_ports": (
                lambda entities: ["-lnt"]
            ),

            "read": self._build_path_only,
            "head": self._build_path_only,
            "tail": self._build_path_only,

            "find": self._build_file_search,
            "search": self._build_text_search,

            "create_file": self._build_path_only,
            "create_directory": (
                self._build_path_only
            ),

            "copy": (
                self._build_source_destination
            ),
            "move": (
                self._build_source_destination
            ),
            "rename": (
                self._build_source_destination
            ),
            "delete": self._build_path_only,

            "chmod": self._build_chmod,
            "chown": self._build_chown,

            "terminate": self._build_terminate,
            "force_terminate": (
                self._build_force_terminate
            ),

            "start": self._build_service_target,
            "stop": self._build_service_target,
            "restart": (
                self._build_service_target
            ),
            "reload": (
                self._build_service_target
            ),

            "install": (
                self._build_package_install
            ),
            "remove": (
                self._build_package_remove
            ),
            "update": (
                lambda entities: ["update"]
            ),

            "reboot": lambda entities: [],
            "shutdown": (
                lambda entities: ["-h", "now"]
            ),

            "format": self._build_format,
        }

    def plan(
        self,
        text: str,
        intent: str,
        entities: Dict[str, str],
    ) -> PlanningResult:
        """
        Create a structured operation plan.

        This method performs planning only.
        It does not execute or authorize anything.
        """

        if not isinstance(
            entities,
            dict,
        ):
            raise TypeError(
                "entities must be a dictionary."
            )

        config = self._get_intent_config(
            intent
        )

        resolution = (
            self.action_resolver.resolve(
                text,
                intent,
            )
        )

        if not resolution.resolved:
            return PlanningResult(
                planned=False,
                decision="CLARIFICATION_REQUIRED",
                reason=resolution.reason,
                plan=None,
            )

        action = resolution.action

        allowed_actions = config.get(
            "actions",
            [],
        )

        if not isinstance(
            allowed_actions,
            list,
        ):
            raise ValueError(
                f"Actions for intent "
                f"'{intent}' must be a list."
            )

        if action not in allowed_actions:
            return PlanningResult(
                planned=False,
                decision="PLANNING_DENIED",
                reason=(
                    "Resolved action is not "
                    "permitted for the intent."
                ),
                plan=None,
            )

        entity_contract_failure = (
            ActionEntityContracts.validate(
                intent=intent,
                action=action,
                entities=entities,
            )
        )

        if entity_contract_failure is not None:
            return PlanningResult(
                planned=False,
                decision=(
                    "CLARIFICATION_REQUIRED"
                ),
                reason=entity_contract_failure,
                plan=None,
            )

        try:
            executable = (
                self._resolve_executable(
                    intent=intent,
                    action=action,
                    entities=entities,
                )
            )
        except ValueError as exc:
            return PlanningResult(
                planned=False,
                decision="PLANNING_DENIED",
                reason=str(exc),
                plan=None,
            )

        allowed_executables = config.get(
            "allowed_executables",
            [],
        )

        if not isinstance(
            allowed_executables,
            list,
        ):
            raise ValueError(
                f"Allowed executables for intent "
                f"'{intent}' must be a list."
            )

        if (
            executable
            not in allowed_executables
        ):
            return PlanningResult(
                planned=False,
                decision="PLANNING_DENIED",
                reason=(
                    "Selected executable is not "
                    "allowlisted for the intent."
                ),
                plan=None,
            )

        builder = self.argument_builders.get(
            action
        )

        if action == "list":
            try:
                arguments = (
                    self._build_list_arguments(
                        intent,
                        entities,
                    )
                )
            except ValueError as exc:
                return PlanningResult(
                    planned=False,
                    decision=(
                        "CLARIFICATION_REQUIRED"
                    ),
                    reason=str(exc),
                    plan=None,
                )

        else:
            if builder is None:
                return PlanningResult(
                    planned=False,
                    decision="PLANNING_DENIED",
                    reason=(
                        "No deterministic argument "
                        "builder exists for action."
                    ),
                    plan=None,
                )

            try:
                arguments = builder(
                    entities
                )
            except ValueError as exc:
                return PlanningResult(
                    planned=False,
                    decision=(
                        "CLARIFICATION_REQUIRED"
                    ),
                    reason=str(exc),
                    plan=None,
                )

        if intent == "service_management":
            arguments = [
                action,
                *arguments,
            ]

        plan = OperationPlan(
            intent=intent,
            action=action,
            executable=executable,
            arguments=arguments,
            entities=dict(entities),
            state_changing=bool(
                config.get(
                    "state_changing",
                    False,
                )
            ),
            privilege_required=config.get(
                "privilege_required",
                False,
            ),
            critical_operation=bool(
                config.get(
                    "critical_operation",
                    False,
                )
            ),
        )

        return PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason=(
                "Structured operation plan created. "
                "Execution is not authorized."
            ),
            plan=plan,
        )

    def _resolve_executable(
        self,
        intent: str,
        action: str,
        entities: Dict[str, str],
    ) -> str:

        if action == "list":
            if intent == "process_inspection":
                if entities.get(
                    "PATTERN"
                ):
                    return "pgrep"

                return "ps"

            if intent == "file_listing":
                return "ls"

            raise ValueError(
                "Unsupported list operation."
            )

        executable = (
            self.ACTION_EXECUTABLES.get(
                action
            )
        )

        if not executable:
            raise ValueError(
                f"No executable mapping for "
                f"action: {action}"
            )

        return executable

    def _get_intent_config(
        self,
        intent: str,
    ) -> dict:

        if not isinstance(
            intent,
            str,
        ):
            raise TypeError(
                "intent must be a string."
            )

        cleaned = intent.strip()

        if not cleaned:
            raise ValueError(
                "intent cannot be empty."
            )

        if cleaned not in self.intents:
            raise ValueError(
                f"Unknown intent: {cleaned}"
            )

        config = self.intents[
            cleaned
        ]

        if not isinstance(
            config,
            dict,
        ):
            raise ValueError(
                f"Configuration for intent "
                f"'{cleaned}' must be a mapping."
            )

        return config

    @staticmethod
    def _require(
        entities: Dict[str, str],
        name: str,
    ) -> str:

        value = entities.get(
            name
        )

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                f"Required entity missing: {name}"
            )

        value = value.strip()

        if not value:
            raise ValueError(
                f"Required entity missing: {name}"
            )

        return value

    def _build_list_arguments(
        self,
        intent: str,
        entities: Dict[str, str],
    ) -> List[str]:

        if intent == "process_inspection":
            pattern = entities.get(
                "PATTERN"
            )

            if pattern:
                return [
                    "-a",
                    pattern,
                ]

            return [
                "-ef",
            ]

        if intent == "file_listing":
            path = entities.get(
                "PATH"
            )

            if path:
                return [
                    "--",
                    path,
                ]

            return []

        raise ValueError(
            "Unsupported list operation."
        )

    def _build_filesystem_usage(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        path = entities.get(
            "PATH"
        )

        if path:
            return [
                "-h",
                "--",
                path,
            ]

        return ["-h"]

    def _build_directory_size(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        path = self._require(
            entities,
            "PATH",
        )

        return [
            "-sh",
            "--",
            path,
        ]

    def _build_process_inspect(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        pid = self._require(
            entities,
            "PID",
        )

        return [
            "-p",
            pid,
        ]

    def _build_service_status(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        service = self._require(
            entities,
            "SERVICE",
        )

        return [
            "status",
            service,
        ]

    def _build_path_only(
        self,
        entities: Dict[str, str],
    ) -> List[str]:
        """
        Build a single path operand with explicit
        option termination.

        Used only for supported GNU/Linux utilities
        whose path operand follows '--'.
        """

        path = self._require(
            entities,
            "PATH",
        )

        return [
            "--",
            path,
        ]

    def _build_file_search(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        pattern = self._require(
            entities,
            "PATTERN",
        )

        path = entities.get(
            "PATH",
            ".",
        )

        if not isinstance(
            path,
            str,
        ):
            raise ValueError(
                "PATH must be a string."
            )

        path = path.strip()

        if not path:
            path = "."

        return [
            path,
            "-name",
            pattern,
        ]

    def _build_text_search(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        pattern = self._require(
            entities,
            "PATTERN",
        )

        path = self._require(
            entities,
            "PATH",
        )

        return [
            "--",
            pattern,
            path,
        ]

    def _build_source_destination(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        source = self._require(
            entities,
            "SOURCE_PATH",
        )

        destination = self._require(
            entities,
            "DESTINATION_PATH",
        )

        return [
            "--",
            source,
            destination,
        ]

    def _build_chmod(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        permission = self._require(
            entities,
            "PERMISSION",
        )

        path = self._require(
            entities,
            "PATH",
        )

        return [
            permission,
            "--",
            path,
        ]

    def _build_chown(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        username = self._require(
            entities,
            "USERNAME",
        )

        path = self._require(
            entities,
            "PATH",
        )

        return [
            username,
            "--",
            path,
        ]

    def _build_terminate(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        pid = self._require(
            entities,
            "PID",
        )

        return [
            "-TERM",
            "--",
            pid,
        ]

    def _build_force_terminate(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        pid = self._require(
            entities,
            "PID",
        )

        return [
            "-KILL",
            "--",
            pid,
        ]

    def _build_service_target(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        service = self._require(
            entities,
            "SERVICE",
        )

        return [
            service,
        ]

    def _build_package_install(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        package = self._require(
            entities,
            "PACKAGE",
        )

        return [
            "install",
            package,
        ]

    def _build_package_remove(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        package = self._require(
            entities,
            "PACKAGE",
        )

        return [
            "remove",
            package,
        ]

    def _build_format(
        self,
        entities: Dict[str, str],
    ) -> List[str]:

        device = self._require(
            entities,
            "DEVICE",
        )

        return [
            device,
        ]