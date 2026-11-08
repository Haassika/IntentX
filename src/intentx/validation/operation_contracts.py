from collections.abc import Mapping
from typing import List, Optional, Tuple

from intentx.planning.models import OperationPlan
from intentx.validation.models import ValidationIssue


class OperationContractValidator:
    """
    Validates deterministic relationships between
    an OperationPlan's action, executable, arguments,
    and entities.

    This component does not execute or authorize
    operations.
    """

    def validate(
        self,
        plan: OperationPlan,
    ) -> List[ValidationIssue]:

        if not isinstance(
            plan,
            OperationPlan,
        ):
            raise TypeError(
                "plan must be an OperationPlan."
            )

        expected = self._expected_contract(
            plan
        )

        if expected is None:
            return [
                self._issue(
                    "UNSUPPORTED_OPERATION_CONTRACT",
                    "No deterministic operation "
                    "contract exists for this "
                    "intent/action combination.",
                )
            ]

        (
            expected_executable,
            expected_arguments,
        ) = expected

        issues = []

        if (
            plan.executable
            != expected_executable
        ):
            issues.append(
                self._issue(
                    "EXECUTABLE_CONTRACT_MISMATCH",
                    "Executable does not match "
                    "the deterministic operation "
                    "contract.",
                    "executable",
                )
            )

        # OperationPlan stores arguments as an
        # immutable tuple. The expected contract is
        # also represented as a tuple so equality
        # remains exact and type-consistent.
        if (
            plan.arguments
            != expected_arguments
        ):
            issues.append(
                self._issue(
                    "ARGUMENT_CONTRACT_MISMATCH",
                    "Arguments do not match the "
                    "deterministic operation "
                    "contract.",
                    "arguments",
                )
            )

        return issues

    def _expected_contract(
        self,
        plan: OperationPlan,
    ) -> Optional[
        Tuple[str, Tuple[str, ...]]
    ]:

        # OperationPlan exposes entities through a
        # read-only Mapping. Contract validation only
        # needs read access and must never mutate it.
        if not isinstance(
            plan.entities,
            Mapping,
        ):
            return None

        e = plan.entities

        key = (
            plan.intent,
            plan.action,
        )

        # =================================================
        # System information
        # =================================================

        if key == (
            "system_information",
            "show_os",
        ):
            return "uname", ("-s",)

        if key == (
            "system_information",
            "show_kernel",
        ):
            return "uname", ("-r",)

        if key == (
            "system_information",
            "show_architecture",
        ):
            return "uname", ("-m",)

        if key == (
            "system_information",
            "show_hostname",
        ):
            return "hostname", ()

        # =================================================
        # Storage inspection
        # =================================================

        if key == (
            "storage_inspection",
            "filesystem_usage",
        ):
            path = e.get(
                "PATH"
            )

            if path:
                return "df", (
                    "-h",
                    "--",
                    path,
                )

            return "df", ("-h",)

        if key == (
            "storage_inspection",
            "directory_size",
        ):
            path = self._require(
                e,
                "PATH",
            )

            if path is None:
                return None

            return "du", (
                "-sh",
                "--",
                path,
            )

        # =================================================
        # Memory inspection
        # =================================================

        if key == (
            "memory_inspection",
            "memory_usage",
        ):
            return "free", ("-h",)

        # =================================================
        # Process inspection
        # =================================================

        if key == (
            "process_inspection",
            "list",
        ):
            pattern = e.get(
                "PATTERN"
            )

            if pattern:
                return "pgrep", (
                    "-a",
                    pattern,
                )

            return "ps", ("-ef",)

        if key == (
            "process_inspection",
            "inspect",
        ):
            pid = self._require(
                e,
                "PID",
            )

            if pid is None:
                return None

            return "ps", (
                "-p",
                pid,
            )

        # =================================================
        # Service inspection
        # =================================================

        if key == (
            "service_inspection",
            "status",
        ):
            service = self._require(
                e,
                "SERVICE",
            )

            if service is None:
                return None

            return "systemctl", (
                "status",
                service,
            )

        # =================================================
        # Network inspection
        # =================================================

        if key == (
            "network_inspection",
            "interfaces",
        ):
            return "ip", (
                "addr",
            )

        if key == (
            "network_inspection",
            "connections",
        ):
            return "ss", (
                "-tun",
            )

        if key == (
            "network_inspection",
            "listening_ports",
        ):
            return "ss", (
                "-lnt",
            )

        # =================================================
        # File listing
        # =================================================

        if key == (
            "file_listing",
            "list",
        ):
            path = e.get(
                "PATH"
            )

            if path:
                return "ls", (
                    "--",
                    path,
                )

            return "ls", ()

        # =================================================
        # File read
        # =================================================

        if (
            key[0] == "file_read"
            and key[1] in {
                "read",
                "head",
                "tail",
            }
        ):
            path = self._require(
                e,
                "PATH",
            )

            if path is None:
                return None

            executable_by_action = {
                "read": "cat",
                "head": "head",
                "tail": "tail",
            }

            executable = (
                executable_by_action[
                    key[1]
                ]
            )

            return executable, (
                "--",
                path,
            )

        # =================================================
        # File search
        # =================================================

        if key == (
            "file_search",
            "find",
        ):
            pattern = self._require(
                e,
                "PATTERN",
            )

            if pattern is None:
                return None

            path = e.get(
                "PATH",
                ".",
            )

            if not isinstance(
                path,
                str,
            ):
                return None

            path = (
                path.strip()
                or "."
            )

            return "find", (
                path,
                "-name",
                pattern,
            )

        # =================================================
        # Text search
        # =================================================

        if key == (
            "text_search",
            "search",
        ):
            pattern = self._require(
                e,
                "PATTERN",
            )

            path = self._require(
                e,
                "PATH",
            )

            if (
                pattern is None
                or path is None
            ):
                return None

            return "grep", (
                "--",
                pattern,
                path,
            )

        # =================================================
        # File creation
        # =================================================

        if (
            key[0] == "file_create"
            and key[1] in {
                "create_file",
                "create_directory",
            }
        ):
            path = self._require(
                e,
                "PATH",
            )

            if path is None:
                return None

            if (
                key[1]
                == "create_file"
            ):
                return "touch", (
                    "--",
                    path,
                )

            return "mkdir", (
                "--",
                path,
            )

        # =================================================
        # File copy
        # =================================================

        if key == (
            "file_copy",
            "copy",
        ):
            source = self._require(
                e,
                "SOURCE_PATH",
            )

            destination = self._require(
                e,
                "DESTINATION_PATH",
            )

            if (
                source is None
                or destination is None
            ):
                return None

            return "cp", (
                "--",
                source,
                destination,
            )

        # =================================================
        # File move / rename
        # =================================================

        if (
            key[0] == "file_move"
            and key[1] in {
                "move",
                "rename",
            }
        ):
            source = self._require(
                e,
                "SOURCE_PATH",
            )

            destination = self._require(
                e,
                "DESTINATION_PATH",
            )

            if (
                source is None
                or destination is None
            ):
                return None

            return "mv", (
                "--",
                source,
                destination,
            )

        # =================================================
        # File delete
        # =================================================

        if key == (
            "file_delete",
            "delete",
        ):
            path = self._require(
                e,
                "PATH",
            )

            if path is None:
                return None

            return "rm", (
                "--",
                path,
            )

        # =================================================
        # Permission changes
        # =================================================

        if key == (
            "permission_change",
            "chmod",
        ):
            permission = self._require(
                e,
                "PERMISSION",
            )

            path = self._require(
                e,
                "PATH",
            )

            if (
                permission is None
                or path is None
            ):
                return None

            return "chmod", (
                permission,
                "--",
                path,
            )

        if key == (
            "permission_change",
            "chown",
        ):
            username = self._require(
                e,
                "USERNAME",
            )

            path = self._require(
                e,
                "PATH",
            )

            if (
                username is None
                or path is None
            ):
                return None

            return "chown", (
                username,
                "--",
                path,
            )

        # =================================================
        # Process termination
        # =================================================

        if key == (
            "process_termination",
            "terminate",
        ):
            pid = self._require(
                e,
                "PID",
            )

            if pid is None:
                return None

            return "kill", (
                "-TERM",
                "--",
                pid,
            )

        if key == (
            "process_termination",
            "force_terminate",
        ):
            pid = self._require(
                e,
                "PID",
            )

            if pid is None:
                return None

            return "kill", (
                "-KILL",
                "--",
                pid,
            )

        # =================================================
        # Service management
        # =================================================

        if (
            key[0] == "service_management"
            and key[1] in {
                "start",
                "stop",
                "restart",
                "reload",
            }
        ):
            service = self._require(
                e,
                "SERVICE",
            )

            if service is None:
                return None

            return "systemctl", (
                key[1],
                service,
            )

        # =================================================
        # Package management
        # =================================================

        if key == (
            "package_management",
            "install",
        ):
            package = self._require(
                e,
                "PACKAGE",
            )

            if package is None:
                return None

            return "apt-get", (
                "install",
                package,
            )

        if key == (
            "package_management",
            "remove",
        ):
            package = self._require(
                e,
                "PACKAGE",
            )

            if package is None:
                return None

            return "apt-get", (
                "remove",
                package,
            )

        if key == (
            "package_management",
            "update",
        ):
            return "apt-get", (
                "update",
            )

        # =================================================
        # System power
        # =================================================

        if key == (
            "system_power",
            "reboot",
        ):
            return "reboot", ()

        if key == (
            "system_power",
            "shutdown",
        ):
            return "shutdown", (
                "-h",
                "now",
            )

        # =================================================
        # Disk management
        # =================================================

        if key == (
            "disk_management",
            "format",
        ):
            device = self._require(
                e,
                "DEVICE",
            )

            if device is None:
                return None

            return "mkfs", (
                device,
            )

        return None

    @staticmethod
    def _require(
        entities: Mapping[str, str],
        name: str,
    ) -> Optional[str]:

        value = entities.get(
            name
        )

        if not isinstance(
            value,
            str,
        ):
            return None

        value = value.strip()

        if not value:
            return None

        return value

    @staticmethod
    def _issue(
        code: str,
        message: str,
        field: Optional[str] = None,
    ) -> ValidationIssue:

        return ValidationIssue(
            code=code,
            message=message,
            field=field,
        )