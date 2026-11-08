import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import yaml


DEFAULT_CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)


@dataclass(frozen=True)
class ActionResolution:
    """
    Result of deterministic action resolution.

    resolved=True means that exactly one permitted
    action was identified for the classified intent.

    It does NOT authorize execution.
    """

    intent: str
    action: str
    resolved: bool
    reason: str


class ActionResolver:
    """
    Deterministically resolves an action inside
    an already-classified intent.

    All matching permitted actions are collected
    before a decision is made.

    Multiple matches fail closed unless an explicit
    semantic subsumption rule proves that one action
    is a more specific form of another.

    Some intents require additional deterministic
    semantic resolution where ordinary keyword
    matching would be ambiguous. These rules remain
    deterministic and do not authorize execution.

    The resolver never authorizes or executes
    an operation.
    """

    ACTION_PATTERNS: Dict[
        str,
        List[tuple],
    ] = {
        "system_information": [
            (
                "show_architecture",
                (
                    r"\b(?:architecture|arch|"
                    r"machine type)\b"
                ),
            ),
            (
                "show_hostname",
                r"\b(?:hostname|host name)\b",
            ),
            (
                "show_kernel",
                r"\bkernel\b",
            ),
            (
                "show_os",
                (
                    r"\b(?:operating system|os|"
                    r"system info)\b"
                ),
            ),
        ],

        "storage_inspection": [
            (
                "directory_size",
                (
                    r"\b(?:directory|folder)"
                    r".*\bsize\b"
                    r"|\bsize.*(?:directory|folder)\b"
                ),
            ),
            (
                "filesystem_usage",
                (
                    r"\b(?:filesystem|disk|storage)"
                    r".*\b(?:usage|space)\b"
                ),
            ),
        ],

        "memory_inspection": [
            (
                "memory_usage",
                r"\b(?:memory|ram)\b",
            ),
        ],

        "process_inspection": [
            (
                "inspect",
                (
                    r"\b(?:inspect|details?|"
                    r"information)\b"
                    r".*\b(?:pid|process)\b"
                ),
            ),
            (
                "list",
                (
                    r"\b(?:list|show|running)\b"
                    r".*\bprocess(?:es)?\b"
                ),
            ),
        ],

        "service_inspection": [
            (
                "status",
                r"\b(?:status|running|check)\b",
            ),
        ],

        "network_inspection": [
            (
                "listening_ports",
                (
                    r"\b(?:listening|open)\s+ports?\b"
                    r"|\bports?\s+(?:listening|open)\b"
                ),
            ),
            (
                "interfaces",
                (
                    r"\b(?:interfaces?|ip address|"
                    r"network interface)\b"
                ),
            ),
            (
                "connections",
                r"\b(?:connections?|sockets?)\b",
            ),
        ],

        "file_listing": [
            (
                "list",
                r"\b(?:list|show|contents?)\b",
            ),
        ],

        "file_read": [
            (
                "head",
                (
                    r"\b(?:head|first lines?|"
                    r"beginning)\b"
                ),
            ),
            (
                "tail",
                (
                    r"\b(?:tail|last lines?|"
                    r"end of)\b"
                ),
            ),
            (
                "read",
                (
                    r"\b(?:read|show|display|"
                    r"contents?)\b"
                ),
            ),
        ],

        "file_search": [
            (
                "find",
                r"\b(?:find|locate|search)\b",
            ),
        ],

        "text_search": [
            (
                "search",
                r"\b(?:search|grep|find)\b",
            ),
        ],

        "file_create": [
            (
                "create_directory",
                r"\b(?:directory|folder)\b",
            ),
            (
                "create_file",
                r"\bfile\b",
            ),
        ],

        "file_copy": [
            (
                "copy",
                r"\b(?:copy|duplicate)\b",
            ),
        ],

        "file_move": [
            (
                "rename",
                r"\brename\b",
            ),
            (
                "move",
                r"\bmove\b",
            ),
        ],

        "file_delete": [
            (
                "delete",
                r"\b(?:delete|remove)\b",
            ),
        ],

        "permission_change": [
            (
                "chmod",
                (
                    r"\bchmod\b"
                    r"|\bpermissions?\b"
                    r"|\bmode\b"
                ),
            ),
            (
                "chown",
                (
                    r"\bchown\b"
                    r"|\bowner(?:ship)?\b"
                ),
            ),
        ],

        "process_termination": [
            (
                "force_terminate",
                (
                    r"\b(?:force|kill\s+-9|"
                    r"sigkill)\b"
                ),
            ),
            (
                "terminate",
                r"\b(?:terminate|kill|end|stop)\b",
            ),
        ],

        "service_management": [
            (
                "restart",
                r"\brestart\b",
            ),
            (
                "reload",
                r"\breload\b",
            ),
            (
                "start",
                r"\bstart\b",
            ),
            (
                "stop",
                r"\bstop\b|\bshut\s+down\b",
            ),
        ],

        "package_management": [
            (
                "install",
                r"\binstall\b",
            ),
            (
                "remove",
                r"\b(?:remove|uninstall)\b",
            ),
            (
                "update",
                r"\b(?:update|upgrade)\b",
            ),
        ],

        "system_power": [
            (
                "reboot",
                r"\breboot\b",
            ),
            (
                "shutdown",
                (
                    r"\b(?:shutdown|shut\s+down|"
                    r"power\s+off)\b"
                ),
            ),
        ],

        "disk_management": [
            (
                "format",
                r"\b(?:format|mkfs)\b",
            ),
        ],
    }

    # =====================================================
    # Explicit semantic subsumption
    # =====================================================
    #
    # These rules are intentionally explicit.
    #
    # They are NOT generic priority rules.
    #
    # A specific action may remove a generic action
    # only when the relationship is semantically
    # defined here.
    #
    # Example:
    #
    #   force kill process 1234
    #
    # may match:
    #
    #   force_terminate
    #   terminate
    #
    # force_terminate is explicitly more specific.
    #
    # Similarly:
    #
    #   show head /tmp/file.txt
    #
    # may match:
    #
    #   head
    #   read
    #
    # head is a specific form of file reading.
    #
    # Genuine conflicts such as:
    #
    #   start and stop nginx
    #
    # have no subsumption relationship and therefore
    # continue to fail closed.
    # =====================================================

    ACTION_SUBSUMPTION = {
        "process_termination": {
            "force_terminate": {
                "terminate",
            },
        },

        "file_read": {
            "head": {
                "read",
            },
            "tail": {
                "read",
            },
        },
    }

    def __init__(
        self,
        catalog_path=DEFAULT_CATALOG_PATH,
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
                "Intent catalog must be "
                "a mapping."
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

    def resolve(
        self,
        text: str,
        intent: str,
    ) -> ActionResolution:
        """
        Resolve a permitted action for the
        supplied intent.

        Resolution is deterministic and
        fail-closed.

        All matching permitted actions are
        collected first.

        Multiple matches are accepted only if
        explicit semantic subsumption reduces
        them to exactly one action.

        If no pattern matches, fallback is allowed
        only when the catalog defines exactly one
        permitted action.
        """

        cleaned_text = self._validate_text(
            text
        )

        config = self._get_intent_config(
            intent
        )

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

        if not allowed_actions:
            return ActionResolution(
                intent=intent,
                action="",
                resolved=False,
                reason=(
                    "Intent has no permitted "
                    "actions."
                ),
            )

        # -------------------------------------------------
        # Process inspection semantic handling
        # -------------------------------------------------
        #
        # process_inspection needs deterministic
        # semantic handling before generic keyword
        # matching.
        #
        # Examples:
        #
        # show process 4321
        #     -> inspect
        #
        # find nginx processes
        #     -> list
        #
        # list processes
        #     -> list
        #
        # This prevents "show process 4321" from
        # being incorrectly interpreted as a generic
        # process listing.

        if intent == "process_inspection":
            process_resolution = (
                self._resolve_process_inspection(
                    cleaned_text,
                    allowed_actions,
                )
            )

            if process_resolution is not None:
                return process_resolution

        patterns = self.ACTION_PATTERNS.get(
            intent,
            [],
        )

        matching_actions = []

        for action, pattern in patterns:

            # Never resolve an action that is not
            # permitted by the catalog.
            if action not in allowed_actions:
                continue

            if re.search(
                pattern,
                cleaned_text,
                re.IGNORECASE,
            ):
                matching_actions.append(
                    action
                )

        # Remove duplicates while preserving
        # deterministic pattern order.
        matching_actions = list(
            dict.fromkeys(
                matching_actions
            )
        )

        # -------------------------------------------------
        # No explicit action match
        # -------------------------------------------------

        if not matching_actions:

            # Safe fallback:
            #
            # If exactly one action exists in the
            # catalog, there is no action-level
            # ambiguity.

            if len(allowed_actions) == 1:
                return ActionResolution(
                    intent=intent,
                    action=allowed_actions[0],
                    resolved=True,
                    reason=(
                        "Intent has exactly one "
                        "permitted action."
                    ),
                )

            return ActionResolution(
                intent=intent,
                action="",
                resolved=False,
                reason=(
                    "Action could not be resolved "
                    "unambiguously."
                ),
            )

        # -------------------------------------------------
        # Exactly one explicit action
        # -------------------------------------------------

        if len(matching_actions) == 1:
            return ActionResolution(
                intent=intent,
                action=matching_actions[0],
                resolved=True,
                reason=(
                    "Exactly one permitted action "
                    "matched the request."
                ),
            )

        # -------------------------------------------------
        # Multiple action matches
        # -------------------------------------------------
        #
        # Apply ONLY explicitly configured semantic
        # subsumption relationships.
        #
        # We deliberately do not choose based on
        # pattern ordering.

        reduced_actions = (
            self._apply_subsumption(
                intent,
                matching_actions,
            )
        )

        if len(reduced_actions) == 1:
            return ActionResolution(
                intent=intent,
                action=reduced_actions[0],
                resolved=True,
                reason=(
                    "Multiple patterns matched, "
                    "but explicit semantic "
                    "subsumption resolved the "
                    "specific action."
                ),
            )

        # Multiple incompatible actions remain.
        #
        # Fail closed rather than choosing based
        # on pattern ordering.

        return ActionResolution(
            intent=intent,
            action="",
            resolved=False,
            reason=(
                "Multiple permitted actions "
                "matched the request."
            ),
        )

    def _resolve_process_inspection(
        self,
        text: str,
        allowed_actions: List[str],
    ):
        """
        Resolve process_inspection semantics.

        A numeric PID associated with a process
        request is strong deterministic evidence
        for inspection of one process.

        Pattern-based process discovery remains
        the list action because the resulting
        operation uses pgrep.

        This method returns None when it cannot
        establish a process-specific action safely,
        allowing the normal resolver to continue.
        """

        has_pid = bool(
            re.search(
                r"\b(?:pid\s*)?\d+\b",
                text,
                re.IGNORECASE,
            )
        )

        has_process_word = bool(
            re.search(
                r"\bprocess(?:es)?\b",
                text,
                re.IGNORECASE,
            )
        )

        has_search_word = bool(
            re.search(
                r"\b(?:find|search|locate)\b",
                text,
                re.IGNORECASE,
            )
        )

        has_list_word = bool(
            re.search(
                r"\b(?:list|running)\b",
                text,
                re.IGNORECASE,
            )
        )

        has_inspect_word = bool(
            re.search(
                (
                    r"\b(?:inspect|details?|"
                    r"information)\b"
                ),
                text,
                re.IGNORECASE,
            )
        )

        # A PID plus process context means inspection
        # of a specific process.
        #
        # Examples:
        #
        #   show process 4321
        #   inspect process 4321
        #   process 4321 details
        #   show pid 4321

        if (
            has_pid
            and (
                has_process_word
                or re.search(
                    r"\bpid\b",
                    text,
                    re.IGNORECASE,
                )
            )
        ):
            if "inspect" in allowed_actions:
                return ActionResolution(
                    intent="process_inspection",
                    action="inspect",
                    resolved=True,
                    reason=(
                        "A specific process PID "
                        "was identified."
                    ),
                )

            return ActionResolution(
                intent="process_inspection",
                action="",
                resolved=False,
                reason=(
                    "PID-based inspection is not "
                    "permitted for this intent."
                ),
            )

        # Search/discovery by process name or pattern
        # is a list-style process operation.
        #
        # Example:
        #
        #   find nginx processes

        if (
            has_search_word
            and has_process_word
        ):
            if "list" in allowed_actions:
                return ActionResolution(
                    intent="process_inspection",
                    action="list",
                    resolved=True,
                    reason=(
                        "Process search resolved "
                        "to the list action."
                    ),
                )

            return ActionResolution(
                intent="process_inspection",
                action="",
                resolved=False,
                reason=(
                    "Process listing is not "
                    "permitted for this intent."
                ),
            )

        # Explicit generic process listing.
        #
        # Examples:
        #
        #   list processes
        #   show running processes

        if (
            has_list_word
            and has_process_word
        ):
            if "list" in allowed_actions:
                return ActionResolution(
                    intent="process_inspection",
                    action="list",
                    resolved=True,
                    reason=(
                        "Generic process listing "
                        "was requested."
                    ),
                )

            return ActionResolution(
                intent="process_inspection",
                action="",
                resolved=False,
                reason=(
                    "Process listing is not "
                    "permitted for this intent."
                ),
            )

        # An explicit inspection request without a
        # PID must not silently become a process list.

        if (
            has_inspect_word
            and has_process_word
            and not has_pid
        ):
            return ActionResolution(
                intent="process_inspection",
                action="",
                resolved=False,
                reason=(
                    "Process inspection requires "
                    "a specific PID."
                ),
            )

        return None

    def _apply_subsumption(
        self,
        intent: str,
        matching_actions: List[str],
    ) -> List[str]:
        """
        Remove generic actions only when an explicit
        semantic rule states that a more specific
        matched action subsumes them.

        Genuine incompatible actions remain and
        therefore fail closed.
        """

        remaining = list(
            matching_actions
        )

        rules = self.ACTION_SUBSUMPTION.get(
            intent,
            {},
        )

        if not isinstance(
            rules,
            dict,
        ):
            return remaining

        matched_set = set(
            matching_actions
        )

        for (
            specific_action,
            generic_actions,
        ) in rules.items():

            if (
                specific_action
                not in matched_set
            ):
                continue

            for generic_action in (
                generic_actions
            ):
                if (
                    generic_action in remaining
                    and generic_action
                    != specific_action
                ):
                    remaining.remove(
                        generic_action
                    )

        return remaining

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
    def _validate_text(
        text: str,
    ) -> str:

        if not isinstance(
            text,
            str,
        ):
            raise TypeError(
                "text must be a string."
            )

        cleaned = " ".join(
            text.strip().split()
        )

        if not cleaned:
            raise ValueError(
                "text cannot be empty."
            )

        return cleaned