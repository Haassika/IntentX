"""Kernel-level security and intrusion detection sensor for Linux systems."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from intentx.telemetry.models import (
    KernelSecurityObservation,
    SensorCollectionStatus,
    SensorStatus,
)


# Standard Linux kernel taint flags bitmask mapping
TAINT_BIT_FLAGS = {
    1: "PROPRIETARY_MODULE",
    2: "FORCED_MODULE",
    4: "CPU_OUT_OF_SPEC",
    8: "MODULE_FORCE_UNLOAD",
    16: "MACHINE_CHECK_EXCEPTION",
    32: "BAD_PAGE",
    64: "USER_REQUESTED",
    128: "KERNEL_DIED",
    256: "ACPI_TABLE_OVERRIDDEN",
    512: "KERNEL_WARN",
    1024: "MODULE_STAGING",
    2048: "KERNEL_CRITICAL",
    4096: "OUT_OF_TREE_MODULE",
    8192: "UNSIGNED_MODULE",
    16384: "SOFTLOCKUP",
    32768: "LIVEPATCH",
    65536: "AUXILIARY",
    131072: "STRUCT_RANDOMIZATION_FAILURE",
}


class KernelSecuritySensor:
    """
    Collects kernel integrity indicators, taint flags, and security alert events.
    Operates strictly in read-only mode and falls back safely when in containers
    or non-Linux environments.
    """

    def __init__(
        self,
        *,
        proc_sys_root: Path = Path("/proc/sys/kernel"),
        kmsg_path: Path = Path("/dev/kmsg"),
    ) -> None:
        self._proc_sys_root = proc_sys_root
        self._kmsg_path = kmsg_path

    def collect(self) -> KernelSecurityObservation:
        """Collect current kernel-level integrity and security flags."""
        taint_val = self._read_int(self._proc_sys_root / "tainted", default=0)
        taint_flags = self._decode_taint(taint_val)
        ptrace = self._read_int(self._proc_sys_root / "yama" / "ptrace_scope", default=None)
        modules_disabled = self._read_int(self._proc_sys_root / "modules_disabled", default=None)
        dmesg_restrict = self._read_int(self._proc_sys_root / "dmesg_restrict", default=None)

        events: list[str] = []
        if taint_val > 0:
            events.append(f"KERNEL_TAINT_ACTIVE: bitmask={taint_val} ({', '.join(taint_flags)})")

        # Scan for kernel security indicators if accessible
        kmsg_lines = self._sample_kernel_messages()
        events.extend(kmsg_lines)

        return KernelSecurityObservation(
            tainted=taint_val,
            taint_flags=tuple(taint_flags),
            ptrace_scope=ptrace,
            modules_disabled=modules_disabled,
            dmesg_restrict=dmesg_restrict,
            security_event_count=len(events),
            security_events=tuple(events),
            status=SensorStatus(status=SensorCollectionStatus.COLLECTED),
        )

    def _read_int(self, path: Path, default: int | None = None) -> int | None:
        try:
            if path.is_file():
                content = path.read_text(encoding="utf-8").strip()
                return int(content)
        except (OSError, ValueError):
            pass
        return default

    @staticmethod
    def _decode_taint(bitmask: int) -> list[str]:
        if not bitmask:
            return []
        flags: list[str] = []
        for bit, label in TAINT_BIT_FLAGS.items():
            if bitmask & bit:
                flags.append(label)
        return flags

    def _sample_kernel_messages(self) -> list[str]:
        """Read non-blocking security alerts from kernel message ring buffer if accessible."""
        alerts: list[str] = []
        try:
            # If simulated or local file provided
            if self._kmsg_path.is_file():
                content = self._kmsg_path.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines()[-20:]:
                    lowered = line.lower()
                    if any(kw in lowered for kw in ("seccomp", "denied", "oom-killer", "segfault", "oops", "taint")):
                        alerts.append(line.strip()[:200])
        except (OSError, PermissionError):
            pass
        return alerts
