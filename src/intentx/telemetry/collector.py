"""Read-only Linux security telemetry collector."""

from __future__ import annotations

import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from intentx.telemetry.kernel_sensor import KernelSecuritySensor
from intentx.telemetry.models import (
    CgroupMemoryObservation,
    KernelSecurityObservation,
    NetworkObservation,
    ProcessObservation,
    SecuritySnapshot,
    SensorCollectionStatus,
    SensorStatus,
)


class TelemetryCollectionError(RuntimeError):
    """Raised when essential telemetry cannot be collected safely."""


class LinuxTelemetryCollector:
    """
    Collects read-only Linux telemetry.

    This component has no mitigation or execution authority. Commands are
    fixed by the implementation and are never constructed from user input.
    """

    def __init__(self, kernel_sensor: KernelSecuritySensor | None = None) -> None:
        self._kernel_sensor = kernel_sensor or KernelSecuritySensor()

    def collect(self) -> SecuritySnapshot:
        load_1m, load_5m, load_15m = self._read_load()
        memory_total, memory_available = self._read_memory()
        processes = self._read_processes()
        connections, network_sensor = self._read_network_connections()
        kernel_sec = self._kernel_sensor.collect()

        return SecuritySnapshot(
            captured_at=datetime.now(timezone.utc),
            hostname=socket.gethostname(),
            load_1m=load_1m,
            load_5m=load_5m,
            load_15m=load_15m,
            memory_total_kb=memory_total,
            memory_available_kb=memory_available,
            process_count=len(processes),
            processes=tuple(processes),
            network_connections=tuple(connections),
            network_sensor=network_sensor,
            cgroup_memory=self._read_cgroup_memory(),
            kernel_security=kernel_sec,
        )

    @staticmethod
    def _read_load() -> tuple[float, float, float]:
        try:
            fields = Path("/proc/loadavg").read_text(
                encoding="utf-8"
            ).split()

            return (
                float(fields[0]),
                float(fields[1]),
                float(fields[2]),
            )
        except (OSError, ValueError, IndexError) as exc:
            raise TelemetryCollectionError(
                "Unable to read Linux load telemetry."
            ) from exc

    @staticmethod
    def _read_memory() -> tuple[int, int]:
        values: dict[str, int] = {}

        try:
            for line in Path("/proc/meminfo").read_text(
                encoding="utf-8"
            ).splitlines():
                key, _, value = line.partition(":")
                if key in {"MemTotal", "MemAvailable"}:
                    values[key] = int(value.strip().split()[0])
        except (OSError, ValueError, IndexError) as exc:
            raise TelemetryCollectionError(
                "Unable to read Linux memory telemetry."
            ) from exc

        if "MemTotal" not in values or "MemAvailable" not in values:
            raise TelemetryCollectionError(
                "Required Linux memory fields were unavailable."
            )

        return values["MemTotal"], values["MemAvailable"]

    @staticmethod
    def _read_cgroup_memory() -> CgroupMemoryObservation:
        """Read the current cgroup v2, never substitute system memory on failure.

        Supports the standard /sys/fs/cgroup unified mount, including Docker's
        private cgroup namespace. Other mount layouts and v1 are unavailable.
        """
        try:
            entries = Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines()
            paths = [entry[3:] for entry in entries if entry.startswith("0::")]
            if len(paths) != 1:
                raise ValueError("unified cgroup v2 membership unavailable")
            relative = paths[0]
            if not relative.startswith("/") or ".." in Path(relative).parts:
                raise ValueError("unsupported cgroup path")
            root = Path("/sys/fs/cgroup").resolve()
            directory = (root / relative.lstrip("/")).resolve()
            if directory != root and root not in directory.parents:
                raise ValueError("cgroup path escapes unified mount")
            current = int((directory / "memory.current").read_text(encoding="utf-8").strip())
            raw_limit = (directory / "memory.max").read_text(encoding="utf-8").strip()
            limit = None if raw_limit == "max" else int(raw_limit)
            if current < 0 or (limit is not None and limit <= 0):
                raise ValueError("invalid cgroup memory value")
            breakdown = {}
            try:
                for line in (directory / "memory.stat").read_text(encoding="utf-8").splitlines():
                    parts = line.split()
                    if parts and parts[0] in {"anon", "file", "kernel"}:
                        if len(parts) != 2 or parts[0] in breakdown:
                            raise ValueError("invalid or duplicate memory.stat field")
                        value = int(parts[1])
                        if value < 0:
                            raise ValueError("negative memory.stat field")
                        breakdown[parts[0]] = value
                if set(breakdown) != {"anon", "file", "kernel"}:
                    raise ValueError("required memory.stat fields unavailable")
                breakdown_status = SensorStatus(SensorCollectionStatus.COLLECTED)
            except (OSError, ValueError) as exc:
                breakdown = {}
                breakdown_status = SensorStatus(SensorCollectionStatus.UNAVAILABLE,
                    detail=f"cgroup memory breakdown unavailable: {exc}")
            return CgroupMemoryObservation(
                anon_bytes=breakdown.get("anon"), file_bytes=breakdown.get("file"),
                kernel_bytes=breakdown.get("kernel"), breakdown_status=breakdown_status,
                current_bytes=current, limit_bytes=limit, source_path=str(directory),
                status=SensorStatus(status=SensorCollectionStatus.COLLECTED),
            )
        except (OSError, ValueError) as exc:
            return CgroupMemoryObservation(status=SensorStatus(
                status=SensorCollectionStatus.UNAVAILABLE,
                detail=f"cgroup v2 memory unavailable: {exc}",
            ))

    def _read_processes(self) -> list[ProcessObservation]:
        output = self._run_read_only(
            (
                "ps",
                "-eo",
                "pid=,ppid=,user=,pcpu=,pmem=,comm=",
            )
        )

        observations: list[ProcessObservation] = []

        for line in output.splitlines():
            parts = line.strip().split(None, 5)

            if len(parts) != 6:
                continue

            try:
                pid = int(parts[0])
                ppid = int(parts[1])
                cpu = float(parts[3])
                memory = float(parts[4])
            except ValueError:
                continue

            observations.append(
                ProcessObservation(
                    pid=pid,
                    ppid=ppid,
                    user=parts[2],
                    cpu_percent=cpu,
                    memory_percent=memory,
                    command=parts[5],
                )
            )

        return observations

    def _read_network_connections(
        self,
    ) -> tuple[list[NetworkObservation], SensorStatus]:
        output = self._run_read_only(
            ("ss", "-tunap"),
            required=False,
        )

        if output is None:
            return (
                [],
                SensorStatus(
                    status=SensorCollectionStatus.UNAVAILABLE,
                    detail="ss telemetry command unavailable or failed",
                ),
            )

        observations: list[NetworkObservation] = []

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or stripped.startswith("Netid"):
                continue

            parts = stripped.split()

            if len(parts) < 6:
                continue

            protocol = parts[0]
            state = parts[1]
            local_address = parts[4]
            remote_address = parts[5]
            process = " ".join(parts[6:]) if len(parts) > 6 else ""

            observations.append(
                NetworkObservation(
                    protocol=protocol,
                    local_address=local_address,
                    remote_address=remote_address,
                    state=state,
                    process=process,
                )
            )

        return (
            observations,
            SensorStatus(
                status=SensorCollectionStatus.COLLECTED,
            ),
        )

    @staticmethod
    def _run_read_only(
        argv: tuple[str, ...],
        *,
        required: bool = True,
    ) -> str | None:
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            if required:
                raise TelemetryCollectionError(
                    f"Unable to collect telemetry using {argv[0]}."
                ) from exc

            return None

        if completed.returncode != 0:
            if required:
                raise TelemetryCollectionError(
                    f"Telemetry command {argv[0]} failed."
                )

            return None

        return completed.stdout
