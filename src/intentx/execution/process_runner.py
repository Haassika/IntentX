from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Mapping, Optional, Tuple

import yaml


DEFAULT_POLICY_PATH = Path(
    "configs/security_policy.yaml"
)


ALLOWED_PROCESS_ENVIRONMENT_VARIABLES = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
    }
)


MAX_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 1024 * 1024

PIPE_READ_SIZE = 8192
PROCESS_TERMINATION_GRACE_SECONDS = 1.0


class ProcessLaunchError(RuntimeError):
    """
    Raised when the controlled process boundary cannot
    successfully create the requested operating-system
    process.

    This exception represents failure at process creation
    rather than a non-zero exit status from a process that
    was successfully launched.
    """


@dataclass(frozen=True)
class ProcessExecutionResult:
    """
    Raw result returned by the controlled process boundary.

    This object contains only process-level information.
    Policy, authorization, risk, and audit decisions belong
    to higher layers.
    """

    return_code: Optional[int]
    stdout: bytes
    stderr: bytes
    timed_out: bool
    duration_ms: int
    metadata: Mapping[str, object]

    def __post_init__(self):
        if self.return_code is not None:
            if (
                isinstance(self.return_code, bool)
                or not isinstance(self.return_code, int)
            ):
                raise TypeError(
                    "return_code must be an integer or None."
                )

        if not isinstance(self.stdout, bytes):
            raise TypeError(
                "stdout must be bytes."
            )

        if not isinstance(self.stderr, bytes):
            raise TypeError(
                "stderr must be bytes."
            )

        if not isinstance(self.timed_out, bool):
            raise TypeError(
                "timed_out must be boolean."
            )

        if (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, int)
        ):
            raise TypeError(
                "duration_ms must be an integer."
            )

        if self.duration_ms < 0:
            raise ValueError(
                "duration_ms cannot be negative."
            )

        if not isinstance(self.metadata, Mapping):
            raise TypeError(
                "metadata must be a mapping."
            )

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                dict(self.metadata)
            ),
        )

        if (
            self.timed_out
            and self.return_code is not None
        ):
            raise ValueError(
                "A timed-out process must not "
                "report a normal return code."
            )

    def to_dict(self):
        return {
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ProcessExecutionRequest:
    """
    Exact process-level request accepted by the operating
    system execution boundary.

    Runtime limits are retained in the request so that the
    requested execution contract is explicit and auditable.

    The request does NOT control those limits.

    ProcessRunner owns the authoritative runtime policy and
    independently verifies that every request exactly matches
    that policy before execution can progress.

    Environment selection deliberately does not belong to
    the request.
    """

    executable_path: str
    arguments: Tuple[str, ...]
    timeout_seconds: int
    stdout_max_bytes: int
    stderr_max_bytes: int

    def __post_init__(self):
        self._validate_executable_path()

        immutable_arguments = (
            self._validate_arguments()
        )

        self._validate_positive_integer(
            "timeout_seconds",
            self.timeout_seconds,
        )

        self._validate_positive_integer(
            "stdout_max_bytes",
            self.stdout_max_bytes,
        )

        self._validate_positive_integer(
            "stderr_max_bytes",
            self.stderr_max_bytes,
        )

        object.__setattr__(
            self,
            "arguments",
            immutable_arguments,
        )

    def _validate_executable_path(
        self,
    ) -> None:
        if not isinstance(
            self.executable_path,
            str,
        ):
            raise TypeError(
                "executable_path must be a string."
            )

        if not self.executable_path.strip():
            raise ValueError(
                "executable_path cannot be empty."
            )

        if "\x00" in self.executable_path:
            raise ValueError(
                "executable_path cannot contain "
                "NUL bytes."
            )

        executable_path = Path(
            self.executable_path
        )

        if not executable_path.is_absolute():
            raise ValueError(
                "executable_path must be "
                "an absolute path."
            )

    def _validate_arguments(
        self,
    ) -> Tuple[str, ...]:
        if isinstance(
            self.arguments,
            (
                str,
                bytes,
                bytearray,
            ),
        ):
            raise TypeError(
                "arguments must be a sequence "
                "of strings, not a string or "
                "bytes object."
            )

        if not isinstance(
            self.arguments,
            Sequence,
        ):
            raise TypeError(
                "arguments must be a sequence "
                "of strings."
            )

        immutable_arguments = tuple(
            self.arguments
        )

        for argument in immutable_arguments:
            if not isinstance(
                argument,
                str,
            ):
                raise TypeError(
                    "All process arguments "
                    "must be strings."
                )

            if "\x00" in argument:
                raise ValueError(
                    "Process arguments cannot "
                    "contain NUL bytes."
                )

        return immutable_arguments

    @staticmethod
    def _validate_positive_integer(
        field_name: str,
        value: int,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                f"{field_name} must be an integer."
            )

        if value <= 0:
            raise ValueError(
                f"{field_name} must be "
                "greater than zero."
            )

    @property
    def argv(self) -> list[str]:
        """
        Return a fresh structured argv list.

        No shell command string is produced.
        """

        return [
            self.executable_path,
            *self.arguments,
        ]

    def to_dict(self):
        return {
            "executable_path":
                self.executable_path,
            "arguments":
                list(self.arguments),
            "argv":
                self.argv,
            "timeout_seconds":
                self.timeout_seconds,
            "stdout_max_bytes":
                self.stdout_max_bytes,
            "stderr_max_bytes":
                self.stderr_max_bytes,
        }


@dataclass(frozen=True)
class ProcessRuntimePolicy:
    """
    Immutable runtime controls owned by ProcessRunner.

    These values originate from the security policy rather
    than from an execution request.
    """

    timeout_seconds: int
    stdout_max_bytes: int
    stderr_max_bytes: int
    fixed_environment: Mapping[str, str]

    def __post_init__(self):
        self._validate_positive_integer(
            "timeout_seconds",
            self.timeout_seconds,
        )

        self._validate_positive_integer(
            "stdout_max_bytes",
            self.stdout_max_bytes,
        )

        self._validate_positive_integer(
            "stderr_max_bytes",
            self.stderr_max_bytes,
        )

        if (
            self.timeout_seconds
            > MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "Configured timeout_seconds exceeds "
                "the maximum safe timeout."
            )

        if (
            self.stdout_max_bytes
            > MAX_OUTPUT_BYTES
        ):
            raise ValueError(
                "Configured stdout_max_bytes exceeds "
                "the maximum safe output limit."
            )

        if (
            self.stderr_max_bytes
            > MAX_OUTPUT_BYTES
        ):
            raise ValueError(
                "Configured stderr_max_bytes exceeds "
                "the maximum safe output limit."
            )

        immutable_environment = (
            MappingProxyType(
                ProcessRunner._validate_environment(
                    self.fixed_environment
                )
            )
        )

        object.__setattr__(
            self,
            "fixed_environment",
            immutable_environment,
        )

    @staticmethod
    def _validate_positive_integer(
        field_name: str,
        value: int,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                f"{field_name} must be an integer."
            )

        if value <= 0:
            raise ValueError(
                f"{field_name} must be "
                "greater than zero."
            )

    def to_dict(self):
        return {
            "timeout_seconds":
                self.timeout_seconds,
            "stdout_max_bytes":
                self.stdout_max_bytes,
            "stderr_max_bytes":
                self.stderr_max_bytes,
            "fixed_environment":
                dict(self.fixed_environment),
        }


class _BoundedPipeCollector:
    """
    Continuously drain one binary process pipe while retaining
    no more than the configured number of bytes.

    Draining continues after the retention limit is reached so
    the child cannot block because an OS pipe buffer becomes
    full.

    The total number of observed bytes is tracked separately
    from the retained bytes.
    """

    def __init__(
        self,
        pipe: BinaryIO,
        max_bytes: int,
    ):
        self._pipe = pipe
        self._max_bytes = max_bytes

        self._retained = bytearray()
        self._total_bytes = 0
        self._error: Optional[BaseException] = None

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @property
    def truncated(self) -> bool:
        return (
            self._total_bytes
            > len(self._retained)
        )

    @property
    def error(self) -> Optional[BaseException]:
        return self._error

    def retained_bytes(self) -> bytes:
        return bytes(self._retained)

    def drain(self) -> None:
        try:
            while True:
                chunk = self._pipe.read(
                    PIPE_READ_SIZE
                )

                if not chunk:
                    break

                if not isinstance(
                    chunk,
                    bytes,
                ):
                    raise TypeError(
                        "Process pipes must produce bytes."
                    )

                self._total_bytes += len(
                    chunk
                )

                remaining = (
                    self._max_bytes
                    - len(self._retained)
                )

                if remaining > 0:
                    self._retained.extend(
                        chunk[:remaining]
                    )

        except BaseException as exc:
            self._error = exc

        finally:
            try:
                self._pipe.close()
            except Exception:
                pass


class ProcessRunner:
    """
    Controlled OS process boundary.

    The runner owns the authoritative runtime policy.

    Timeout, output limits, and the child-process
    environment are loaded from the security policy rather
    than trusted from an execution request.

    A ProcessExecutionRequest may carry runtime-limit values
    for audit transparency, but those values must exactly
    match the runner-owned policy.

    Processes are launched without a shell, without inherited
    stdin, and without inheriting the parent environment.

    stdout and stderr are drained concurrently and bounded in
    memory.

    On timeout, the complete child process group is terminated
    and reaped.
    """

    def __init__(
        self,
        policy_path: Optional[Path] = None,
    ):
        self.policy_path = (
            Path(policy_path)
            if policy_path is not None
            else DEFAULT_POLICY_PATH
        )

        self._runtime_policy = (
            self._load_runtime_policy()
        )

    @property
    def runtime_policy(
        self,
    ) -> ProcessRuntimePolicy:
        return self._runtime_policy

    @property
    def timeout_seconds(
        self,
    ) -> int:
        return (
            self._runtime_policy.timeout_seconds
        )

    @property
    def stdout_max_bytes(
        self,
    ) -> int:
        return (
            self._runtime_policy.stdout_max_bytes
        )

    @property
    def stderr_max_bytes(
        self,
    ) -> int:
        return (
            self._runtime_policy.stderr_max_bytes
        )

    @property
    def fixed_environment(
        self,
    ) -> Mapping[str, str]:
        return (
            self._runtime_policy.fixed_environment
        )

    def _load_runtime_policy(
        self,
    ) -> ProcessRuntimePolicy:
        if not self.policy_path.exists():
            raise FileNotFoundError(
                "Security policy not found: "
                f"{self.policy_path}"
            )

        with self.policy_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            policy = yaml.safe_load(handle)

        if not isinstance(policy, dict):
            raise ValueError(
                "Security policy must contain "
                "a YAML mapping."
            )

        execution_requirements = (
            policy.get(
                "execution_requirements"
            )
        )

        if not isinstance(
            execution_requirements,
            dict,
        ):
            raise ValueError(
                "Security policy must define "
                "execution_requirements."
            )

        self._validate_execution_requirements(
            execution_requirements
        )

        runtime_limits = (
            execution_requirements.get(
                "runtime_limits"
            )
        )

        if not isinstance(
            runtime_limits,
            dict,
        ):
            raise ValueError(
                "execution_requirements must define "
                "runtime_limits."
            )

        required_runtime_keys = {
            "timeout_seconds",
            "stdout_max_bytes",
            "stderr_max_bytes",
        }

        if (
            set(runtime_limits)
            != required_runtime_keys
        ):
            raise ValueError(
                "runtime_limits must contain exactly "
                "timeout_seconds, stdout_max_bytes, "
                "and stderr_max_bytes."
            )

        process_environment = (
            execution_requirements.get(
                "process_environment"
            )
        )

        if not isinstance(
            process_environment,
            dict,
        ):
            raise ValueError(
                "execution_requirements must define "
                "process_environment."
            )

        if (
            process_environment.get(
                "inherit_parent_environment"
            )
            is not False
        ):
            raise ValueError(
                "Parent process environment inheritance "
                "must be disabled."
            )

        fixed_environment = (
            process_environment.get(
                "fixed_environment"
            )
        )

        if not isinstance(
            fixed_environment,
            Mapping,
        ):
            raise ValueError(
                "process_environment must define "
                "fixed_environment."
            )

        return ProcessRuntimePolicy(
            timeout_seconds=runtime_limits[
                "timeout_seconds"
            ],
            stdout_max_bytes=runtime_limits[
                "stdout_max_bytes"
            ],
            stderr_max_bytes=runtime_limits[
                "stderr_max_bytes"
            ],
            fixed_environment=fixed_environment,
        )

    @staticmethod
    def _validate_execution_requirements(
        execution_requirements: Mapping[
            str,
            object,
        ],
    ) -> None:
        required_true_controls = (
            "require_intent_validation",
            "require_entity_validation",
            "require_risk_assessment",
            "require_policy_evaluation",
            "require_allowlisted_executable",
            "require_validated_arguments",
            "execution_timeout_required",
            "output_limit_required",
            "audit_record_required",
        )

        for control_name in (
            required_true_controls
        ):
            if (
                execution_requirements.get(
                    control_name
                )
                is not True
            ):
                raise ValueError(
                    f"{control_name} must be enabled "
                    "before process execution."
                )

        if (
            execution_requirements.get(
                "shell_mode_allowed"
            )
            is not False
        ):
            raise ValueError(
                "shell_mode_allowed must be false."
            )

    @staticmethod
    def _validate_environment(
        environment: Mapping[str, str],
    ) -> dict[str, str]:
        if not isinstance(
            environment,
            Mapping,
        ):
            raise TypeError(
                "fixed_environment must be a mapping."
            )

        environment_copy = dict(
            environment
        )

        if (
            set(environment_copy)
            != ALLOWED_PROCESS_ENVIRONMENT_VARIABLES
        ):
            raise ValueError(
                "fixed_environment must contain "
                "exactly PATH, LANG, and LC_ALL."
            )

        for key, value in (
            environment_copy.items()
        ):
            if not isinstance(key, str):
                raise TypeError(
                    "Environment variable names "
                    "must be strings."
                )

            if not key:
                raise ValueError(
                    "Environment variable names "
                    "cannot be empty."
                )

            if "\x00" in key:
                raise ValueError(
                    "Environment variable names "
                    "cannot contain NUL bytes."
                )

            if "=" in key:
                raise ValueError(
                    "Environment variable names "
                    "cannot contain '='."
                )

            if not isinstance(value, str):
                raise TypeError(
                    "Environment variable values "
                    "must be strings."
                )

            if "\x00" in value:
                raise ValueError(
                    "Environment variable values "
                    "cannot contain NUL bytes."
                )

            if not value:
                raise ValueError(
                    "Environment variable values "
                    "cannot be empty."
                )

        path_value = environment_copy[
            "PATH"
        ]

        path_components = path_value.split(
            ":"
        )

        if not path_components:
            raise ValueError(
                "PATH must contain at least "
                "one directory."
            )

        for component in path_components:
            if not component:
                raise ValueError(
                    "PATH cannot contain empty "
                    "components."
                )

            if not (
                Path(component).is_absolute()
                or component.startswith("/")
            ):
                raise ValueError(
                    "Every PATH component must "
                    "be absolute."
                )

        return environment_copy

    def _validate_request_policy(
        self,
        request: ProcessExecutionRequest,
    ) -> None:
        """
        Ensure the caller cannot weaken runner-owned
        runtime controls.

        All request limits must exactly match the
        authoritative runtime policy.
        """

        mismatches = []

        if (
            request.timeout_seconds
            != self.timeout_seconds
        ):
            mismatches.append(
                "timeout_seconds"
            )

        if (
            request.stdout_max_bytes
            != self.stdout_max_bytes
        ):
            mismatches.append(
                "stdout_max_bytes"
            )

        if (
            request.stderr_max_bytes
            != self.stderr_max_bytes
        ):
            mismatches.append(
                "stderr_max_bytes"
            )

        if mismatches:
            raise ValueError(
                "Process execution request does not "
                "match the runner-owned runtime "
                "policy: "
                + ", ".join(mismatches)
                + "."
            )

    @staticmethod
    def _validate_executable_for_launch(
        executable_path: str,
    ) -> str:
        """
        Perform immediate pre-launch filesystem checks.

        Trusted-directory resolution remains the
        responsibility of TrustedExecutableResolver.

        This method verifies that the supplied canonical path
        still refers to an absolute, regular, executable file
        immediately before Popen is called.
        """

        path = Path(
            executable_path
        )

        if not path.is_absolute():
            raise ProcessLaunchError(
                "Executable path is not absolute."
            )

        try:
            resolved = path.resolve(
                strict=True
            )
        except (
            FileNotFoundError,
            OSError,
        ) as exc:
            raise ProcessLaunchError(
                "Executable does not exist at "
                "process launch time."
            ) from exc

        try:
            if not resolved.is_file():
                raise ProcessLaunchError(
                    "Executable path is not a "
                    "regular file."
                )

            if not os.access(
                resolved,
                os.X_OK,
            ):
                raise ProcessLaunchError(
                    "Executable path is not "
                    "executable."
                )

        except OSError as exc:
            raise ProcessLaunchError(
                "Executable could not be validated "
                "at process launch time."
            ) from exc

        if (
            str(resolved)
            != executable_path
        ):
            raise ProcessLaunchError(
                "Executable path changed during "
                "pre-launch validation."
            )

        return str(resolved)

    @staticmethod
    def _start_collector_thread(
        collector: _BoundedPipeCollector,
        name: str,
    ) -> threading.Thread:
        thread = threading.Thread(
            target=collector.drain,
            name=name,
            daemon=True,
        )

        thread.start()

        return thread

    @staticmethod
    def _terminate_process_group(
        process: subprocess.Popen,
    ) -> None:
        """
        Terminate the complete process group created for the
        child.

        SIGTERM is attempted first. If the process group does
        not exit during the short grace period, SIGKILL is
        used.

        The child is always waited on so it is reaped.
        """

        try:
            os.killpg(
                process.pid,
                signal.SIGTERM,
            )
        except (
            ProcessLookupError,
            PermissionError,
            OSError,
        ):
            try:
                process.terminate()
            except (
                ProcessLookupError,
                OSError,
            ):
                pass

        try:
            process.wait(
                timeout=(
                    PROCESS_TERMINATION_GRACE_SECONDS
                )
            )
            return

        except subprocess.TimeoutExpired:
            pass

        try:
            os.killpg(
                process.pid,
                signal.SIGKILL,
            )
        except (
            ProcessLookupError,
            PermissionError,
            OSError,
        ):
            try:
                process.kill()
            except (
                ProcessLookupError,
                OSError,
            ):
                pass

        try:
            process.wait()
        except Exception:
            pass

    @staticmethod
    def _join_collector(
        thread: threading.Thread,
    ) -> None:
        """
        Wait for a pipe-draining thread to finish.

        The process has already exited or been terminated at
        this point, so closing its pipe should eventually
        produce EOF.
        """

        thread.join()

    def run(
        self,
        request: ProcessExecutionRequest,
    ) -> ProcessExecutionResult:
        if not isinstance(
            request,
            ProcessExecutionRequest,
        ):
            raise TypeError(
                "request must be a "
                "ProcessExecutionRequest."
            )

        self._validate_request_policy(
            request
        )

        executable_path = (
            self._validate_executable_for_launch(
                request.executable_path
            )
        )

        argv = [
            executable_path,
            *request.arguments,
        ]

        environment = dict(
            self.fixed_environment
        )

        start_time = time.monotonic()

        try:
            process = subprocess.Popen(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                text=False,
                close_fds=True,
                start_new_session=True,
            )

        except (
            OSError,
            ValueError,
            subprocess.SubprocessError,
        ) as exc:
            raise ProcessLaunchError(
                "Operating-system process launch failed."
            ) from exc

        if (
            process.stdout is None
            or process.stderr is None
        ):
            try:
                self._terminate_process_group(
                    process
                )
            finally:
                raise ProcessLaunchError(
                    "Process output pipes were not "
                    "created as required."
                )

        stdout_collector = _BoundedPipeCollector(
            process.stdout,
            self.stdout_max_bytes,
        )

        stderr_collector = _BoundedPipeCollector(
            process.stderr,
            self.stderr_max_bytes,
        )

        stdout_thread = (
            self._start_collector_thread(
                stdout_collector,
                "intentx-stdout-drain",
            )
        )

        stderr_thread = (
            self._start_collector_thread(
                stderr_collector,
                "intentx-stderr-drain",
            )
        )

        timed_out = False
        return_code: Optional[int]

        try:
            process.wait(
                timeout=self.timeout_seconds
            )

            return_code = process.returncode

        except subprocess.TimeoutExpired:
            timed_out = True

            self._terminate_process_group(
                process
            )

            # A timeout is represented independently from the
            # signal-based return code produced during forced
            # termination.
            return_code = None

        finally:
            self._join_collector(
                stdout_thread
            )

            self._join_collector(
                stderr_thread
            )

        duration_ms = max(
            0,
            int(
                (
                    time.monotonic()
                    - start_time
                )
                * 1000
            ),
        )

        if stdout_collector.error is not None:
            raise ProcessLaunchError(
                "Failed while reading process stdout."
            ) from stdout_collector.error

        if stderr_collector.error is not None:
            raise ProcessLaunchError(
                "Failed while reading process stderr."
            ) from stderr_collector.error

        stdout = (
            stdout_collector.retained_bytes()
        )

        stderr = (
            stderr_collector.retained_bytes()
        )

        return ProcessExecutionResult(
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration_ms=duration_ms,
            metadata={
                "stdout_original_bytes":
                    stdout_collector.total_bytes,
                "stdout_retained_bytes":
                    len(stdout),
                "stdout_truncated":
                    stdout_collector.truncated,
                "stderr_original_bytes":
                    stderr_collector.total_bytes,
                "stderr_retained_bytes":
                    len(stderr),
                "stderr_truncated":
                    stderr_collector.truncated,
                "shell":
                    False,
                "parent_environment_inherited":
                    False,
                "stdin":
                    "DEVNULL",
                "start_new_session":
                    True,
            },
        )