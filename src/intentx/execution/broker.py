from pathlib import Path
from typing import Optional
from uuid import uuid4

import yaml

from intentx.execution.audit import (
    ExecutionAuditRecord,
    JsonlAuditWriter,
    utc_timestamp,
)
from intentx.execution.models import (
    ExecutionRequest,
    ExecutionResult,
)
from intentx.execution.process_runner import (
    ProcessExecutionRequest,
    ProcessLaunchError,
    ProcessRunner,
)
from intentx.execution.resolver import (
    TrustedExecutableResolver,
)
from intentx.planning.models import OperationPlan
from intentx.policy.engine import PolicyEngine
from intentx.risk.engine import RiskAssessmentEngine
from intentx.validation.operation_validator import (
    OperationValidator,
)


DEFAULT_POLICY_PATH = Path(
    "configs/security_policy.yaml"
)

DEFAULT_CATALOG_PATH = Path(
    "configs/intent_catalog.yaml"
)

DEFAULT_AUDIT_PATH = Path(
    "logs/execution_audit.jsonl"
)


class ExecutionBroker:
    """
    Deterministic security boundary immediately preceding
    operating-system execution.

    Authorization and execution deliberately begin from an
    OperationPlan. A previously produced ExecutionRequest is
    not an authority token.

    Before a process can be launched, the broker:

        1. independently validates the exact operation plan,
        2. independently assesses risk,
        3. independently evaluates deterministic policy/RBAC,
        4. requires an explicit ALLOW decision,
        5. resolves the executable only from trusted
           directories,
        6. constructs a process request using runner-owned
           runtime limits,
        7. writes an EXECUTION_ATTEMPTED audit record,
        8. invokes the controlled ProcessRunner,
        9. writes a terminal audit record.

    Failure to write the pre-execution audit record is
    fail-closed: ProcessRunner.run() is never called.
    """

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        catalog_path: Optional[Path] = None,
        validator=None,
        risk_engine=None,
        policy_engine=None,
        resolver=None,
        runner=None,
        audit_writer=None,
        audit_path: Optional[Path] = None,
    ):
        self.policy_path = (
            Path(policy_path)
            if policy_path is not None
            else DEFAULT_POLICY_PATH
        )

        self.catalog_path = (
            Path(catalog_path)
            if catalog_path is not None
            else DEFAULT_CATALOG_PATH
        )

        self.validator = (
            validator
            or OperationValidator(
                catalog_path=self.catalog_path,
            )
        )

        self.risk_engine = (
            risk_engine
            or RiskAssessmentEngine(
                policy_path=self.policy_path,
            )
        )

        self.policy_engine = (
            policy_engine
            or PolicyEngine(
                policy_path=self.policy_path,
                catalog_path=self.catalog_path,
            )
        )

        self.runner = (
            runner
            or ProcessRunner(
                policy_path=self.policy_path,
            )
        )

        self.resolver = (
            resolver
            or TrustedExecutableResolver(
                trusted_directories=(
                    self._load_trusted_directories()
                ),
            )
        )

        resolved_audit_path = (
            Path(audit_path)
            if audit_path is not None
            else DEFAULT_AUDIT_PATH
        )

        self.audit_writer = (
            audit_writer
            or JsonlAuditWriter(
                resolved_audit_path
            )
        )

    def authorize(
        self,
        plan: OperationPlan,
        role: str,
        environment: str,
        execution_id: Optional[str] = None,
    ) -> tuple[
        Optional[ExecutionRequest],
        Optional[ExecutionResult],
    ]:
        """
        Revalidate and reauthorize an exact operation plan.

        Returns:

            (ExecutionRequest, None)

        only when the complete deterministic authorization
        chain produces ALLOW.

        Otherwise returns:

            (None, ExecutionResult)

        with status BLOCKED.

        This method never launches an operating-system
        process.

        ExecutionRequest remains descriptive only. It is not
        accepted by execute() as execution authority.
        """

        if not isinstance(
            plan,
            OperationPlan,
        ):
            raise TypeError(
                "plan must be an OperationPlan."
            )

        normalized_execution_id = (
            self._resolve_execution_id(
                execution_id
            )
        )

        validation = self.validator.validate(
            plan
        )

        if (
            not validation.valid
            or validation.plan is None
        ):
            return (
                None,
                self._blocked_result(
                    execution_id=(
                        normalized_execution_id
                    ),
                    plan=plan,
                    reason_code=(
                        "OPERATION_VALIDATION_FAILED"
                    ),
                    reason=(
                        "The operation failed "
                        "deterministic validation "
                        "at the execution boundary."
                    ),
                    metadata={
                        "validation_decision":
                            validation.decision,
                        "validation_issues": [
                            issue.to_dict()
                            for issue
                            in validation.issues
                        ],
                    },
                ),
            )

        validated_plan = validation.plan

        risk = self.risk_engine.assess(
            validated_plan,
            environment=environment,
        )

        policy = self.policy_engine.evaluate(
            plan=validated_plan,
            risk=risk,
            role=role,
            environment=environment,
        )

        if policy.decision != "ALLOW":
            return (
                None,
                self._blocked_result(
                    execution_id=(
                        normalized_execution_id
                    ),
                    plan=validated_plan,
                    reason_code=(
                        "POLICY_NOT_ALLOW"
                    ),
                    reason=(
                        "Execution requires an "
                        "explicit ALLOW decision "
                        "from the deterministic "
                        "policy engine."
                    ),
                    metadata={
                        "policy_decision":
                            policy.decision,
                        "policy_reason_codes":
                            policy.reason_codes,
                        "risk_score":
                            risk.score,
                        "risk_level":
                            risk.level,
                        "role":
                            policy.role,
                        "environment":
                            policy.environment,
                    },
                ),
            )

        request = ExecutionRequest(
            execution_id=(
                normalized_execution_id
            ),
            role=policy.role,
            environment=policy.environment,
            intent=validated_plan.intent,
            action=validated_plan.action,
            executable=validated_plan.executable,
            arguments=validated_plan.arguments,
        )

        return request, None

    def execute(
        self,
        plan: OperationPlan,
        role: str,
        environment: str,
        correlation_id: str,
        execution_id: Optional[str] = None,
    ) -> ExecutionResult:
        """
        Securely orchestrate one authorized operation.

        The caller must supply an OperationPlan. A prior
        ExecutionRequest cannot be replayed as authority.

        No process launch occurs unless the exact plan passes
        the deterministic authorization chain and the
        pre-execution audit write succeeds.
        """

        if not isinstance(
            plan,
            OperationPlan,
        ):
            raise TypeError(
                "plan must be an OperationPlan."
            )

        normalized_correlation_id = (
            self._resolve_correlation_id(
                correlation_id
            )
        )

        normalized_execution_id = (
            self._resolve_execution_id(
                execution_id
            )
        )

        request, blocked = self.authorize(
            plan=plan,
            role=role,
            environment=environment,
            execution_id=(
                normalized_execution_id
            ),
        )

        if blocked is not None:
            self._write_blocked_audit(
                result=blocked,
                plan=plan,
                role=role,
                environment=environment,
                correlation_id=(
                    normalized_correlation_id
                ),
            )
            return blocked

        if request is None:
            raise RuntimeError(
                "Authorization produced neither an "
                "ExecutionRequest nor a blocked result."
            )

        try:
            executable_path = (
                self.resolver.resolve(
                    request.executable
                )
            )
        except (
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            result = self._blocked_result(
                execution_id=(
                    request.execution_id
                ),
                plan=plan,
                reason_code=(
                    "EXECUTABLE_RESOLUTION_FAILED"
                ),
                reason=(
                    "The authorized executable could "
                    "not be resolved inside the "
                    "configured trusted executable "
                    "directories."
                ),
                metadata={
                    "policy_decision": "ALLOW",
                    "role": request.role,
                    "environment":
                        request.environment,
                    "error_type":
                        type(exc).__name__,
                },
            )

            self._write_blocked_audit(
                result=result,
                plan=plan,
                role=request.role,
                environment=request.environment,
                correlation_id=(
                    normalized_correlation_id
                ),
                policy_decision="ALLOW",
            )
            return result

        process_request = ProcessExecutionRequest(
            executable_path=(
                str(executable_path)
            ),
            arguments=request.arguments,
            timeout_seconds=(
                self.runner.timeout_seconds
            ),
            stdout_max_bytes=(
                self.runner.stdout_max_bytes
            ),
            stderr_max_bytes=(
                self.runner.stderr_max_bytes
            ),
        )

        attempted_record = self._audit_record(
            correlation_id=(
                normalized_correlation_id
            ),
            execution_id=(
                request.execution_id
            ),
            event_type=(
                "EXECUTION_ATTEMPTED"
            ),
            role=request.role,
            environment=request.environment,
            plan=plan,
            policy_decision="ALLOW",
            execution_status="ATTEMPTED",
            return_code=None,
            stdout_truncated=False,
            stderr_truncated=False,
            duration_ms=None,
            reason_code=(
                "EXECUTION_ATTEMPTED"
            ),
            reason=(
                "Authorized execution is entering "
                "the controlled process boundary."
            ),
            metadata={
                "resolved_executable":
                    str(executable_path),
                "timeout_seconds":
                    self.runner.timeout_seconds,
                "stdout_max_bytes":
                    self.runner.stdout_max_bytes,
                "stderr_max_bytes":
                    self.runner.stderr_max_bytes,
            },
        )

        try:
            self.audit_writer.write(
                attempted_record
            )
        except Exception as exc:
            return self._blocked_result(
                execution_id=(
                    request.execution_id
                ),
                plan=plan,
                reason_code=(
                    "AUDIT_PREWRITE_FAILED"
                ),
                reason=(
                    "Execution was blocked because "
                    "the mandatory pre-execution "
                    "audit record could not be "
                    "written."
                ),
                metadata={
                    "policy_decision": "ALLOW",
                    "role": request.role,
                    "environment":
                        request.environment,
                    "error_type":
                        type(exc).__name__,
                },
            )

        try:
            process_result = self.runner.run(
                process_request
            )
        except ProcessLaunchError as exc:
            result = self._blocked_result(
                execution_id=(
                    request.execution_id
                ),
                plan=plan,
                reason_code=(
                    "PROCESS_LAUNCH_FAILED"
                ),
                reason=(
                    "The controlled process boundary "
                    "could not create the operating-"
                    "system process."
                ),
                metadata={
                    "policy_decision": "ALLOW",
                    "role": request.role,
                    "environment":
                        request.environment,
                    "error_type":
                        type(exc).__name__,
                },
            )

            self._write_terminal_audit(
                correlation_id=(
                    normalized_correlation_id
                ),
                request=request,
                plan=plan,
                result=result,
                event_type="EXECUTION_FAILED",
                duration_ms=None,
            )
            return result

        result = self._process_result_to_execution_result(
            execution_id=(
                request.execution_id
            ),
            plan=plan,
            request=request,
            process_result=process_result,
        )

        if result.status == "TIMED_OUT":
            event_type = (
                "EXECUTION_TIMED_OUT"
            )
        elif result.status == "FAILED":
            event_type = (
                "EXECUTION_FAILED"
            )
        else:
            event_type = (
                "EXECUTION_COMPLETED"
            )

        self._write_terminal_audit(
            correlation_id=(
                normalized_correlation_id
            ),
            request=request,
            plan=plan,
            result=result,
            event_type=event_type,
            duration_ms=(
                process_result.duration_ms
            ),
        )

        return result

    def _load_trusted_directories(
        self,
    ):
        try:
            with self.policy_path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                policy = (
                    yaml.safe_load(handle)
                    or {}
                )
        except OSError as exc:
            raise ValueError(
                "Unable to read execution "
                "security policy."
            ) from exc

        try:
            directories = policy[
                "execution_requirements"
            ][
                "process_environment"
            ][
                "trusted_executable_directories"
            ]
        except (
            KeyError,
            TypeError,
        ) as exc:
            raise ValueError(
                "Security policy is missing "
                "trusted executable directories."
            ) from exc

        if (
            isinstance(
                directories,
                (
                    str,
                    bytes,
                    bytearray,
                ),
            )
            or not isinstance(
                directories,
                list,
            )
            or not directories
        ):
            raise ValueError(
                "trusted_executable_directories "
                "must be a non-empty list."
            )

        return tuple(
            directories
        )

    @staticmethod
    def _resolve_execution_id(
        execution_id: Optional[str],
    ) -> str:
        if execution_id is None:
            return f"exec-{uuid4()}"

        if not isinstance(
            execution_id,
            str,
        ):
            raise TypeError(
                "execution_id must be a string "
                "or None."
            )

        normalized = execution_id.strip()

        if not normalized:
            raise ValueError(
                "execution_id cannot be empty."
            )

        return normalized

    @staticmethod
    def _resolve_correlation_id(
        correlation_id: str,
    ) -> str:
        if not isinstance(
            correlation_id,
            str,
        ):
            raise TypeError(
                "correlation_id must be a string."
            )

        normalized = (
            correlation_id.strip()
        )

        if not normalized:
            raise ValueError(
                "correlation_id cannot be empty."
            )

        return normalized

    @staticmethod
    def _blocked_result(
        execution_id: str,
        plan: OperationPlan,
        reason_code: str,
        reason: str,
        metadata,
    ) -> ExecutionResult:
        return ExecutionResult(
            execution_id=execution_id,
            status="BLOCKED",
            executable=plan.executable,
            arguments=plan.arguments,
            return_code=None,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            reason_code=reason_code,
            reason=reason,
            metadata=metadata,
        )

    @staticmethod
    def _decode_output(
        value: bytes,
    ) -> str:
        return value.decode(
            "utf-8",
            errors="replace",
        )

    @staticmethod
    def _metadata_bool(
        metadata,
        key: str,
    ) -> bool:
        value = metadata.get(
            key,
            False,
        )

        return (
            value
            if isinstance(value, bool)
            else False
        )

    def _process_result_to_execution_result(
        self,
        execution_id: str,
        plan: OperationPlan,
        request: ExecutionRequest,
        process_result,
    ) -> ExecutionResult:
        stdout_truncated = (
            self._metadata_bool(
                process_result.metadata,
                "stdout_truncated",
            )
        )

        stderr_truncated = (
            self._metadata_bool(
                process_result.metadata,
                "stderr_truncated",
            )
        )

        metadata = dict(
            process_result.metadata
        )

        metadata.update(
            {
                "policy_decision": "ALLOW",
                "role": request.role,
                "environment":
                    request.environment,
                "duration_ms":
                    process_result.duration_ms,
            }
        )

        if process_result.timed_out:
            status = "TIMED_OUT"
            reason_code = (
                "EXECUTION_TIMED_OUT"
            )
            reason = (
                "The controlled process exceeded "
                "the configured execution timeout."
            )
        elif process_result.return_code == 0:
            status = "EXECUTED"
            reason_code = (
                "EXECUTION_COMPLETED"
            )
            reason = (
                "The controlled process completed "
                "successfully."
            )
        else:
            status = "FAILED"
            reason_code = (
                "PROCESS_EXIT_NONZERO"
            )
            reason = (
                "The controlled process completed "
                "with a non-zero return code."
            )

        return ExecutionResult(
            execution_id=execution_id,
            status=status,
            executable=plan.executable,
            arguments=plan.arguments,
            return_code=(
                process_result.return_code
            ),
            stdout=self._decode_output(
                process_result.stdout
            ),
            stderr=self._decode_output(
                process_result.stderr
            ),
            stdout_truncated=(
                stdout_truncated
            ),
            stderr_truncated=(
                stderr_truncated
            ),
            reason_code=reason_code,
            reason=reason,
            metadata=metadata,
        )

    def _write_blocked_audit(
        self,
        result: ExecutionResult,
        plan: OperationPlan,
        role: str,
        environment: str,
        correlation_id: str,
        policy_decision: Optional[str] = None,
    ) -> None:
        metadata = dict(
            result.metadata
        )

        decision = (
            policy_decision
            or str(
                metadata.get(
                    "policy_decision",
                    "NOT_EVALUATED",
                )
            )
        )

        normalized_role = str(
            metadata.get(
                "role",
                role,
            )
        ).strip().upper()

        normalized_environment = str(
            metadata.get(
                "environment",
                environment,
            )
        ).strip().upper()

        if not normalized_role:
            normalized_role = "UNKNOWN"

        if not normalized_environment:
            normalized_environment = (
                "UNKNOWN"
            )

        record = self._audit_record(
            correlation_id=(
                correlation_id
            ),
            execution_id=(
                result.execution_id
            ),
            event_type=(
                "EXECUTION_BLOCKED"
            ),
            role=normalized_role,
            environment=(
                normalized_environment
            ),
            plan=plan,
            policy_decision=decision,
            execution_status="BLOCKED",
            return_code=None,
            stdout_truncated=False,
            stderr_truncated=False,
            duration_ms=None,
            reason_code=(
                result.reason_code
            ),
            reason=result.reason,
            metadata=metadata,
        )

        self.audit_writer.write(
            record
        )

    def _write_terminal_audit(
        self,
        correlation_id: str,
        request: ExecutionRequest,
        plan: OperationPlan,
        result: ExecutionResult,
        event_type: str,
        duration_ms: Optional[int],
    ) -> None:
        record = self._audit_record(
            correlation_id=(
                correlation_id
            ),
            execution_id=(
                result.execution_id
            ),
            event_type=event_type,
            role=request.role,
            environment=request.environment,
            plan=plan,
            policy_decision="ALLOW",
            execution_status=(
                result.status
            ),
            return_code=(
                result.return_code
            ),
            stdout_truncated=(
                result.stdout_truncated
            ),
            stderr_truncated=(
                result.stderr_truncated
            ),
            duration_ms=duration_ms,
            reason_code=(
                result.reason_code
            ),
            reason=result.reason,
            metadata=dict(
                result.metadata
            ),
        )

        self.audit_writer.write(
            record
        )

    @staticmethod
    def _audit_record(
        correlation_id: str,
        execution_id: str,
        event_type: str,
        role: str,
        environment: str,
        plan: OperationPlan,
        policy_decision: str,
        execution_status: str,
        return_code: Optional[int],
        stdout_truncated: bool,
        stderr_truncated: bool,
        duration_ms: Optional[int],
        reason_code: str,
        reason: str,
        metadata,
    ) -> ExecutionAuditRecord:
        return ExecutionAuditRecord(
            timestamp=utc_timestamp(),
            correlation_id=(
                correlation_id
            ),
            execution_id=execution_id,
            event_type=event_type,
            role=role,
            environment=environment,
            intent=plan.intent,
            action=plan.action,
            executable=plan.executable,
            arguments=plan.arguments,
            policy_decision=(
                policy_decision
            ),
            execution_status=(
                execution_status
            ),
            return_code=return_code,
            stdout_truncated=(
                stdout_truncated
            ),
            stderr_truncated=(
                stderr_truncated
            ),
            duration_ms=duration_ms,
            reason_code=reason_code,
            reason=reason,
            metadata=metadata,
        )
