from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple
from uuid import uuid4

from intentx.analysis.pipeline import IntentAnalysisPipeline
from intentx.execution.broker import ExecutionBroker
from intentx.execution.models import ExecutionResult
from intentx.persistence.models import LifecycleRecord
from intentx.planning.models import OperationPlan
from intentx.planning.planner import OperationPlanner
from intentx.security.assessment import (
    SecurityAssessment,
    SecurityAssessmentService,
)


@dataclass(frozen=True)
class ApplicationRequest:
    """
    Request entering the IntentX application boundary.

    execute=False keeps analysis and deterministic
    security assessment separate from operating-system
    execution by default.
    """

    text: str
    role: str
    environment: str
    correlation_id: str
    execute: bool = False
    execution_id: Optional[str] = None

    def __post_init__(self):
        text = self._clean_required(
            self.text,
            "text",
        )
        role = self._clean_required(
            self.role,
            "role",
        ).upper()
        environment = self._clean_required(
            self.environment,
            "environment",
        ).upper()
        correlation_id = self._clean_required(
            self.correlation_id,
            "correlation_id",
        )

        if not isinstance(self.execute, bool):
            raise TypeError(
                "execute must be a boolean."
            )

        execution_id = self.execution_id

        if execution_id is not None:
            execution_id = self._clean_required(
                execution_id,
                "execution_id",
            )

        object.__setattr__(
            self,
            "text",
            text,
        )
        object.__setattr__(
            self,
            "role",
            role,
        )
        object.__setattr__(
            self,
            "environment",
            environment,
        )
        object.__setattr__(
            self,
            "correlation_id",
            correlation_id,
        )
        object.__setattr__(
            self,
            "execution_id",
            execution_id,
        )

    @staticmethod
    def _clean_required(
        value: str,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string."
            )

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                f"{field_name} cannot be empty."
            )

        return cleaned


@dataclass(frozen=True)
class ApplicationResult:
    """
    Result returned by the application-service
    orchestration boundary.

    security_assessment is descriptive only.
    It is not an execution request, approval token,
    capability, or authority to launch a process.

    This model represents progression through the
    IntentX lifecycle. It does not independently
    authorize execution.
    """

    status: str
    stage: str
    reason: str
    executed: bool
    predicted_intent: Optional[str] = None
    confidence: Optional[float] = None
    missing_entities: Tuple[str, ...] = ()
    plan: Optional[OperationPlan] = None
    execution_result: Optional[
        ExecutionResult
    ] = None
    security_assessment: Optional[
        SecurityAssessment
    ] = None


class IntentXApplicationService:
    """
    Orchestrates the high-level IntentX lifecycle.

    Analysis-only path:

        Natural-language input
            -> analysis
            -> deterministic planning
            -> read-only security assessment
               -> validation
               -> risk assessment
               -> policy evaluation
            -> application result

    Execution path:

        Natural-language input
            -> analysis
            -> deterministic planning
            -> read-only security assessment
            -> ExecutionBroker
               -> independent validation
               -> independent risk assessment
               -> independent policy evaluation
               -> trusted executable resolution
               -> mandatory audit handling
               -> controlled execution

    The read-only security assessment is never
    treated as execution authority.

    The service never launches an operating-system
    process directly.

    Execution remains opt-in at this boundary.
    Even when execute=True, the service delegates
    exclusively to ExecutionBroker for the actual
    execution security boundary.

    Lifecycle persistence is observational only.
    Persisted records describe request progression
    and must never be treated as authorization or
    execution authority.
    """

    def __init__(
        self,
        analysis_pipeline=None,
        planner=None,
        broker=None,
        lifecycle_repository=None,
        security_assessment_service=None,
    ):
        self.analysis_pipeline = (
            analysis_pipeline
            or IntentAnalysisPipeline()
        )
        self.planner = (
            planner
            or OperationPlanner()
        )
        self.broker = (
            broker
            or ExecutionBroker()
        )
        self.lifecycle_repository = (
            lifecycle_repository
        )
        self.security_assessment_service = (
            security_assessment_service
            or SecurityAssessmentService()
        )

    def handle(
        self,
        request: ApplicationRequest,
    ) -> ApplicationResult:
        if not isinstance(
            request,
            ApplicationRequest,
        ):
            raise TypeError(
                "request must be an "
                "ApplicationRequest."
            )

        analysis = (
            self.analysis_pipeline.analyze(
                request.text
            )
        )

        self._persist_checkpoint(
            request=request,
            stage="ANALYSIS",
            status=analysis.decision,
            reason=analysis.reason,
            predicted_intent=(
                analysis.predicted_intent
            ),
            confidence=analysis.confidence,
            execution_id=None,
        )

        if (
            not analysis.intent_accepted
            or not analysis.entities_valid
            or analysis.decision
            != "READY_FOR_PLANNING"
        ):
            return ApplicationResult(
                status=analysis.decision,
                stage="ANALYSIS",
                reason=analysis.reason,
                executed=False,
                predicted_intent=(
                    analysis.predicted_intent
                ),
                confidence=analysis.confidence,
                missing_entities=tuple(
                    analysis.missing_entities
                    or ()
                ),
            )

        planning = self.planner.plan(
            analysis.text,
            analysis.predicted_intent,
            dict(analysis.entities),
        )

        self._persist_checkpoint(
            request=request,
            stage="PLANNING",
            status=planning.decision,
            reason=planning.reason,
            predicted_intent=(
                analysis.predicted_intent
            ),
            confidence=analysis.confidence,
            execution_id=None,
        )

        if (
            not planning.planned
            or planning.plan is None
        ):
            return ApplicationResult(
                status=planning.decision,
                stage="PLANNING",
                reason=planning.reason,
                executed=False,
                predicted_intent=(
                    analysis.predicted_intent
                ),
                confidence=analysis.confidence,
                missing_entities=(),
            )

        plan = planning.plan

        security_assessment = (
            self.security_assessment_service.assess(
                plan=plan,
                role=request.role,
                environment=request.environment,
            )
        )

        if not request.execute:
            return ApplicationResult(
                status=planning.decision,
                stage="PLANNING",
                reason=planning.reason,
                executed=False,
                predicted_intent=(
                    analysis.predicted_intent
                ),
                confidence=analysis.confidence,
                missing_entities=(),
                plan=plan,
                security_assessment=(
                    security_assessment
                ),
            )

        execution_result = (
            self.broker.execute(
                plan=plan,
                role=request.role,
                environment=request.environment,
                correlation_id=(
                    request.correlation_id
                ),
                execution_id=(
                    request.execution_id
                ),
            )
        )

        self._persist_checkpoint(
            request=request,
            stage="EXECUTION",
            status=execution_result.status,
            reason=execution_result.reason,
            predicted_intent=(
                analysis.predicted_intent
            ),
            confidence=analysis.confidence,
            execution_id=(
                execution_result.execution_id
            ),
        )

        return ApplicationResult(
            status=execution_result.status,
            stage="EXECUTION",
            reason=execution_result.reason,
            executed=(
                execution_result.process_started
            ),
            predicted_intent=(
                analysis.predicted_intent
            ),
            confidence=analysis.confidence,
            missing_entities=(),
            plan=plan,
            execution_result=execution_result,
            security_assessment=(
                security_assessment
            ),
        )

    def _persist_checkpoint(
        self,
        request: ApplicationRequest,
        stage: str,
        status: str,
        reason: str,
        predicted_intent: Optional[str],
        confidence: Optional[float],
        execution_id: Optional[str],
    ) -> None:
        """
        Persist one observational lifecycle checkpoint.

        A fresh request_id is generated for every
        checkpoint so earlier lifecycle stages are
        preserved rather than overwritten.

        This method performs no authorization,
        policy evaluation, planning, or execution.
        """

        if self.lifecycle_repository is None:
            return

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        record = LifecycleRecord(
            request_id=str(uuid4()),
            correlation_id=(
                request.correlation_id
            ),
            execution_id=execution_id,
            request_text=request.text,
            role=request.role,
            environment=request.environment,
            stage=stage,
            status=status,
            predicted_intent=(
                predicted_intent
            ),
            confidence=confidence,
            reason=reason,
            created_at=timestamp,
            updated_at=timestamp,
        )

        self.lifecycle_repository.save(
            record
        )