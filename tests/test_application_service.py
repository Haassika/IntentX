from dataclasses import dataclass

import pytest

from intentx.application.service import (
    ApplicationRequest,
    ApplicationResult,
    IntentXApplicationService,
)
from intentx.planning.models import OperationPlan
from intentx.planning.planner import PlanningResult


@dataclass(frozen=True)
class FakeAnalysisResult:
    text: str
    predicted_intent: str
    confidence: float
    entities: dict
    intent_accepted: bool
    entities_valid: bool
    decision: str
    reason: str
    missing_entities: list | None = None


class FakeAnalysisPipeline:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def analyze(self, text):
        self.calls.append(text)
        return self.result


class FakePlanner:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def plan(self, text, intent, entities):
        self.calls.append(
            (text, intent, dict(entities))
        )
        return self.result


class FakeBroker:
    def __init__(self):
        self.execute_calls = []

    def execute(
        self,
        plan,
        role,
        environment,
        correlation_id,
        execution_id=None,
    ):
        self.execute_calls.append(
            {
                "plan": plan,
                "role": role,
                "environment": environment,
                "correlation_id": correlation_id,
                "execution_id": execution_id,
            }
        )
        raise AssertionError(
            "Broker execution should not be reached "
            "in this test."
        )


def make_plan():
    return OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="free",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )


def test_application_request_normalizes_values():
    request = ApplicationRequest(
        text="  show memory usage  ",
        role=" viewer ",
        environment=" dev ",
        correlation_id=" corr-001 ",
    )

    assert request.text == "show memory usage"
    assert request.role == "VIEWER"
    assert request.environment == "DEV"
    assert request.correlation_id == "corr-001"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("text", ""),
        ("role", ""),
        ("environment", ""),
        ("correlation_id", ""),
    ],
)
def test_application_request_rejects_empty_required_values(
    field,
    value,
):
    values = {
        "text": "show memory usage",
        "role": "VIEWER",
        "environment": "DEV",
        "correlation_id": "corr-001",
    }
    values[field] = value

    with pytest.raises(ValueError):
        ApplicationRequest(**values)


def test_analysis_rejection_stops_before_planning_and_execution():
    analysis = FakeAnalysisResult(
        text="do something unclear",
        predicted_intent="system_information",
        confidence=0.31,
        entities={},
        intent_accepted=False,
        entities_valid=False,
        decision="CLARIFICATION_REQUIRED",
        reason="Intent confidence is below threshold.",
    )

    analysis_pipeline = FakeAnalysisPipeline(analysis)
    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason="Should never be reached.",
            plan=make_plan(),
        )
    )
    broker = FakeBroker()

    service = IntentXApplicationService(
        analysis_pipeline=analysis_pipeline,
        planner=planner,
        broker=broker,
    )

    result = service.handle(
        ApplicationRequest(
            text="do something unclear",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-002",
        )
    )

    assert isinstance(result, ApplicationResult)
    assert result.status == "CLARIFICATION_REQUIRED"
    assert result.stage == "ANALYSIS"
    assert result.executed is False
    assert planner.calls == []
    assert broker.execute_calls == []


def test_invalid_entities_stop_before_planning_and_execution():
    analysis = FakeAnalysisResult(
        text="read the file",
        predicted_intent="file_read",
        confidence=0.91,
        entities={},
        intent_accepted=True,
        entities_valid=False,
        decision="CLARIFICATION_REQUIRED",
        reason="Required entity information is missing.",
        missing_entities=["PATH"],
    )

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason="Should never be reached.",
            plan=make_plan(),
        )
    )
    broker = FakeBroker()

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            analysis
        ),
        planner=planner,
        broker=broker,
    )

    result = service.handle(
        ApplicationRequest(
            text="read the file",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-003",
        )
    )

    assert result.status == "CLARIFICATION_REQUIRED"
    assert result.stage == "ANALYSIS"
    assert result.missing_entities == ("PATH",)
    assert planner.calls == []
    assert broker.execute_calls == []


def test_planning_failure_stops_before_execution():
    analysis = FakeAnalysisResult(
        text="inspect process",
        predicted_intent="process_inspection",
        confidence=0.94,
        entities={},
        intent_accepted=True,
        entities_valid=True,
        decision="READY_FOR_PLANNING",
        reason="Ready.",
        missing_entities=[],
    )

    planner = FakePlanner(
        PlanningResult(
            planned=False,
            decision="CLARIFICATION_REQUIRED",
            reason="Action is ambiguous.",
            plan=None,
        )
    )
    broker = FakeBroker()

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            analysis
        ),
        planner=planner,
        broker=broker,
    )

    result = service.handle(
        ApplicationRequest(
            text="inspect process",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-004",
        )
    )

    assert result.status == "CLARIFICATION_REQUIRED"
    assert result.stage == "PLANNING"
    assert result.executed is False
    assert broker.execute_calls == []


def test_service_does_not_execute_when_execute_not_requested():
    analysis = FakeAnalysisResult(
        text="show memory usage",
        predicted_intent="memory_inspection",
        confidence=0.98,
        entities={},
        intent_accepted=True,
        entities_valid=True,
        decision="READY_FOR_PLANNING",
        reason="Ready.",
        missing_entities=[],
    )

    plan = make_plan()
    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason="Structured operation plan created.",
            plan=plan,
        )
    )
    broker = FakeBroker()

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            analysis
        ),
        planner=planner,
        broker=broker,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-005",
            execute=False,
        )
    )

    assert result.status == "PLAN_CREATED"
    assert result.stage == "PLANNING"
    assert result.executed is False
    assert result.plan == plan
    assert broker.execute_calls == []


class ReturningFakeBroker:
    def __init__(self, result):
        self.result = result
        self.execute_calls = []

    def execute(
        self,
        plan,
        role,
        environment,
        correlation_id,
        execution_id=None,
    ):
        self.execute_calls.append(
            {
                "plan": plan,
                "role": role,
                "environment": environment,
                "correlation_id": correlation_id,
                "execution_id": execution_id,
            }
        )
        return self.result


def make_ready_analysis():
    return FakeAnalysisResult(
        text="show memory usage",
        predicted_intent="memory_inspection",
        confidence=0.98,
        entities={},
        intent_accepted=True,
        entities_valid=True,
        decision="READY_FOR_PLANNING",
        reason="Ready.",
        missing_entities=[],
    )


def make_execution_result(
    status,
    reason_code,
    reason,
    return_code=None,
):
    from intentx.execution.models import (
        ExecutionResult,
    )

    return ExecutionResult(
        execution_id="exec-001",
        status=status,
        executable="free",
        arguments=("-h",),
        return_code=return_code,
        stdout="",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        reason_code=reason_code,
        reason=reason,
        metadata={},
    )


def test_execute_true_delegates_only_to_broker():
    plan = make_plan()

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason="Plan created.",
            plan=plan,
        )
    )

    execution_result = make_execution_result(
        status="EXECUTED",
        reason_code="EXECUTION_COMPLETED",
        reason="Execution completed.",
        return_code=0,
    )

    broker = ReturningFakeBroker(
        execution_result
    )

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=planner,
        broker=broker,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-006",
            execution_id="exec-001",
            execute=True,
        )
    )

    assert len(broker.execute_calls) == 1

    call = broker.execute_calls[0]

    assert call["plan"] is plan
    assert call["role"] == "VIEWER"
    assert call["environment"] == "DEV"
    assert call["correlation_id"] == "corr-006"
    assert call["execution_id"] == "exec-001"

    assert result.status == "EXECUTED"
    assert result.stage == "EXECUTION"
    assert result.executed is True
    assert result.plan is plan
    assert (
        result.execution_result
        is execution_result
    )


def test_broker_block_remains_blocked():
    plan = make_plan()

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason="Plan created.",
            plan=plan,
        )
    )

    execution_result = make_execution_result(
        status="BLOCKED",
        reason_code="POLICY_NOT_ALLOW",
        reason="Policy did not allow execution.",
    )

    broker = ReturningFakeBroker(
        execution_result
    )

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=planner,
        broker=broker,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="PROD",
            correlation_id="corr-007",
            execution_id="exec-001",
            execute=True,
        )
    )

    assert len(broker.execute_calls) == 1
    assert result.status == "BLOCKED"
    assert result.stage == "EXECUTION"
    assert result.executed is False
    assert (
        result.execution_result.reason_code
        == "POLICY_NOT_ALLOW"
    )


def test_service_never_passes_natural_language_to_broker():
    plan = make_plan()

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason="Plan created.",
            plan=plan,
        )
    )

    broker = ReturningFakeBroker(
        make_execution_result(
            status="BLOCKED",
            reason_code="POLICY_NOT_ALLOW",
            reason="Blocked.",
        )
    )

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=planner,
        broker=broker,
    )

    service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="PROD",
            correlation_id="corr-008",
            execute=True,
        )
    )

    call = broker.execute_calls[0]

    assert isinstance(
        call["plan"],
        OperationPlan,
    )
    assert "text" not in call
    assert "command" not in call


class FakeLifecycleRepository:
    def __init__(self):
        self.records = []

    def save(self, record):
        self.records.append(record)


def test_analysis_rejection_is_persisted():
    analysis = FakeAnalysisResult(
        text="do something unclear",
        predicted_intent="system_information",
        confidence=0.31,
        entities={},
        intent_accepted=False,
        entities_valid=False,
        decision="CLARIFICATION_REQUIRED",
        reason="Intent confidence is below threshold.",
    )

    repository = FakeLifecycleRepository()

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            analysis
        ),
        planner=FakePlanner(
            PlanningResult(
                planned=True,
                decision="PLAN_CREATED",
                reason="Should not be reached.",
                plan=make_plan(),
            )
        ),
        broker=FakeBroker(),
        lifecycle_repository=repository,
    )

    result = service.handle(
        ApplicationRequest(
            text="do something unclear",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-history-001",
        )
    )

    assert result.stage == "ANALYSIS"
    assert len(repository.records) == 1

    record = repository.records[0]

    assert record.correlation_id == (
        "corr-history-001"
    )
    assert record.execution_id is None
    assert record.request_text == (
        "do something unclear"
    )
    assert record.role == "VIEWER"
    assert record.environment == "DEV"
    assert record.stage == "ANALYSIS"
    assert record.status == (
        "CLARIFICATION_REQUIRED"
    )
    assert record.predicted_intent == (
        "system_information"
    )
    assert record.confidence == 0.31


def test_planning_result_is_persisted_without_execution():
    plan = make_plan()
    repository = FakeLifecycleRepository()
    broker = FakeBroker()

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=FakePlanner(
            PlanningResult(
                planned=True,
                decision="PLAN_CREATED",
                reason="Plan created.",
                plan=plan,
            )
        ),
        broker=broker,
        lifecycle_repository=repository,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-history-002",
            execute=False,
        )
    )

    assert result.stage == "PLANNING"
    assert broker.execute_calls == []

    assert [
        record.stage
        for record in repository.records
    ] == [
        "ANALYSIS",
        "PLANNING",
    ]

    assert repository.records[0].status == (
        "READY_FOR_PLANNING"
    )
    assert repository.records[1].status == (
        "PLAN_CREATED"
    )


def test_execution_result_is_persisted_after_broker():
    plan = make_plan()
    repository = FakeLifecycleRepository()

    execution_result = make_execution_result(
        status="EXECUTED",
        reason_code="EXECUTION_COMPLETED",
        reason="Execution completed.",
        return_code=0,
    )

    broker = ReturningFakeBroker(
        execution_result
    )

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=FakePlanner(
            PlanningResult(
                planned=True,
                decision="PLAN_CREATED",
                reason="Plan created.",
                plan=plan,
            )
        ),
        broker=broker,
        lifecycle_repository=repository,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-history-003",
            execution_id="exec-001",
            execute=True,
        )
    )

    assert result.status == "EXECUTED"

    assert [
        record.stage
        for record in repository.records
    ] == [
        "ANALYSIS",
        "PLANNING",
        "EXECUTION",
    ]

    execution_record = repository.records[-1]

    assert execution_record.execution_id == (
        "exec-001"
    )
    assert execution_record.status == "EXECUTED"
    assert execution_record.reason == (
        "Execution completed."
    )


def test_blocked_execution_is_persisted_as_blocked():
    repository = FakeLifecycleRepository()

    execution_result = make_execution_result(
        status="BLOCKED",
        reason_code="POLICY_NOT_ALLOW",
        reason="Policy did not allow execution.",
    )

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=FakePlanner(
            PlanningResult(
                planned=True,
                decision="PLAN_CREATED",
                reason="Plan created.",
                plan=make_plan(),
            )
        ),
        broker=ReturningFakeBroker(
            execution_result
        ),
        lifecycle_repository=repository,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-history-004",
            execution_id="exec-001",
            execute=True,
        )
    )

    assert result.status == "BLOCKED"
    assert result.executed is False
    assert repository.records[-1].status == (
        "BLOCKED"
    )


def test_persistence_does_not_replace_broker_authority():
    repository = FakeLifecycleRepository()
    broker = FakeBroker()

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=FakePlanner(
            PlanningResult(
                planned=True,
                decision="PLAN_CREATED",
                reason="Plan created.",
                plan=make_plan(),
            )
        ),
        broker=broker,
        lifecycle_repository=repository,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-history-005",
            execute=False,
        )
    )

    assert result.status == "PLAN_CREATED"
    assert result.executed is False
    assert broker.execute_calls == []

    assert not hasattr(
        repository,
        "authorize",
    )
    assert not hasattr(
        repository,
        "execute",
    )
    assert not hasattr(
        repository,
        "run",
    )


def test_lifecycle_checkpoints_have_unique_request_ids():
    repository = FakeLifecycleRepository()

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=FakePlanner(
            PlanningResult(
                planned=True,
                decision="PLAN_CREATED",
                reason="Plan created.",
                plan=make_plan(),
            )
        ),
        broker=FakeBroker(),
        lifecycle_repository=repository,
    )

    service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-history-006",
            execute=False,
        )
    )

    request_ids = [
        record.request_id
        for record in repository.records
    ]

    assert len(request_ids) == 2
    assert len(set(request_ids)) == 2

    assert all(
        record.correlation_id
        == "corr-history-006"
        for record in repository.records
    )


def test_application_service_persists_real_sqlite_lifecycle(
    tmp_path,
):
    from intentx.persistence.repository import (
        SQLiteLifecycleRepository,
    )

    database_path = tmp_path / "intentx.db"

    repository = SQLiteLifecycleRepository(
        database_path
    )

    service = IntentXApplicationService(
        analysis_pipeline=FakeAnalysisPipeline(
            make_ready_analysis()
        ),
        planner=FakePlanner(
            PlanningResult(
                planned=True,
                decision="PLAN_CREATED",
                reason="Plan created.",
                plan=make_plan(),
            )
        ),
        broker=FakeBroker(),
        lifecycle_repository=repository,
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id="corr-sqlite-001",
            execute=False,
        )
    )

    assert result.status == "PLAN_CREATED"
    assert result.executed is False

    records = (
        repository.list_by_correlation_id(
            "corr-sqlite-001"
        )
    )

    assert len(records) == 2

    assert [
        record.stage
        for record in records
    ] == [
        "ANALYSIS",
        "PLANNING",
    ]

    assert [
        record.status
        for record in records
    ] == [
        "READY_FOR_PLANNING",
        "PLAN_CREATED",
    ]

    assert (
        records[0].request_id
        != records[1].request_id
    )

    assert all(
        record.correlation_id
        == "corr-sqlite-001"
        for record in records
    )


# ---------------------------------------------------------
# Phase 11B: read-only security assessment integration
# ---------------------------------------------------------


class FakeSecurityAssessmentService:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def assess(
        self,
        plan,
        role,
        environment,
    ):
        self.calls.append(
            {
                "plan": plan,
                "role": role,
                "environment": environment,
            }
        )

        return self.result


def _make_security_assessment():
    from intentx.policy.models import (
        PolicyDecision,
        PolicyReason,
    )
    from intentx.risk.models import (
        RiskAssessmentResult,
    )
    from intentx.security.assessment import (
        SecurityAssessment,
    )

    risk = RiskAssessmentResult(
        score=0,
        level="LOW",
        base_score=0,
        environment_adjustment=0,
        environment="DEV",
        factors=(),
    )

    policy = PolicyDecision(
        decision="ALLOW",
        role="VIEWER",
        environment="DEV",
        intent="memory_inspection",
        action="memory_usage",
        category="inspection",
        risk_score=0,
        risk_level="LOW",
        reasons=(
            PolicyReason(
                code="TEST_ALLOW",
                message=(
                    "Operation is allowed by "
                    "test policy."
                ),
            ),
        ),
        metadata={},
    )

    return SecurityAssessment(
        validation_valid=True,
        validation_decision="VALID",
        validation_issues=(),
        risk=risk,
        policy=policy,
    )


def test_execute_false_returns_security_assessment():
    analysis_pipeline = FakeAnalysisPipeline(
        make_ready_analysis()
    )

    plan = make_plan()

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason=(
                "Structured operation plan created."
            ),
            plan=plan,
        )
    )

    broker = FakeBroker()

    assessment_result = (
        _make_security_assessment()
    )

    assessment_service = (
        FakeSecurityAssessmentService(
            assessment_result
        )
    )

    service = IntentXApplicationService(
        analysis_pipeline=analysis_pipeline,
        planner=planner,
        broker=broker,
        security_assessment_service=(
            assessment_service
        ),
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="viewer",
            environment="dev",
            correlation_id=(
                "corr-security-assessment-001"
            ),
            execute=False,
        )
    )

    assert result.status == "PLAN_CREATED"
    assert result.stage == "PLANNING"
    assert result.executed is False
    assert result.plan is plan

    assert (
        result.security_assessment
        is assessment_result
    )

    assert len(
        assessment_service.calls
    ) == 1

    call = assessment_service.calls[0]

    assert call["plan"] is plan
    assert call["role"] == "VIEWER"
    assert call["environment"] == "DEV"

    assert broker.execute_calls == []


def test_execute_true_still_uses_broker_after_assessment():
    analysis_pipeline = FakeAnalysisPipeline(
        make_ready_analysis()
    )

    plan = make_plan()

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason=(
                "Structured operation plan created."
            ),
            plan=plan,
        )
    )

    execution_result = make_execution_result(
        status="BLOCKED",
        reason_code="TEST_BLOCK",
        reason="Blocked by test broker.",
    )

    broker = ReturningFakeBroker(
        execution_result
    )

    assessment_result = (
        _make_security_assessment()
    )

    assessment_service = (
        FakeSecurityAssessmentService(
            assessment_result
        )
    )

    service = IntentXApplicationService(
        analysis_pipeline=analysis_pipeline,
        planner=planner,
        broker=broker,
        security_assessment_service=(
            assessment_service
        ),
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="viewer",
            environment="dev",
            correlation_id=(
                "corr-security-assessment-002"
            ),
            execute=True,
            execution_id=(
                "exec-assessment-001"
            ),
        )
    )

    assert len(
        assessment_service.calls
    ) == 1

    assert len(
        broker.execute_calls
    ) == 1

    assert (
        result.security_assessment
        is assessment_result
    )

    assert result.stage == "EXECUTION"
    assert result.status == "BLOCKED"


def test_analysis_rejection_does_not_assess_security():
    class AssessmentMustNotBeCalled:
        def assess(
            self,
            plan,
            role,
            environment,
        ):
            raise AssertionError(
                "Security assessment must not "
                "run before a plan exists."
            )

    analysis = FakeAnalysisResult(
        text="do something unclear",
        predicted_intent=(
            "system_information"
        ),
        confidence=0.31,
        entities={},
        intent_accepted=False,
        entities_valid=False,
        decision=(
            "CLARIFICATION_REQUIRED"
        ),
        reason=(
            "Intent confidence is below "
            "threshold."
        ),
        missing_entities=[],
    )

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason=(
                "Should never be reached."
            ),
            plan=make_plan(),
        )
    )

    service = IntentXApplicationService(
        analysis_pipeline=(
            FakeAnalysisPipeline(analysis)
        ),
        planner=planner,
        broker=FakeBroker(),
        security_assessment_service=(
            AssessmentMustNotBeCalled()
        ),
    )

    result = service.handle(
        ApplicationRequest(
            text="do something unclear",
            role="VIEWER",
            environment="DEV",
            correlation_id=(
                "corr-security-assessment-003"
            ),
            execute=False,
        )
    )

    assert result.stage == "ANALYSIS"
    assert (
        result.security_assessment
        is None
    )

    assert planner.calls == []


def test_security_assessment_is_not_execution_authority():
    analysis_pipeline = FakeAnalysisPipeline(
        make_ready_analysis()
    )

    plan = make_plan()

    planner = FakePlanner(
        PlanningResult(
            planned=True,
            decision="PLAN_CREATED",
            reason=(
                "Structured operation plan created."
            ),
            plan=plan,
        )
    )

    broker = FakeBroker()

    assessment_service = (
        FakeSecurityAssessmentService(
            _make_security_assessment()
        )
    )

    service = IntentXApplicationService(
        analysis_pipeline=analysis_pipeline,
        planner=planner,
        broker=broker,
        security_assessment_service=(
            assessment_service
        ),
    )

    result = service.handle(
        ApplicationRequest(
            text="show memory usage",
            role="VIEWER",
            environment="DEV",
            correlation_id=(
                "corr-security-assessment-004"
            ),
            execute=False,
        )
    )

    assert (
        result.security_assessment
        .policy.decision
        == "ALLOW"
    )

    assert result.executed is False
    assert broker.execute_calls == []
