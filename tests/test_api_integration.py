from pathlib import Path

from fastapi.testclient import TestClient

from intentx.analysis.pipeline import (
    IntentAnalysisPipeline,
)
from intentx.api.app import create_app
from intentx.application.service import (
    IntentXApplicationService,
)
from intentx.persistence.repository import (
    SQLiteLifecycleRepository,
)
from intentx.execution.models import (
    ExecutionResult,
)
from intentx.planning.planner import (
    OperationPlanner,
)


MODEL_PATH = Path(
    "models/intent_classifier_v2.joblib"
)


def make_real_client(tmp_path):
    database_path = (
        tmp_path / "intentx_integration.db"
    )

    repository = SQLiteLifecycleRepository(
        database_path
    )

    analysis_pipeline = IntentAnalysisPipeline(
        model_path=MODEL_PATH,
    )

    service = IntentXApplicationService(
        analysis_pipeline=analysis_pipeline,
        planner=OperationPlanner(),
        lifecycle_repository=repository,
    )

    app = create_app(
        application_service=service
    )

    return (
        TestClient(app),
        repository,
        database_path,
    )


def test_real_api_analysis_planning_and_persistence(
    tmp_path,
):
    client, repository, database_path = (
        make_real_client(tmp_path)
    )

    correlation_id = (
        "corr-integration-memory-001"
    )

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": correlation_id,
            "execute": False,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["stage"] == "PLANNING"
    assert body["status"] == "PLAN_CREATED"
    assert body["executed"] is False

    assert body["predicted_intent"] == (
        "memory_inspection"
    )

    assert body["confidence"] is not None

    assert body["plan"] is not None
    assert body["plan"]["intent"] == (
        "memory_inspection"
    )
    assert body["plan"]["action"] == (
        "memory_usage"
    )
    assert body["plan"]["executable"] == (
        "free"
    )

    assert body["execution_result"] is None

    assert database_path.exists()

    records = (
        repository.list_by_correlation_id(
            correlation_id
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

    assert all(
        record.correlation_id
        == correlation_id
        for record in records
    )

    assert all(
        record.execution_id is None
        for record in records
    )

    assert records[0].predicted_intent == (
        "memory_inspection"
    )

    assert records[1].status == (
        "PLAN_CREATED"
    )


def test_real_api_execute_false_never_reaches_broker(
    tmp_path,
):
    class BrokerMustNotBeCalled:
        def execute(self, *args, **kwargs):
            raise AssertionError(
                "ExecutionBroker must not be "
                "called when execute=False."
            )

    database_path = (
        tmp_path / "no_execution.db"
    )

    repository = SQLiteLifecycleRepository(
        database_path
    )

    service = IntentXApplicationService(
        analysis_pipeline=(
            IntentAnalysisPipeline(
                model_path=MODEL_PATH,
            )
        ),
        planner=OperationPlanner(),
        broker=BrokerMustNotBeCalled(),
        lifecycle_repository=repository,
    )

    app = create_app(
        application_service=service
    )

    client = TestClient(app)

    correlation_id = (
        "corr-integration-safe-001"
    )

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "VIEWER",
            "environment": "DEV",
            "correlation_id": correlation_id,
            "execute": False,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["executed"] is False
    assert body["stage"] == "PLANNING"
    assert body["execution_result"] is None

    records = (
        repository.list_by_correlation_id(
            correlation_id
        )
    )

    assert [
        record.stage
        for record in records
    ] == [
        "ANALYSIS",
        "PLANNING",
    ]


def test_real_api_execute_true_uses_controlled_broker_and_persists_block(
    tmp_path,
):
    class ControlledBlockingBroker:
        def __init__(self):
            self.calls = []

        def execute(
            self,
            plan,
            role,
            environment,
            correlation_id,
            execution_id=None,
        ):
            self.calls.append(
                {
                    "plan": plan,
                    "role": role,
                    "environment": environment,
                    "correlation_id":
                        correlation_id,
                    "execution_id":
                        execution_id,
                }
            )

            return ExecutionResult(
                execution_id=(
                    execution_id
                    or "exec-controlled-001"
                ),
                status="BLOCKED",
                executable=plan.executable,
                arguments=plan.arguments,
                return_code=None,
                stdout="",
                stderr="",
                stdout_truncated=False,
                stderr_truncated=False,
                reason_code=(
                    "CONTROLLED_TEST_BLOCK"
                ),
                reason=(
                    "Execution intentionally "
                    "blocked by integration test."
                ),
                metadata={
                    "test_boundary": True,
                },
            )

    database_path = (
        tmp_path / "blocked_execution.db"
    )

    repository = SQLiteLifecycleRepository(
        database_path
    )

    broker = ControlledBlockingBroker()

    service = IntentXApplicationService(
        analysis_pipeline=(
            IntentAnalysisPipeline(
                model_path=MODEL_PATH,
            )
        ),
        planner=OperationPlanner(),
        broker=broker,
        lifecycle_repository=repository,
    )

    app = create_app(
        application_service=service
    )

    client = TestClient(app)

    correlation_id = (
        "corr-integration-execution-001"
    )
    execution_id = (
        "exec-integration-001"
    )

    response = client.post(
        "/api/v1/intent",
        json={
            "text": "show memory usage",
            "role": "viewer",
            "environment": "dev",
            "correlation_id":
                correlation_id,
            "execution_id":
                execution_id,
            "execute": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert len(broker.calls) == 1

    call = broker.calls[0]

    assert call["role"] == "VIEWER"
    assert call["environment"] == "DEV"
    assert (
        call["correlation_id"]
        == correlation_id
    )
    assert (
        call["execution_id"]
        == execution_id
    )

    assert call["plan"].intent == (
        "memory_inspection"
    )
    assert call["plan"].action == (
        "memory_usage"
    )
    assert call["plan"].executable == "free"

    assert body["stage"] == "EXECUTION"
    assert body["status"] == "BLOCKED"
    assert body["executed"] is False

    assert body["execution_result"][
        "execution_id"
    ] == execution_id

    assert body["execution_result"][
        "status"
    ] == "BLOCKED"

    assert body["execution_result"][
        "reason_code"
    ] == "CONTROLLED_TEST_BLOCK"

    records = (
        repository.list_by_correlation_id(
            correlation_id
        )
    )

    assert len(records) == 3

    assert [
        record.stage
        for record in records
    ] == [
        "ANALYSIS",
        "PLANNING",
        "EXECUTION",
    ]

    execution_record = records[2]

    assert execution_record.status == (
        "BLOCKED"
    )
    assert (
        execution_record.execution_id
        == execution_id
    )
