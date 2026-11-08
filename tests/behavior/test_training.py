from datetime import datetime, timedelta, timezone

import pytest

from intentx.behavior.anomaly import (
    BehavioralAnomalyDetector,
    BehavioralAnomalyTrainer,
    load_behavioral_model,
)
from intentx.behavior.baseline import BaselineWindowBuilder
from intentx.behavior.training import BehavioralTrainingWorkflow
from intentx.telemetry.events import (
    CollectionStatus,
    SecurityEvent,
    SecurityEventType,
    TelemetrySource,
)
from intentx.telemetry.repository import SecurityEventRepository


START = datetime(
    2026,
    10,
    2,
    10,
    0,
    tzinfo=timezone.utc,
)


def populate_repository(
    repository: SecurityEventRepository,
    *,
    minutes: int,
) -> None:
    events = []

    for minute in range(minutes):
        observed_at = (
            START
            + timedelta(
                minutes=minute,
                seconds=10,
            )
        )

        events.append(
            SecurityEvent(
                event_id=f"resource-{minute}",
                observed_at=observed_at,
                hostname="linux-lab",
                source=TelemetrySource.RESOURCE,
                event_type=SecurityEventType.RESOURCE_SNAPSHOT,
                collection_status=CollectionStatus.COLLECTED,
                attributes={
                    "load_1m": 0.20 + (minute % 5) * 0.01,
                    "memory_used_ratio": (
                        0.40 + (minute % 4) * 0.01
                    ),
                    "process_count": 100 + (minute % 6),
                },
            )
        )

    repository.save_many(events)


def make_workflow(tmp_path):
    repository = SecurityEventRepository(
        tmp_path / "telemetry.db"
    )
    repository.initialize()

    populate_repository(
        repository,
        minutes=30,
    )

    baseline_builder = BaselineWindowBuilder(
        repository=repository,
        window_seconds=60,
        minimum_windows=30,
    )

    trainer = BehavioralAnomalyTrainer(
        n_estimators=50,
        contamination="auto",
        random_state=42,
    )

    return BehavioralTrainingWorkflow(
        baseline_builder=baseline_builder,
        trainer=trainer,
    )


def test_training_workflow_creates_model_with_provenance(
    tmp_path,
):
    workflow = make_workflow(tmp_path)

    model_path = (
        tmp_path
        / "behavior_isolation_forest_v1.joblib"
    )

    result = workflow.train(
        hostname="linux-lab",
        observation_start=START,
        observation_end=START + timedelta(minutes=30),
        model_path=model_path,
    )

    assert model_path.exists()
    assert result.model_path == model_path
    assert result.hostname == "linux-lab"
    assert result.observation_start == START
    assert result.observation_end == (
        START + timedelta(minutes=30)
    )
    assert result.window_seconds == 60
    assert result.training_samples == 30

    metadata = result.artifact.metadata

    assert metadata.training_samples == 30
    assert metadata.training_hostnames == (
        "linux-lab",
    )
    assert metadata.n_estimators == 50
    assert metadata.random_state == 42


def test_saved_model_can_be_loaded_and_score_window(
    tmp_path,
):
    workflow = make_workflow(tmp_path)

    model_path = tmp_path / "behavior.joblib"

    result = workflow.train(
        hostname="linux-lab",
        observation_start=START,
        observation_end=START + timedelta(minutes=30),
        model_path=model_path,
    )

    loaded = load_behavioral_model(model_path)
    detector = BehavioralAnomalyDetector(loaded)

    score = detector.score(
        result.artifact.model is not None
        and _make_scoring_window()
    )

    assert score.hostname == "linux-lab"
    assert score.model_prediction in (-1, 1)
    assert isinstance(
        score.decision_function,
        float,
    )


def _make_scoring_window():
    from intentx.telemetry.windowing import BehavioralWindow

    return BehavioralWindow(
        window_start=START + timedelta(minutes=31),
        window_end=START + timedelta(minutes=32),
        hostname="linux-lab",
        event_count=110,
        process_event_count=100,
        unique_process_count=100,
        root_process_event_count=2,
        network_connection_count=0,
        network_listener_count=0,
        unique_remote_address_count=0,
        auth_success_count=0,
        auth_failure_count=0,
        privilege_activity_count=0,
        file_activity_count=0,
        audit_event_count=0,
        kernel_event_count=0,
        sensor_unavailable_count=0,
        sensor_error_count=0,
        mean_load_1m=0.22,
        max_load_1m=0.22,
        mean_memory_used_ratio=0.41,
        max_memory_used_ratio=0.41,
        mean_process_count=102.0,
        max_process_count=102,
        mean_process_cpu_percent=0.0,
        max_process_cpu_percent=0.0,
        mean_process_memory_percent=0.0,
        max_process_memory_percent=0.0,
    )


def test_training_rejects_insufficient_observation_period(
    tmp_path,
):
    workflow = make_workflow(tmp_path)

    with pytest.raises(
        ValueError,
        match="minimum",
    ):
        workflow.train(
            hostname="linux-lab",
            observation_start=START,
            observation_end=START + timedelta(minutes=29),
            model_path=tmp_path / "model.joblib",
        )
