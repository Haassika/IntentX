from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from intentx.behavior.anomaly import (
    MODEL_FORMAT_VERSION,
    BehavioralAnomalyDetector,
    BehavioralAnomalyTrainer,
    BehavioralModelArtifact,
    BehavioralModelMetadata,
    load_behavioral_model,
    save_behavioral_model,
)
from intentx.behavior.dataset import BehavioralDatasetBuilder
from intentx.telemetry.windowing import BehavioralWindow


START = datetime(
    2026,
    10,
    2,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_window(
    *,
    index: int,
    hostname: str = "intentx-test",
    process_count: int | None = None,
) -> BehavioralWindow:
    start = START + timedelta(
        seconds=index * 60
    )

    count = (
        process_count
        if process_count is not None
        else 100 + (index % 4)
    )

    return BehavioralWindow(
        window_start=start,
        window_end=start + timedelta(seconds=60),
        hostname=hostname,
        event_count=count + 10,
        process_event_count=count,
        unique_process_count=count,
        root_process_event_count=2 + (index % 2),
        network_connection_count=5 + (index % 3),
        network_listener_count=2,
        unique_remote_address_count=3 + (index % 2),
        auth_success_count=1,
        auth_failure_count=0,
        privilege_activity_count=0,
        file_activity_count=1 + (index % 2),
        audit_event_count=2,
        kernel_event_count=1,
        sensor_unavailable_count=0,
        sensor_error_count=0,
        mean_load_1m=0.40 + (index % 5) * 0.01,
        max_load_1m=0.60 + (index % 5) * 0.01,
        mean_memory_used_ratio=0.45 + (index % 4) * 0.01,
        max_memory_used_ratio=0.55 + (index % 4) * 0.01,
        mean_process_count=float(count),
        max_process_count=count + 3,
        mean_process_cpu_percent=4.0 + (index % 4),
        max_process_cpu_percent=12.0 + (index % 5),
        mean_process_memory_percent=1.5 + (index % 3) * 0.1,
        max_process_memory_percent=4.0 + (index % 4) * 0.2,
    )


def make_dataset():
    windows = tuple(
        make_window(index=index)
        for index in range(40)
    )

    return BehavioralDatasetBuilder(
        minimum_samples=20
    ).build(windows)


def make_artifact():
    return BehavioralAnomalyTrainer(
        n_estimators=50,
        random_state=42,
    ).train(make_dataset())


def test_trainer_creates_isolation_forest_artifact():
    artifact = make_artifact()

    assert artifact.metadata.model_type == "isolation_forest"
    assert (
        artifact.metadata.model_format_version
        == MODEL_FORMAT_VERSION
    )
    assert artifact.metadata.training_samples == 40
    assert artifact.metadata.training_hostnames == (
        "intentx-test",
    )
    assert artifact.metadata.n_estimators == 50
    assert artifact.metadata.random_state == 42
    assert artifact.metadata.feature_names == tuple(
        BehavioralWindow.FEATURE_NAMES
    )


def test_training_is_reproducible_for_same_data_and_seed():
    dataset = make_dataset()

    first = BehavioralAnomalyTrainer(
        n_estimators=50,
        random_state=42,
    ).train(dataset)

    second = BehavioralAnomalyTrainer(
        n_estimators=50,
        random_state=42,
    ).train(dataset)

    window = make_window(index=50)

    first_score = BehavioralAnomalyDetector(
        first
    ).score(window)

    second_score = BehavioralAnomalyDetector(
        second
    ).score(window)

    assert first_score.decision_function == pytest.approx(
        second_score.decision_function
    )
    assert first_score.score_samples == pytest.approx(
        second_score.score_samples
    )
    assert (
        first_score.model_prediction
        == second_score.model_prediction
    )


def test_detector_scores_window_without_threat_semantics():
    detector = BehavioralAnomalyDetector(
        make_artifact()
    )

    result = detector.score(
        make_window(index=50)
    )

    assert isinstance(
        result.decision_function,
        float,
    )
    assert isinstance(
        result.score_samples,
        float,
    )
    assert result.model_prediction in (-1, 1)
    assert result.is_anomalous == (
        result.model_prediction == -1
    )

    assert not hasattr(result, "threat")
    assert not hasattr(result, "severity")
    assert not hasattr(result, "mitigation")


def test_model_round_trip(tmp_path):
    artifact = make_artifact()

    path = tmp_path / "behavior.joblib"

    save_behavioral_model(
        artifact,
        path,
    )

    loaded = load_behavioral_model(path)

    original_result = BehavioralAnomalyDetector(
        artifact
    ).score(make_window(index=50))

    loaded_result = BehavioralAnomalyDetector(
        loaded
    ).score(make_window(index=50))

    assert (
        loaded.metadata.feature_names
        == artifact.metadata.feature_names
    )

    assert loaded_result.decision_function == pytest.approx(
        original_result.decision_function
    )


def test_load_rejects_missing_model(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_behavioral_model(
            tmp_path / "missing.joblib"
        )


def test_load_rejects_wrong_object(tmp_path):
    import joblib

    path = tmp_path / "wrong.joblib"
    joblib.dump({"not": "a model"}, path)

    with pytest.raises(
        TypeError,
        match="BehavioralModelArtifact",
    ):
        load_behavioral_model(path)


def test_trainer_rejects_invalid_estimator_count():
    with pytest.raises(
        ValueError,
        match="n_estimators",
    ):
        BehavioralAnomalyTrainer(
            n_estimators=0
        )


@pytest.mark.parametrize(
    "value",
    [
        0.0,
        -0.1,
        0.51,
        1.0,
        True,
        "invalid",
    ],
)
def test_trainer_rejects_invalid_contamination(value):
    with pytest.raises(
        ValueError,
        match="contamination",
    ):
        BehavioralAnomalyTrainer(
            contamination=value
        )


def test_trainer_accepts_auto_contamination():
    trainer = BehavioralAnomalyTrainer(
        contamination="auto"
    )

    assert trainer is not None


def test_trainer_accepts_valid_numeric_contamination():
    artifact = BehavioralAnomalyTrainer(
        n_estimators=20,
        contamination=0.1,
    ).train(make_dataset())

    assert artifact.metadata.contamination == 0.1


def test_trainer_rejects_feature_schema_mismatch():
    dataset = make_dataset()

    invalid = replace(
        dataset,
        feature_names=(
            "wrong_feature",
        ),
    )

    with pytest.raises(
        ValueError,
        match="feature schema",
    ):
        BehavioralAnomalyTrainer().train(
            invalid
        )


def test_detector_rejects_runtime_schema_mismatch(
    monkeypatch,
):
    artifact = make_artifact()
    detector = BehavioralAnomalyDetector(
        artifact
    )

    monkeypatch.setattr(
        BehavioralWindow,
        "FEATURE_NAMES",
        (
            "changed_feature",
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="runtime behavioral feature schema",
    ):
        detector.score(
            make_window(index=50)
        )


def test_detector_rejects_empty_hostname():
    detector = BehavioralAnomalyDetector(
        make_artifact()
    )

    invalid = replace(
        make_window(index=50),
        hostname=" ",
    )

    with pytest.raises(
        ValueError,
        match="hostname",
    ):
        detector.score(invalid)


def test_detector_rejects_naive_start():
    detector = BehavioralAnomalyDetector(
        make_artifact()
    )

    window = make_window(index=50)

    invalid = replace(
        window,
        window_start=window.window_start.replace(
            tzinfo=None
        ),
    )

    with pytest.raises(
        ValueError,
        match="start",
    ):
        detector.score(invalid)


def test_detector_rejects_naive_end():
    detector = BehavioralAnomalyDetector(
        make_artifact()
    )

    window = make_window(index=50)

    invalid = replace(
        window,
        window_end=window.window_end.replace(
            tzinfo=None
        ),
    )

    with pytest.raises(
        ValueError,
        match="end",
    ):
        detector.score(invalid)


def test_detector_rejects_invalid_range():
    detector = BehavioralAnomalyDetector(
        make_artifact()
    )

    window = make_window(index=50)

    invalid = replace(
        window,
        window_end=window.window_start,
    )

    with pytest.raises(
        ValueError,
        match="greater than start",
    ):
        detector.score(invalid)


@pytest.mark.parametrize(
    "invalid_value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_detector_rejects_non_finite_vector(
    invalid_value,
):
    detector = BehavioralAnomalyDetector(
        make_artifact()
    )

    invalid = replace(
        make_window(index=50),
        mean_load_1m=invalid_value,
    )

    with pytest.raises(
        ValueError,
        match="finite",
    ):
        detector.score(invalid)


def test_artifact_rejects_wrong_model_type():
    artifact = make_artifact()

    invalid_metadata = replace(
        artifact.metadata,
        model_type="something_else",
    )

    invalid = BehavioralModelArtifact(
        metadata=invalid_metadata,
        model=artifact.model,
    )

    with pytest.raises(
        ValueError,
        match="model type",
    ):
        BehavioralAnomalyDetector(invalid)


def test_artifact_rejects_wrong_format_version():
    artifact = make_artifact()

    invalid_metadata = replace(
        artifact.metadata,
        model_format_version=999,
    )

    invalid = BehavioralModelArtifact(
        metadata=invalid_metadata,
        model=artifact.model,
    )

    with pytest.raises(
        ValueError,
        match="format version",
    ):
        BehavioralAnomalyDetector(invalid)


def test_artifact_rejects_model_without_required_methods():
    metadata = BehavioralModelMetadata(
        model_type="isolation_forest",
        model_format_version=MODEL_FORMAT_VERSION,
        feature_names=tuple(
            BehavioralWindow.FEATURE_NAMES
        ),
        training_samples=10,
        training_hostnames=("host",),
        trained_at=START.isoformat(),
        sklearn_version="test",
        n_estimators=10,
        contamination="auto",
        random_state=42,
    )

    invalid = BehavioralModelArtifact(
        metadata=metadata,
        model=object(),
    )

    with pytest.raises(
        TypeError,
        match="decision_function",
    ):
        BehavioralAnomalyDetector(invalid)


def test_detector_rejects_unseen_hostname():
    detector = BehavioralAnomalyDetector(
        make_artifact()
    )

    unseen = replace(
        make_window(index=50),
        hostname="different-host",
    )

    with pytest.raises(
        ValueError,
        match="not represented",
    ):
        detector.score(unseen)
