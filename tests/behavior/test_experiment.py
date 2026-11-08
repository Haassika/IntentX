from pathlib import Path

import pytest

from intentx.behavior.experiment import (
    BehavioralExperimentConfig,
    _parse_contamination,
    _sha256_file,
)


def test_default_configuration_is_valid():
    config = BehavioralExperimentConfig()

    assert config.duration_seconds == 3600
    assert config.interval_seconds == 5.0
    assert config.window_seconds == 60
    assert config.minimum_windows == 30
    assert config.contamination == "auto"


def test_duration_must_cover_minimum_windows():
    with pytest.raises(
        ValueError,
        match="too short",
    ):
        BehavioralExperimentConfig(
            duration_seconds=120,
            window_seconds=60,
            minimum_windows=3,
        )


def test_duration_must_be_exact_window_multiple():
    with pytest.raises(
        ValueError,
        match="exact multiple",
    ):
        BehavioralExperimentConfig(
            duration_seconds=125,
            window_seconds=60,
            minimum_windows=2,
        )


def test_minimum_windows_must_be_at_least_two():
    with pytest.raises(
        ValueError,
        match="at least two",
    ):
        BehavioralExperimentConfig(
            duration_seconds=60,
            window_seconds=60,
            minimum_windows=1,
        )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("auto", "auto"),
        ("AUTO", "auto"),
        ("0.05", 0.05),
        ("0.5", 0.5),
    ],
)
def test_parse_contamination_accepts_valid_values(
    raw,
    expected,
):
    assert _parse_contamination(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "invalid",
        "0",
        "-0.1",
        "0.6",
    ],
)
def test_parse_contamination_rejects_invalid_values(
    raw,
):
    with pytest.raises(
        Exception,
    ):
        _parse_contamination(raw)


def test_config_rejects_invalid_contamination_string():
    with pytest.raises(
        ValueError,
        match="'auto'",
    ):
        BehavioralExperimentConfig(
            contamination="invalid",
        )


def test_config_rejects_invalid_numeric_contamination():
    with pytest.raises(
        ValueError,
        match="0.0, 0.5",
    ):
        BehavioralExperimentConfig(
            contamination=0.75,
        )


def test_sha256_file(tmp_path: Path):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"intentx")

    assert _sha256_file(sample) == (
        "e3aeb32c37370b442f40fcee700cfece5d0dc691d65f"
        "e783be0f226828843102"
    )


@pytest.mark.parametrize("interval", [float("nan"), float("inf"), 7, 61])
def test_collection_interval_must_be_finite_and_divide_window(interval):
    with pytest.raises(ValueError):
        BehavioralExperimentConfig(interval_seconds=interval)


def _clock(monkeypatch, oversleep=0, wall_only=False):
    from datetime import datetime, timedelta, timezone
    from intentx.behavior import experiment
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    clock = {"mono": 0.0, "wall": 0.0}

    class ClockDateTime:
        @staticmethod
        def now(tz):
            return start + timedelta(seconds=clock["wall"])

    def sleep(seconds):
        clock["mono"] += seconds + (0 if wall_only else oversleep)
        clock["wall"] += seconds + oversleep

    monkeypatch.setattr(experiment, "datetime", ClockDateTime)
    monkeypatch.setattr(experiment.time, "monotonic", lambda: clock["mono"])
    monkeypatch.setattr(experiment.time, "sleep", sleep)
    return start, clock


def test_schedule_collects_expected_slots_and_waits_to_end(monkeypatch):
    from intentx.behavior import experiment
    start, clock = _clock(monkeypatch)
    calls = []
    config = BehavioralExperimentConfig(duration_seconds=4, window_seconds=2, minimum_windows=2, interval_seconds=1)
    experiment._collect_on_schedule(config, lambda: calls.append(clock["wall"]), start)
    assert calls == [0, 1, 2, 3]
    assert clock["wall"] == 4


@pytest.mark.parametrize("oversleep,wall_only", [(2, False), (2, True), (20, False)])
def test_suspend_does_not_collect_catch_up_slots(monkeypatch, oversleep, wall_only):
    from intentx.behavior import experiment
    start, clock = _clock(monkeypatch, oversleep, wall_only)
    calls = []
    config = BehavioralExperimentConfig(duration_seconds=4, window_seconds=2, minimum_windows=2, interval_seconds=1)
    with pytest.raises(RuntimeError):
        experiment._collect_on_schedule(config, lambda: calls.append(clock["wall"]), start)
    assert calls == [0]


def test_slow_collection_crossing_deadline_is_rejected(monkeypatch):
    from intentx.behavior import experiment
    start, clock = _clock(monkeypatch)
    calls = []

    def collect():
        calls.append(clock["wall"])
        clock["wall"] += 10
        clock["mono"] += 10

    config = BehavioralExperimentConfig(duration_seconds=4, window_seconds=2, minimum_windows=2, interval_seconds=1)
    with pytest.raises(RuntimeError, match="deadline"):
        experiment._collect_on_schedule(config, collect, start)
    assert len(calls) == 1


@pytest.mark.parametrize("offsets,valid", [([0, 1, 2, 3], True), ([0, 1, 1.9995, 3], True), ([0, 1], False), ([0, .1, 2, 2.1], False), ([0, 1, 2, 4], False)])
def test_persisted_window_coverage(offsets, valid):
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from intentx.behavior import experiment
    from intentx.telemetry.events import SecurityEventType, CollectionStatus
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [SimpleNamespace(observed_at=start + timedelta(seconds=offset), event_type=SecurityEventType.RESOURCE_SNAPSHOT, collection_status=CollectionStatus.COLLECTED) for offset in offsets]
    config = BehavioralExperimentConfig(duration_seconds=4, window_seconds=2, minimum_windows=2, interval_seconds=1)
    if valid:
        coverage = experiment._validate_collection_coverage(events, config, start)
        assert coverage["complete"]
        assert sum(coverage["resource_snapshots_per_window"]) == 4
    else:
        with pytest.raises(RuntimeError):
            experiment._validate_collection_coverage(events, config, start)


def test_incomplete_run_preserves_failure_and_does_not_train(tmp_path, monkeypatch):
    import json
    from intentx.behavior import experiment
    trained = []
    monkeypatch.setattr(experiment.BehavioralTrainingWorkflow, "train", lambda *a, **kw: trained.append(True))

    def fail(*args):
        raise RuntimeError("simulated suspension")

    monkeypatch.setattr(experiment, "_collect_on_schedule", fail)
    config = BehavioralExperimentConfig(output_root=tmp_path)
    with pytest.raises(RuntimeError, match="suspension"):
        experiment.run_behavioral_baseline_experiment(config)
    failures = list(tmp_path.glob("*/collection_failure.json"))
    assert len(failures) == 1
    assert json.loads(failures[0].read_text())["model_trained"] is False
    assert not trained
    assert not list(tmp_path.glob("*/behavioral_model.joblib"))


@pytest.mark.parametrize("schema", [1, 2])
def test_complete_run_trains_and_records_coverage(tmp_path, monkeypatch, schema):
    import json
    from datetime import timedelta
    from intentx.behavior import experiment
    from intentx.telemetry.events import SecurityEvent, TelemetrySource, SecurityEventType, CollectionStatus
    from intentx.telemetry.service import TelemetryCycleResult
    start, clock = _clock(monkeypatch)

    class FakeService:
        def __init__(self, repository, **kwargs):
            self.repository = repository

        def collect_once(self):
            event = SecurityEvent(
                event_id=str(clock["wall"]),
                observed_at=start + timedelta(seconds=clock["wall"]),
                hostname="lab", source=TelemetrySource.RESOURCE,
                event_type=SecurityEventType.RESOURCE_SNAPSHOT,
                collection_status=CollectionStatus.COLLECTED,
                attributes={"load_1m": clock["wall"],
                    "cgroup_memory_status": "collected",
                    "cgroup_memory_scope": "current_cgroup_and_descendants",
                    "cgroup_memory_limit_finite": True,
                    "cgroup_memory_used_ratio": .1 + clock["wall"] * .01},
            )
            return TelemetryCycleResult(self.repository.save_many([event]), 0)

    monkeypatch.setattr(experiment, "TelemetryService", FakeService)
    config = BehavioralExperimentConfig(duration_seconds=4, window_seconds=2,
        minimum_windows=2, interval_seconds=1, n_estimators=2, output_root=tmp_path, feature_schema_version=schema)
    result = experiment.run_behavioral_baseline_experiment(config)
    manifest = json.loads(result.manifest_path.read_text())
    assert manifest["model"]["feature_schema_version"] == schema
    assert result.collection_cycles == 4
    assert result.training_samples == 2
    assert result.model_path.exists()
    assert manifest["collection_coverage"]["complete"] is True
    assert manifest["collection_coverage"]["resource_snapshots_per_window"] == [2, 2]
    assert not list(tmp_path.glob("*/collection_failure.json"))
