"""Reproducible real-Linux userspace behavioral baseline experiments."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from intentx.behavior.anomaly import BehavioralAnomalyTrainer
from intentx.behavior.baseline import BaselineWindowBuilder
from intentx.behavior.training import BehavioralTrainingWorkflow
from intentx.telemetry.collector import LinuxTelemetryCollector
from intentx.telemetry.normalizer import TelemetryEventNormalizer
from intentx.telemetry.repository import SecurityEventRepository
from intentx.telemetry.service import TelemetryService


@dataclass(frozen=True)
class BehavioralExperimentConfig:
    """Configuration for one declared behavioral baseline experiment."""

    duration_seconds: int = 3600
    interval_seconds: float = 5.0
    window_seconds: int = 60
    minimum_windows: int = 30

    max_events: int = 100_000
    max_events_per_window: int = 10_000

    n_estimators: int = 200
    contamination: str | float = "auto"
    random_state: int = 42
    feature_schema_version: int = 1

    output_root: Path = Path(
        "runtime/behavior/experiments"
    )

    def __post_init__(self) -> None:
        from intentx.telemetry.windowing import BehavioralWindow
        BehavioralWindow.feature_names(self.feature_schema_version)
        if self.duration_seconds < 1:
            raise ValueError(
                "duration_seconds must be greater than zero."
            )

        if not math.isfinite(self.interval_seconds) or self.interval_seconds <= 0:
            raise ValueError(
                "interval_seconds must be greater than zero."
            )

        if self.window_seconds < 1:
            raise ValueError(
                "window_seconds must be greater than zero."
            )

        samples_per_window = self.window_seconds / self.interval_seconds
        if samples_per_window < 1 or not samples_per_window.is_integer():
            raise ValueError("interval_seconds must divide window_seconds exactly.")

        if self.minimum_windows < 2:
            raise ValueError(
                "minimum_windows must be at least two."
            )

        required_duration = (
            self.window_seconds * self.minimum_windows
        )

        if self.duration_seconds < required_duration:
            raise ValueError(
                "duration_seconds is too short for the requested "
                "minimum number of complete windows."
            )

        if self.duration_seconds % self.window_seconds != 0:
            raise ValueError(
                "duration_seconds must be an exact multiple of "
                "window_seconds so the experiment contains only "
                "complete behavioral windows."
            )

        if self.max_events < 1:
            raise ValueError(
                "max_events must be greater than zero."
            )

        if not 1 <= self.max_events_per_window <= 100_000:
            raise ValueError(
                "max_events_per_window must be between "
                "1 and 100000."
            )

        if isinstance(self.contamination, str):
            if self.contamination != "auto":
                raise ValueError(
                    "contamination string must be 'auto'."
                )
        else:
            contamination = float(self.contamination)

            if not 0.0 < contamination <= 0.5:
                raise ValueError(
                    "numeric contamination must be in "
                    "the interval (0.0, 0.5]."
                )


@dataclass(frozen=True)
class BehavioralExperimentResult:
    """Artifacts and provenance produced by one experiment."""

    experiment_id: str
    experiment_directory: Path
    database_path: Path
    model_path: Path
    manifest_path: Path

    hostname: str
    observation_start: datetime
    observation_end: datetime

    collection_cycles: int
    event_count: int
    training_samples: int


def _parse_contamination(value: str) -> str | float:
    cleaned = value.strip().lower()

    if cleaned == "auto":
        return "auto"

    try:
        numeric = float(cleaned)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "contamination must be 'auto' or a float."
        ) from exc

    if not 0.0 < numeric <= 0.5:
        raise argparse.ArgumentTypeError(
            "numeric contamination must be in (0.0, 0.5]."
        )

    return numeric


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _write_manifest_atomic(
    destination: Path,
    payload: dict[str, object],
) -> None:
    temporary = destination.with_suffix(
        destination.suffix + ".tmp"
    )

    temporary.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    temporary.replace(destination)


def _collect_on_schedule(config, collect, observation_start):
    """Reject overdue slots; use UTC too because monotonic may pause on suspend."""
    schedule_start = time.monotonic()
    tolerance = config.interval_seconds / 2
    expected_cycles = int(config.duration_seconds / config.interval_seconds)
    for index in range(expected_cycles):
        offset = index * config.interval_seconds
        remaining = schedule_start + offset - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        elapsed = (datetime.now(timezone.utc) - observation_start).total_seconds()
        monotonic_elapsed = time.monotonic() - schedule_start
        if elapsed >= config.duration_seconds or monotonic_elapsed >= config.duration_seconds:
            raise RuntimeError("Observation deadline reached before all collection slots; no catch-up collection allowed.")
        if abs(elapsed - offset) > tolerance or abs(monotonic_elapsed - offset) > tolerance:
            raise RuntimeError("Collection timing gap or clock jump exceeds half the collection interval; refusing incomplete baseline.")
        collect()
        finished = (datetime.now(timezone.utc) - observation_start).total_seconds()
        if finished >= config.duration_seconds or time.monotonic() - schedule_start >= config.duration_seconds:
            raise RuntimeError("Collection crossed observation deadline; refusing incomplete baseline.")
    remaining = schedule_start + config.duration_seconds - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
    elapsed = (datetime.now(timezone.utc) - observation_start).total_seconds()
    if abs(elapsed - config.duration_seconds) > tolerance:
        raise RuntimeError("Final observation timing gap or clock jump; refusing incomplete baseline.")


def _validate_collection_coverage(events, config, observation_start):
    """Validate scheduled slots independently of small window-boundary jitter."""
    snapshots = sorted(
        event.observed_at for event in events
        if event.event_type.value == "resource_snapshot"
        and event.collection_status.value == "collected"
    )
    expected_per_window = int(config.window_seconds / config.interval_seconds)
    counts = [0] * (config.duration_seconds // config.window_seconds)
    for stamp in snapshots:
        offset = (stamp - observation_start).total_seconds()
        if not 0 <= offset < config.duration_seconds:
            raise RuntimeError("Resource snapshot outside observation period.")
        counts[int(offset // config.window_seconds)] += 1
    expected_cycles = int(config.duration_seconds / config.interval_seconds)
    if len(snapshots) != expected_cycles:
        raise RuntimeError(f"Incomplete resource coverage: {len(snapshots)} snapshots; expected {expected_cycles}.")
    if any(count == 0 for count in counts):
        raise RuntimeError("Incomplete resource coverage: empty behavioral window.")
    tolerance = config.interval_seconds / 2
    offsets = [(stamp - observation_start).total_seconds() for stamp in snapshots]
    if any(abs(offset - index * config.interval_seconds) > tolerance
           for index, offset in enumerate(offsets)):
        raise RuntimeError("Persisted resource timestamps contain collection gaps or catch-up bursts.")
    return {
        "complete": True,
        "expected_collection_cycles": expected_cycles,
        "expected_resource_snapshots_per_window": expected_per_window,
        "validation_basis": "one resource timestamp per scheduled slot",
        "resource_snapshots_per_window": counts,
        "maximum_allowed_slot_lateness_seconds": tolerance,
    }


def run_behavioral_baseline_experiment(
    config: BehavioralExperimentConfig,
) -> BehavioralExperimentResult:
    """
    Collect genuine Linux userspace telemetry and train one baseline.

    This workflow establishes evidence for Linux behavioral monitoring.
    It does NOT establish kernel-level or audit-event monitoring and does
    not classify activity as malicious or an intrusion.
    """

    started_at = datetime.now(timezone.utc)

    experiment_id = started_at.strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    experiment_directory = (
        Path(config.output_root) / experiment_id
    )

    experiment_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    database_path = (
        experiment_directory / "telemetry.db"
    )

    model_path = (
        experiment_directory
        / "behavioral_model.joblib"
    )

    manifest_path = (
        experiment_directory
        / "manifest.json"
    )

    repository = SecurityEventRepository(
        database_path
    )

    repository.initialize()

    if repository.count() != 0:
        raise RuntimeError(
            "baseline experiment database must begin empty."
        )

    telemetry_service = TelemetryService(
        collector=LinuxTelemetryCollector(),
        normalizer=TelemetryEventNormalizer(),
        repository=repository,
        interval_seconds=config.interval_seconds,
        max_events=config.max_events,
    )

    from intentx.behavior.provenance import read_workload_profile
    workload_profile = read_workload_profile()

    observation_start = datetime.now(
        timezone.utc
    )

    observation_end = observation_start + timedelta(seconds=config.duration_seconds)
    collection_cycles = 0
    events_saved = 0
    events_removed = 0

    def collect():
        nonlocal collection_cycles, events_saved, events_removed
        cycle = telemetry_service.collect_once()
        collection_cycles += 1
        events_saved += cycle.events_collected
        events_removed += cycle.events_removed_by_retention

    try:
        _collect_on_schedule(config, collect, observation_start)
        if events_removed:
            raise RuntimeError("Telemetry retention removed events; refusing incomplete baseline.")
        recent = repository.get_recent(limit=min(max(repository.count(), 1), 10_000))
        hostnames = {event.hostname for event in recent}
        if len(hostnames) != 1:
            raise RuntimeError("Expected telemetry from exactly one hostname.")
        hostname = next(iter(hostnames))
        events = repository.get_window(
            hostname=hostname, start_time=observation_start,
            end_time=observation_end, max_events=min(config.max_events, 100_000),
        )
        coverage = _validate_collection_coverage(events, config, observation_start)
        if config.feature_schema_version == 2:
            BaselineWindowBuilder(repository=repository,
                window_seconds=config.window_seconds, minimum_windows=config.minimum_windows,
                max_events_per_window=config.max_events_per_window,
                feature_schema_version=2).build(hostname=hostname,
                    observation_start=observation_start, observation_end=observation_end)
    except (RuntimeError, ValueError, OSError, KeyboardInterrupt) as exc:
        _write_manifest_atomic(experiment_directory / "collection_failure.json", {
            "status": "incomplete", "model_trained": False,
            "reason": str(exc) or "Experiment interrupted",
            "collection_cycles": collection_cycles,
            "events_reported_saved": events_saved,
            "events_removed_by_retention": events_removed,
            "start_utc": observation_start.isoformat(),
            "planned_end_utc": observation_end.isoformat(),
            "failure_utc": datetime.now(timezone.utc).isoformat(),
        })
        raise

    print("Collection coverage validated: all scheduled resource snapshots are present. Training baseline.", flush=True)

    baseline_builder = BaselineWindowBuilder(
        feature_schema_version=config.feature_schema_version,
        repository=repository,
        window_seconds=config.window_seconds,
        minimum_windows=config.minimum_windows,
        max_events_per_window=(
            config.max_events_per_window
        ),
    )

    trainer = BehavioralAnomalyTrainer(
        n_estimators=config.n_estimators,
        contamination=config.contamination,
        random_state=config.random_state,
    )

    workflow = BehavioralTrainingWorkflow(
        baseline_builder=baseline_builder,
        trainer=trainer,
    )

    training_result = workflow.train(
        hostname=hostname,
        observation_start=observation_start,
        observation_end=observation_end,
        model_path=model_path,
    )

    source_counts = Counter(
        event.source.value
        for event in events
    )

    event_type_counts = Counter(
        event.event_type.value
        for event in events
    )

    status_counts = Counter(
        event.collection_status.value
        for event in events
    )

    metadata = training_result.artifact.metadata

    kernel_audit_event_count = sum(
        count
        for name, count
        in source_counts.items()
        if name in {
            "linux_audit",
            "kernel",
        }
    )

    manifest: dict[str, object] = {
        "schema_version": 2,
        "collection_coverage": coverage,
        "workload_provenance": workload_profile,
        "experiment_id": experiment_id,
        "experiment_type": (
            "linux_userspace_behavioral_baseline"
        ),
        "claim_boundary": {
            "genuine_linux_userspace_telemetry": True,
            "behavioral_baseline_training": True,
            "kernel_level_monitoring_validated": False,
            "linux_audit_monitoring_validated": False,
            "intrusion_classification_validated": False,
            "note": (
                "This experiment evaluates Linux userspace "
                "behavioral telemetry only. Kernel/audit "
                "evidence requires a separate Linux security "
                "lab experiment."
            ),
        },
        "runtime": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "source_revision": os.getenv(
                "INTENTX_SOURCE_REVISION"
            ),
        },
        "observation": {
            "hostname": hostname,
            "start_utc": (
                observation_start.isoformat()
            ),
            "end_utc": (
                observation_end.isoformat()
            ),
            "duration_seconds": (
                config.duration_seconds
            ),
            "collection_interval_seconds": (
                config.interval_seconds
            ),
            "collection_cycles": (
                collection_cycles
            ),
            "events_reported_saved": events_saved,
            "events_in_training_period": len(events),
            "events_removed_by_retention": (
                events_removed
            ),
            "window_seconds": (
                config.window_seconds
            ),
            "minimum_windows": (
                config.minimum_windows
            ),
        },
        "telemetry": {
            "source_counts": dict(
                sorted(source_counts.items())
            ),
            "event_type_counts": dict(
                sorted(event_type_counts.items())
            ),
            "collection_status_counts": dict(
                sorted(status_counts.items())
            ),
            "kernel_or_audit_event_count": (
                kernel_audit_event_count
            ),
            "note": (
                "Absence of an event source does not by itself "
                "prove that a sensor was unavailable; for "
                "example, a collected network sensor may observe "
                "zero active connections."
            ),
        },
        "model": {
            "model_type": metadata.model_type,
            "model_format_version": (
                metadata.model_format_version
            ),
            "feature_schema_version": metadata.feature_schema_version,
            "feature_names": list(
                metadata.feature_names
            ),
            "training_samples": (
                metadata.training_samples
            ),
            "training_hostnames": list(
                metadata.training_hostnames
            ),
            "trained_at_utc": (
                metadata.trained_at
            ),
            "sklearn_version": (
                metadata.sklearn_version
            ),
            "n_estimators": (
                metadata.n_estimators
            ),
            "contamination": (
                metadata.contamination
            ),
            "random_state": (
                metadata.random_state
            ),
        },
        "artifacts": {
            "telemetry_database": (
                database_path.name
            ),
            "behavioral_model": (
                model_path.name
            ),
            "manifest": (
                manifest_path.name
            ),
            "telemetry_database_sha256": (
                _sha256_file(database_path)
            ),
            "behavioral_model_sha256": (
                _sha256_file(model_path)
            ),
        },
    }

    _write_manifest_atomic(
        manifest_path,
        manifest,
    )

    return BehavioralExperimentResult(
        experiment_id=experiment_id,
        experiment_directory=(
            experiment_directory
        ),
        database_path=database_path,
        model_path=model_path,
        manifest_path=manifest_path,
        hostname=hostname,
        observation_start=observation_start,
        observation_end=observation_end,
        collection_cycles=collection_cycles,
        event_count=len(events),
        training_samples=(
            training_result.training_samples
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect genuine Linux userspace telemetry "
            "and train an IntentX behavioral baseline."
        )
    )

    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=3600,
    )

    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=5.0,
    )

    parser.add_argument(
        "--window-seconds",
        type=int,
        default=60,
    )

    parser.add_argument(
        "--minimum-windows",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(
            "runtime/behavior/experiments"
        ),
    )

    parser.add_argument(
        "--n-estimators",
        type=int,
        default=200,
    )

    parser.add_argument(
        "--contamination",
        type=_parse_contamination,
        default="auto",
    )

    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
    )

    parser.add_argument("--feature-schema-version", type=int, choices=(1, 2), default=1)
    return parser


def main() -> None:
    parser = _build_parser()
    arguments = parser.parse_args()

    config = BehavioralExperimentConfig(
        feature_schema_version=arguments.feature_schema_version,
        duration_seconds=(
            arguments.duration_seconds
        ),
        interval_seconds=(
            arguments.interval_seconds
        ),
        window_seconds=(
            arguments.window_seconds
        ),
        minimum_windows=(
            arguments.minimum_windows
        ),
        output_root=arguments.output_root,
        n_estimators=arguments.n_estimators,
        contamination=arguments.contamination,
        random_state=arguments.random_state,
    )

    print(
        "IntentX behavioral baseline experiment"
    )
    print(
        "Scope: genuine Linux userspace telemetry; "
        "not kernel/audit validation."
    )
    print(
        f"Duration: {config.duration_seconds}s"
    )
    print(
        f"Cadence: {config.interval_seconds}s"
    )
    print(
        f"Window: {config.window_seconds}s"
    )

    try:
        result = (
            run_behavioral_baseline_experiment(
                config
            )
        )
    except KeyboardInterrupt:
        print()
        print(
            "Experiment interrupted. "
            "No completed baseline is being claimed."
        )
        raise SystemExit(130)
    except (RuntimeError, ValueError) as exc:
        print(f"Experiment rejected: {exc}")
        print("No completed baseline or trained model is being claimed. See collection_failure.json.")
        raise SystemExit(1) from exc

    print()
    print("=== EXPERIMENT COMPLETE ===")
    print(
        f"experiment_id={result.experiment_id}"
    )
    print(
        f"hostname={result.hostname}"
    )
    print(
        f"collection_cycles="
        f"{result.collection_cycles}"
    )
    print(
        f"events={result.event_count}"
    )
    print(
        f"training_samples="
        f"{result.training_samples}"
    )
    print(
        f"database={result.database_path}"
    )
    print(
        f"model={result.model_path}"
    )
    print(
        f"manifest={result.manifest_path}"
    )


if __name__ == "__main__":
    main()
