"""Collect independent benign telemetry and score a frozen lab baseline."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from intentx.behavior.anomaly import BehavioralAnomalyDetector, load_behavioral_model
from intentx.behavior.baseline import BaselineWindowBuilder
from intentx.behavior.experiment import (
    BehavioralExperimentConfig, _collect_on_schedule,
    _validate_collection_coverage, _write_manifest_atomic,
)
from intentx.telemetry.collector import LinuxTelemetryCollector
from intentx.telemetry.normalizer import TelemetryEventNormalizer
from intentx.telemetry.repository import SecurityEventRepository
from intentx.telemetry.service import TelemetryService


def score_benign_windows(detector, windows):
    """Report model flags, conditional on the caller's declared benign workload."""
    results = [asdict(detector.score(window)) for window in windows]
    if not results:
        raise ValueError("Evaluation requires at least one complete window")
    flagged = sum(result["is_anomalous"] for result in results)
    return {
        "window_count": len(results), "flagged_windows": flagged,
        "benign_flag_rate": flagged / len(results), "windows": results,
        "interpretation": "Flags on a declared benign lab workload; not intrusion classification or real-world accuracy.",
    }


def run_benign_evaluation(config, model_path):
    model_path = Path(model_path)
    original_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    detector = BehavioralAnomalyDetector(load_behavioral_model(model_path))
    started = datetime.now(timezone.utc)
    directory = Path(config.output_root) / started.strftime("%Y%m%dT%H%M%S%fZ")
    directory.mkdir(parents=True, exist_ok=False)
    repository = SecurityEventRepository(directory / "telemetry.db")
    repository.initialize()
    service = TelemetryService(collector=LinuxTelemetryCollector(),
        normalizer=TelemetryEventNormalizer(), repository=repository,
        interval_seconds=config.interval_seconds, max_events=config.max_events)
    from intentx.behavior.provenance import read_workload_profile
    workload_profile = read_workload_profile()
    start = datetime.now(timezone.utc)
    end = start + timedelta(seconds=config.duration_seconds)
    cycles = removed = 0

    def collect():
        nonlocal cycles, removed
        cycle = service.collect_once()
        cycles += 1
        removed += cycle.events_removed_by_retention

    try:
        _collect_on_schedule(config, collect, start)
        if removed:
            raise RuntimeError("Retention removed evaluation telemetry")
        hosts = {event.hostname for event in repository.get_recent(limit=10000)}
        if len(hosts) != 1:
            raise RuntimeError("Expected exactly one evaluation hostname")
        hostname = next(iter(hosts))
        if hostname not in detector.metadata.training_hostnames:
            raise ValueError("Evaluation hostname must match the baseline lab identity")
        events = repository.get_window(hostname=hostname, start_time=start,
            end_time=end, max_events=min(config.max_events, 100000))
        coverage = _validate_collection_coverage(events, config, start)
        baseline = BaselineWindowBuilder(repository=repository,
            feature_schema_version=getattr(detector.metadata, "feature_schema_version", 1),
            window_seconds=config.window_seconds, minimum_windows=config.minimum_windows,
            max_events_per_window=config.max_events_per_window).build(
                hostname=hostname, observation_start=start, observation_end=end)
        report = score_benign_windows(detector, baseline.windows)
        if hashlib.sha256(model_path.read_bytes()).hexdigest() != original_hash:
            raise RuntimeError("Frozen model changed during evaluation")
        report.update({"workload_provenance": workload_profile, "schema_version": 1, "experiment_type": "independent_benign_evaluation",
            "model_retrained": False, "model_sha256": original_hash,
            "model_training_samples": detector.metadata.training_samples,
            "feature_schema_version": getattr(detector.metadata, "feature_schema_version", 1),
            "collection_coverage": coverage, "collection_cycles": cycles,
            "observation": {"hostname": hostname, "start_utc": start.isoformat(), "end_utc": end.isoformat()},
            "note": "Only compare equivalent controlled lab environments. Hostname identity alone does not establish equivalence."})
        destination = directory / "evaluation.json"
        # Anomaly results contain datetime values; preserve them as ISO timestamps.
        payload = json.loads(json.dumps(report, default=lambda value: value.isoformat()))
        _write_manifest_atomic(destination, payload)
        return destination
    except (RuntimeError, ValueError, OSError, KeyboardInterrupt) as exc:
        _write_manifest_atomic(directory / "evaluation_failure.json", {
            "status": "incomplete", "model_retrained": False,
            "reason": str(exc) or "Interrupted", "collection_cycles": cycles,
        })
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, default=600)
    parser.add_argument("--interval-seconds", type=float, default=5)
    parser.add_argument("--output-root", type=Path, default=Path("runtime/behavior/evaluations"))
    args = parser.parse_args()
    config = BehavioralExperimentConfig(duration_seconds=args.duration_seconds,
        interval_seconds=args.interval_seconds, minimum_windows=2, output_root=args.output_root)
    print("Independent benign evaluation; frozen model, no retraining.", flush=True)
    try:
        destination = run_benign_evaluation(config, args.model_path)
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, f"Evaluation rejected: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Evaluation interrupted\n")
    report = json.loads(destination.read_text())
    print(f"Evaluation complete: {report['flagged_windows']}/{report['window_count']} benign windows flagged")
    print(f"report={destination}")


if __name__ == "__main__":
    main()
