"""Offline v2 training, benign threshold calibration, and untouched evaluation."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import re
from dataclasses import replace, asdict
from datetime import datetime
from pathlib import Path

from intentx.behavior.anomaly import BehavioralAnomalyTrainer, BehavioralAnomalyDetector, save_behavioral_model
from intentx.behavior.baseline import BaselineWindowBuilder
from intentx.behavior.dataset import BehavioralDatasetBuilder
from intentx.behavior.experiment import BehavioralExperimentConfig, _validate_collection_coverage, _write_manifest_atomic
from intentx.behavior.evaluation import score_benign_windows
from intentx.telemetry.repository import SecurityEventRepository


def calibration_threshold(scores, target_rate):
    """Lower-tail empirical cutoff; ties are unflagged, no future-rate guarantee."""
    if not 0 < target_rate < .5 or not math.isfinite(target_rate):
        raise ValueError('target_rate must be finite and between zero and 0.5')
    values = sorted(float(value) for value in scores)
    if len(values) < math.ceil(1 / target_rate):
        raise ValueError('Insufficient calibration windows for requested rate')
    if not all(math.isfinite(value) for value in values):
        raise ValueError('Calibration scores must be finite')
    return values[math.floor(target_rate * len(values))]


def validate_plan(plan, base):
    declared = plan.get('declared_lab_hostnames')
    if declared is not None:
        if (not isinstance(declared, list) or not declared
                or any(not isinstance(h, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', h) for h in declared) or len(set(declared)) != len(declared)):
            raise ValueError('Invalid declared lab hostnames')
    sessions = []
    fingerprints = set()
    event_ids = set()
    for role in ('training', 'calibration', 'evaluation'):
        paths = plan.get(role, [])
        if len(paths) < (2 if role == 'training' else 1):
            raise ValueError(f'{role} requires independent sessions')
        for raw in paths:
            path = (base / raw).resolve()
            m = json.loads(path.read_text())
            o = m['observation']
            if m['model'].get('feature_schema_version') != 2:
                raise ValueError('Every session must use schema v2')
            if not m['collection_coverage']['complete'] or o['events_removed_by_retention']:
                raise ValueError('Incomplete session')
            db = path.parent / 'telemetry.db'
            digest = hashlib.sha256(db.read_bytes()).hexdigest()
            if digest != m['artifacts']['telemetry_database_sha256']:
                raise ValueError('Session database checksum mismatch')
            if digest in fingerprints:
                raise ValueError('Reused session database across workflow')
            fingerprints.add(digest)
            start = datetime.fromisoformat(o['start_utc'])
            end = datetime.fromisoformat(o['end_utc'])
            if start.tzinfo is None or end.tzinfo is None or end <= start:
                raise ValueError('Invalid observation period')
            for previous in sessions:
                po = previous['manifest']['observation']
                if o['hostname'] == po['hostname'] and start < previous['end'] and previous['start'] < end:
                    raise ValueError('Overlapping observations; sessions must be disjoint')
            connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                ids = {row[0] for row in connection.execute(
                    "SELECT event_id FROM security_events WHERE observed_at >= ? AND observed_at < ?",
                    (start.isoformat(), end.isoformat()))}
            finally:
                connection.close()
            if event_ids.intersection(ids):
                raise ValueError('Reused observations across sessions')
            event_ids.update(ids)
            sessions.append(dict(role=role, path=path, manifest=m, db=db,
                digest=digest, start=start, end=end))
    hosts = {s['manifest']['observation']['hostname'] for s in sessions}
    if declared is None:
        if len(hosts) != 1:
            raise ValueError('Sessions must share one declared lab identity')
    else:
        training_hosts = {s['manifest']['observation']['hostname'] for s in sessions if s['role'] == 'training'}
        if training_hosts != set(declared) or not hosts.issubset(training_hosts):
            raise ValueError('Every declared/evaluation/calibration host must be represented in training')
    return sessions


def load_windows(session):
    m = session['manifest']; o = m['observation']
    seconds = int((session['end'] - session['start']).total_seconds())
    config = BehavioralExperimentConfig(duration_seconds=seconds,
        interval_seconds=o['collection_interval_seconds'], window_seconds=o['window_seconds'],
        minimum_windows=2, feature_schema_version=2)
    repository = SecurityEventRepository(session['db'])
    events = repository.get_window(hostname=o['hostname'], start_time=session['start'],
        end_time=session['end'], max_events=100000)
    _validate_collection_coverage(events, config, session['start'])
    return BaselineWindowBuilder(repository=repository, feature_schema_version=2,
        window_seconds=config.window_seconds, minimum_windows=2).build(
            hostname=o['hostname'], observation_start=session['start'],
            observation_end=session['end']).windows


def run_workflow(plan_path, output, target_rate=.05):
    plan_path = Path(plan_path)
    plan = json.loads(plan_path.read_text())
    sessions = validate_plan(plan, plan_path.parent)
    # Check global window duration consistency before fitting or reading evaluation features.
    if len({s['manifest']['observation']['window_seconds'] for s in sessions}) != 1:
        raise ValueError('Session window durations must match')
    def windows(role):
        return sorted((w for s in sessions if s['role'] == role for w in load_windows(s)), key=lambda w: w.window_start)
    training = windows('training')
    artifact = BehavioralAnomalyTrainer().train(
        BehavioralDatasetBuilder(feature_schema_version=2).build(training, require_single_hostname=plan.get('declared_lab_hostnames') is None))
    calibration = windows('calibration')
    scores = artifact.model.score_samples([w.as_vector(2) for w in calibration])
    cutoff = calibration_threshold(scores, target_rate)
    artifact = replace(artifact, metadata=replace(artifact.metadata, model_format_version=2, calibrated_score_threshold=cutoff))
    # The frozen threshold is now fixed; evaluation observations were not used to choose it.
    evaluation = windows('evaluation')
    report = score_benign_windows(BehavioralAnomalyDetector(artifact), evaluation)
    output = Path(output); output.mkdir(parents=True, exist_ok=False)
    model_path = output / 'behavioral_model.joblib'
    save_behavioral_model(artifact, model_path)
    report.update({
        'experiment_type': 'multisession_v2_benign_validation', 'feature_schema_version': 2,
        'training_windows': len(training), 'calibration_windows': len(calibration),
        'target_calibration_flag_rate': target_rate, 'calibrated_score_threshold': cutoff,
        'observed_calibration_flag_rate': sum(float(v) < cutoff for v in scores) / len(scores),
        'threshold_chosen_without_evaluation': True,
        'model_sha256': hashlib.sha256(model_path.read_bytes()).hexdigest(),
        'model_metadata': asdict(artifact.metadata),
        'declared_lab_hostnames': plan.get('declared_lab_hostnames'),
        'sessions': [{'role':s['role'],'manifest':str(s['path']),'database_sha256':s['digest']} for s in sessions],
        'claim_boundary': 'Empirical controlled benign validation only; no guarantee of future false alarms or attack detection.',
    })
    _write_manifest_atomic(output / 'validation.json', json.loads(json.dumps(report, default=str)))
    return output / 'validation.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--target-rate', type=float, default=.05)
    args = parser.parse_args()
    print(run_workflow(args.plan, args.output_root, args.target_rate))


if __name__ == '__main__':
    main()
