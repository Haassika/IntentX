"""Continuous frozen-model lab scoring with bounded temporary telemetry."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import socket
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sklearn

from intentx.behavior.anomaly import BehavioralAnomalyDetector, load_behavioral_model
from intentx.behavior.baseline import BaselineWindowBuilder
from intentx.behavior.experiment import BehavioralExperimentConfig, _collect_on_schedule, _validate_collection_coverage, _write_manifest_atomic
from intentx.telemetry.collector import LinuxTelemetryCollector
from intentx.telemetry.live_status import LiveStatusMonitor, SENSORS
from intentx.telemetry.normalizer import TelemetryEventNormalizer
from intentx.telemetry.repository import SecurityEventRepository
from intentx.telemetry.service import TelemetryService
from intentx.telemetry.windowing import BehavioralWindow


def load_frozen_detector(path, expected_hash):
    """Only load an operator-selected local artifact after checking its digest."""
    if len(expected_hash) != 64 or any(c not in '0123456789abcdef' for c in expected_hash):
        raise ValueError('Expected model digest must be lowercase SHA-256')
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected_hash:
        raise ValueError('Frozen model digest mismatch')
    detector = BehavioralAnomalyDetector(load_behavioral_model(path))
    metadata = detector.metadata
    if metadata.feature_schema_version != 2 or metadata.model_format_version != 2 or metadata.calibrated_score_threshold is None:
        raise ValueError('Live scoring requires calibrated schema 2 model format 2')
    if metadata.sklearn_version != sklearn.__version__:
        raise ValueError('Runtime sklearn version differs from frozen model')
    return detector


def score_batch(detector, repository, config, start, *, collect):
    _collect_on_schedule(config, collect, start)
    end = start + timedelta(seconds=config.duration_seconds)
    hostname = socket.gethostname()
    events = repository.get_window(hostname=hostname, start_time=start, end_time=end, max_events=config.max_events)
    coverage = _validate_collection_coverage(events, config, start)
    baseline = BaselineWindowBuilder(repository=repository, window_seconds=config.window_seconds,
        minimum_windows=2, feature_schema_version=2).build(hostname=hostname, observation_start=start, observation_end=end)
    results = []
    for window in baseline.windows:
        result = detector.score(window, feature_schema_version=2)
        results.append({'start_utc': window.window_start.isoformat(), 'end_utc': window.window_end.isoformat(),
            'score': result.score_samples, 'margin': result.decision_function, 'flagged': result.is_anomalous,
            'features': dict(zip(BehavioralWindow.FEATURE_NAMES_V2, window.as_vector(2))),
            'coverage_complete': coverage['complete']})
    return results


class LiveScoringRunner:
    def __init__(self, detector, model_path, model_hash, report_path, status_path):
        self.detector, self.model_path, self.model_hash = detector, Path(model_path), model_hash
        self.report_path = Path(report_path)
        self.monitor = LiveStatusMonitor(status_path)
        self.windows = []
        self.collection_started_at = None

    def publish(self, state):
        _write_manifest_atomic(self.report_path, {'version': 1, 'state': state,
            'updated_at': datetime.now(timezone.utc).isoformat(), 'model_sha256': self.model_hash,
            'feature_schema_version': 2, 'threshold': self.detector.metadata.calibrated_score_threshold,
            'model_retrained': False, 'windows': self.windows,
            **({'collection_started_at': self.collection_started_at.isoformat(), 'startup_seconds': 120}
               if self.collection_started_at is not None else {})})

    def run_batch(self):
        config = BehavioralExperimentConfig(duration_seconds=120, interval_seconds=5,
            window_seconds=60, minimum_windows=2, feature_schema_version=2)
        with tempfile.TemporaryDirectory(prefix='intentx-live-', dir=self.report_path.parent) as directory:
            repository = SecurityEventRepository(Path(directory) / 'telemetry.db')
            repository.initialize()
            runner = self
            class Collector:
                def collect(self):
                    snapshot = LinuxTelemetryCollector().collect()
                    runner.monitor.last_success = snapshot.captured_at.isoformat()
                    sensors = dict.fromkeys(SENSORS, 'unavailable')
                    sensors.update(resource='collected', process='collected', network=snapshot.network_sensor.status.value,
                        cgroup_memory=snapshot.cgroup_memory.status.status.value)
                    runner.monitor.publish('collecting', sensors)
                    runner.publish('collecting' if runner.windows else 'warming_up')
                    return snapshot
            service = TelemetryService(collector=Collector(), normalizer=TelemetryEventNormalizer(), repository=repository)
            def collect():
                result = service.collect_once()
                if result.events_removed_by_retention:
                    raise RuntimeError('Retention invalidated live window')
            start = datetime.now(timezone.utc)
            if self.collection_started_at is None:
                self.collection_started_at = start
            results = score_batch(self.detector, repository, config, start, collect=collect)
            if hashlib.sha256(self.model_path.read_bytes()).hexdigest() != self.model_hash:
                raise RuntimeError('Frozen model changed during collection')
            self.windows = (self.windows + results)[-20:]
            self.publish('collecting')

    def run(self):
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            while True:
                self.run_batch()
        except KeyboardInterrupt:
            self.publish('stopped')
            self.monitor.publish('stopped', dict.fromkeys(SENSORS, 'unknown'))
        except Exception:
            self.publish('error')
            self.monitor.publish('error', dict.fromkeys(SENSORS, 'unknown'))
            raise


def read_live_scores(path, *, now=None):
    if not path:
        return {'status': 'not_configured', 'windows': []}
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(131073)
        if len(raw) > 131072:
            raise ValueError('Oversized live report')
        data = json.loads(raw)
        if data['version'] != 1 or data['state'] not in ('warming_up', 'collecting', 'stopped', 'error') or data['model_retrained'] is not False or data['feature_schema_version'] != 2:
            raise ValueError('Invalid live report')
        stamp = datetime.fromisoformat(data['updated_at'])
        if stamp.tzinfo is None:
            raise ValueError('Naive timestamp')
        age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
        if age < -5:
            raise ValueError('Future timestamp')
        threshold = data['threshold']
        if type(threshold) not in (float, int) or not math.isfinite(threshold):
            raise ValueError('Invalid threshold')
        digest = data['model_sha256']
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Invalid model digest')
        if not isinstance(data['windows'],list) or len(data['windows']) > 20:
            raise ValueError('Invalid window list')
        collection_start = None
        collection_age = None
        phase = 'unknown'
        if 'collection_started_at' in data or 'startup_seconds' in data:
            if type(data['startup_seconds']) is not int or data['startup_seconds'] != 120:
                raise ValueError('Invalid startup period')
            collection_start = datetime.fromisoformat(data['collection_started_at'])
            if collection_start.tzinfo is None or collection_start > stamp:
                raise ValueError('Invalid collection start')
            collection_age = (stamp - collection_start).total_seconds()
            phase = 'startup' if collection_age < 120 else 'steady_state'
        windows = []
        previous = None
        for row in data['windows']:
            start, end = (datetime.fromisoformat(row[k]) for k in ('start_utc', 'end_utc'))
            if start.tzinfo is None or end.tzinfo is None or (end-start).total_seconds()!=60 or end>stamp or (previous and start<previous):
                raise ValueError('Invalid window times')
            if collection_start is not None and start < collection_start:
                raise ValueError('Window precedes collection start')
            window_phase = ('startup' if start < collection_start + timedelta(seconds=120) else 'steady_state') if collection_start else 'unknown'
            previous = end
            score, margin = row['score'], row['margin']
            if any(type(v) not in (float,int) or not math.isfinite(v) for v in (score,margin)) or not math.isclose(margin,score-threshold,abs_tol=1e-10):
                raise ValueError('Invalid scores')
            if type(row['flagged']) is not bool or row['flagged'] != (score<threshold) or row['coverage_complete'] is not True:
                raise ValueError('Invalid flag or coverage')
            features = row['features']
            if not isinstance(features,dict) or set(features)!=set(BehavioralWindow.FEATURE_NAMES_V2) or any(type(v) not in (float,int) or not math.isfinite(v) or v<0 for v in features.values()):
                raise ValueError('Invalid feature evidence')
            windows.append(dict(start_utc=start.isoformat(),end_utc=end.isoformat(),score=score,margin=margin,
                flagged=row['flagged'],features={k:features[k] for k in BehavioralWindow.FEATURE_NAMES_V2},coverage_complete=True,collection_phase=window_phase))
        return {'status': 'stale' if age>30 else data['state'], 'updated_at': stamp.isoformat(),
                'threshold':threshold, 'model_sha256':digest, 'feature_schema_version':2, 'windows':windows,
                'collection_started_at': collection_start.isoformat() if collection_start else None,
                'collection_age_seconds': collection_age, 'collection_phase': phase}
    except (OSError,ValueError,KeyError,TypeError,OverflowError):
        return {'status':'unavailable','windows':[]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-path',type=Path,required=True)
    parser.add_argument('--model-sha256',required=True)
    parser.add_argument('--report-path',type=Path,default=Path('/app/runtime/behavior/live-scores.json'))
    parser.add_argument('--status-path',type=Path,default=Path('/app/runtime/telemetry/live-status.json'))
    args=parser.parse_args()
    if sys.platform!='linux' or os.geteuid()==0:
        parser.error('Run in Linux as a non-root user')
    try:
        detector=load_frozen_detector(args.model_path,args.model_sha256)
        if socket.gethostname() not in detector.metadata.training_hostnames:
            raise ValueError('Runtime hostname is outside frozen model lab identity')
    except (OSError,ValueError,TypeError) as exc:
        parser.error(str(exc))
    for sig in (signal.SIGINT,signal.SIGTERM):
        def stop(*_):
            raise KeyboardInterrupt
        signal.signal(sig,stop)
    LiveScoringRunner(detector,args.model_path,args.model_sha256,args.report_path,args.status_path).run()


if __name__=='__main__':
    main()
