from dataclasses import dataclass

import pytest

from intentx.behavior.evaluation import score_benign_windows


@dataclass
class Result:
    is_anomalous: bool


class Detector:
    def score(self, value):
        return Result(value)


def test_benign_flag_rate_and_no_intrusion_claim():
    result = score_benign_windows(Detector(), [False, False, True, False])
    assert result['window_count'] == 4
    assert result['flagged_windows'] == 1
    assert result['benign_flag_rate'] == .25
    assert 'not intrusion classification' in result['interpretation']


def test_rejects_empty_evaluation():
    with pytest.raises(ValueError, match='at least one'):
        score_benign_windows(Detector(), [])


def test_scoring_error_is_not_swallowed():
    class RejectingDetector:
        def score(self, value):
            raise ValueError('unseen hostname')

    with pytest.raises(ValueError, match='hostname'):
        score_benign_windows(RejectingDetector(), [1])


@pytest.mark.parametrize('complete', [True, False])
def test_evaluation_preserves_model_and_rejects_missing_samples(tmp_path, monkeypatch, complete):
    import json
    from datetime import timedelta
    from types import SimpleNamespace
    from intentx.behavior import evaluation
    from intentx.behavior.experiment import BehavioralExperimentConfig
    from intentx.telemetry.events import SecurityEvent, TelemetrySource, SecurityEventType, CollectionStatus
    from intentx.telemetry.service import TelemetryCycleResult
    model = tmp_path / 'frozen.joblib'
    model.write_bytes(b'unchanged frozen model')
    state = {}

    class LabDetector:
        metadata = SimpleNamespace(training_hostnames=('lab',), training_samples=60)
        def __init__(self, artifact):
            pass
        def score(self, window):
            return Result(False)

    class Service:
        def __init__(self, repository, **kwargs):
            self.repository = repository
        def collect_once(self):
            stamp = state['stamp']
            event = SecurityEvent(event_id=stamp.isoformat(), observed_at=stamp,
                hostname='lab', source=TelemetrySource.RESOURCE,
                event_type=SecurityEventType.RESOURCE_SNAPSHOT,
                collection_status=CollectionStatus.COLLECTED)
            return TelemetryCycleResult(self.repository.save_many([event]), 0)

    def schedule(config, collect, start):
        for index in range(4 if complete else 3):
            state['stamp'] = start + timedelta(seconds=index)
            collect()

    monkeypatch.setattr(evaluation, 'load_behavioral_model', lambda path: None)
    monkeypatch.setattr(evaluation, 'BehavioralAnomalyDetector', LabDetector)
    monkeypatch.setattr(evaluation, 'TelemetryService', Service)
    monkeypatch.setattr(evaluation, '_collect_on_schedule', schedule)
    config = BehavioralExperimentConfig(duration_seconds=4, interval_seconds=1,
        window_seconds=2, minimum_windows=2, output_root=tmp_path/'results')
    if complete:
        report = json.loads(evaluation.run_benign_evaluation(config, model).read_text())
        assert report['model_retrained'] is False
        assert report['window_count'] == 2
        assert report['collection_coverage']['complete'] is True
    else:
        with pytest.raises(RuntimeError, match='coverage'):
            evaluation.run_benign_evaluation(config, model)
        assert list((tmp_path/'results').glob('*/evaluation_failure.json'))
        assert not list((tmp_path/'results').glob('*/evaluation.json'))
    assert model.read_bytes() == b'unchanged frozen model'
    assert not list((tmp_path/'results').glob('*/behavioral_model.joblib'))
