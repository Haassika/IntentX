from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from intentx.behavior.anomaly import BehavioralAnomalyTrainer, BehavioralAnomalyDetector, save_behavioral_model, load_behavioral_model
from intentx.behavior.dataset import BehavioralDatasetBuilder
from intentx.telemetry.windowing import BehavioralWindowAggregator, BehavioralWindow
from intentx.telemetry.events import SecurityEvent, SecurityEventType, TelemetrySource, CollectionStatus


def window(index=0, complete=True):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=index)
    attrs = {'memory_used_ratio': .8, 'load_1m': 20, 'process_count': 5}
    if complete:
        attrs.update(cgroup_memory_status='collected',
            cgroup_memory_scope='current_cgroup_and_descendants',
            cgroup_memory_limit_finite=True, cgroup_memory_used_ratio=.1 + index*.01)
    event = SecurityEvent(event_id=str(index), observed_at=start, hostname='lab',
        source=TelemetrySource.RESOURCE, event_type=SecurityEventType.RESOURCE_SNAPSHOT,
        collection_status=CollectionStatus.COLLECTED, attributes=attrs)
    return BehavioralWindowAggregator().aggregate([event], window_start=start, hostname='lab')


def test_v2_has_distinct_container_features_and_no_system_or_lifetime_metrics():
    w = window()
    names = BehavioralWindow.feature_names(2)
    assert len(names) == 19
    assert 'mean_cgroup_memory_used_ratio' in names
    assert 'mean_memory_used_ratio' not in names
    assert 'mean_load_1m' not in names
    assert 'mean_process_cpu_percent' not in names
    assert 'mean_process_memory_percent' not in names
    assert len(w.as_vector()) == 25
    assert w.as_vector(2)[-2:] == (.1, .1)


def test_missing_cgroup_is_rejected_by_v2_but_legacy_still_works():
    w = window(complete=False)
    assert len(w.as_vector()) == 25
    with pytest.raises(ValueError, match='cgroup'):
        w.as_vector(2)


def test_v2_round_trip_and_version_mismatch(tmp_path):
    windows = [window(i) for i in range(4)]
    data = BehavioralDatasetBuilder(feature_schema_version=2).build(windows)
    artifact = BehavioralAnomalyTrainer(n_estimators=5).train(data)
    path = tmp_path/'model.joblib'
    save_behavioral_model(artifact, path)
    detector = BehavioralAnomalyDetector(load_behavioral_model(path))
    assert detector.metadata.feature_schema_version == 2
    assert detector.score(windows[0]).model_prediction in (-1, 1)
    with pytest.raises(RuntimeError, match='version'):
        detector.score(windows[0], feature_schema_version=1)
    with pytest.raises(ValueError, match='cgroup'):
        detector.score(window(complete=False))
    legacy = BehavioralAnomalyDetector(BehavioralAnomalyTrainer(n_estimators=5).train(
        BehavioralDatasetBuilder().build(windows)))
    with pytest.raises(RuntimeError, match='version'):
        legacy.score(windows[0], feature_schema_version=2)


def test_wrong_feature_names_are_rejected():
    data = BehavioralDatasetBuilder(feature_schema_version=2).build([window(0),window(1)])
    with pytest.raises(ValueError, match='schema'):
        BehavioralAnomalyTrainer().train(replace(data, feature_names=BehavioralWindow.FEATURE_NAMES))


@pytest.mark.parametrize('version', [0, 3, -1])
def test_unknown_schema_rejected(version):
    with pytest.raises(ValueError, match='schema'):
        BehavioralDatasetBuilder(feature_schema_version=version)


def test_one_missing_resource_sample_invalidates_v2_window():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = []
    for index in range(2):
        attrs = {} if index else {
            'cgroup_memory_status': 'collected',
            'cgroup_memory_scope': 'current_cgroup_and_descendants',
            'cgroup_memory_limit_finite': True, 'cgroup_memory_used_ratio': .1}
        events.append(SecurityEvent(event_id=str(index), observed_at=start+timedelta(seconds=index),
            hostname='lab', source=TelemetrySource.RESOURCE,
            event_type=SecurityEventType.RESOURCE_SNAPSHOT,
            collection_status=CollectionStatus.COLLECTED, attributes=attrs))
    w = BehavioralWindowAggregator().aggregate(events, window_start=start, hostname='lab')
    with pytest.raises(ValueError, match='cgroup'):
        w.as_vector(2)
