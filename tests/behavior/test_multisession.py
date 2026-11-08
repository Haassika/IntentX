import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import replace
import hashlib

import pytest

from intentx.behavior.multisession import calibration_threshold, validate_plan, run_workflow
from intentx.behavior.anomaly import BehavioralAnomalyDetector, BehavioralAnomalyTrainer
from intentx.behavior.dataset import BehavioralDatasetBuilder


def session(tmp_path, name, minute, windows=2, hostname="lab"):
    from intentx.telemetry.events import SecurityEvent, TelemetrySource, SecurityEventType, CollectionStatus
    from intentx.telemetry.repository import SecurityEventRepository
    p = tmp_path/name; p.mkdir()
    start = datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(minutes=minute)
    repo = SecurityEventRepository(p/'telemetry.db'); repo.initialize()
    events = [SecurityEvent(event_id=f'{name}-{i}', observed_at=start+timedelta(seconds=i*30),
        hostname=hostname, source=TelemetrySource.RESOURCE,
        event_type=SecurityEventType.RESOURCE_SNAPSHOT, collection_status=CollectionStatus.COLLECTED,
        attributes={'cgroup_memory_status':'collected','cgroup_memory_scope':'current_cgroup_and_descendants',
            'cgroup_memory_limit_finite':True,'cgroup_memory_used_ratio':.1+(i%4)*.01})
        for i in range(windows*2)]
    repo.save_many(events)
    m = {'model':{'feature_schema_version':2},'collection_coverage':{'complete':True},
        'observation':{'hostname':hostname,'start_utc':start.isoformat(),
            'end_utc':(start+timedelta(minutes=windows)).isoformat(),
            'events_removed_by_retention':0,'collection_interval_seconds':30,'window_seconds':60},
        'artifacts':{'telemetry_database_sha256':hashlib.sha256((p/'telemetry.db').read_bytes()).hexdigest()}}
    path=p/'manifest.json';path.write_text(json.dumps(m));return str(path)


def plan(tmp_path):
    return {'training':[session(tmp_path,'a',0),session(tmp_path,'b',10)],
        'calibration':[session(tmp_path,'c',20,windows=20)],
        'evaluation':[session(tmp_path,'d',50)]}


def test_cutoff_controls_empirical_rate_and_ties():
    values=[-i/100 for i in range(100)]
    threshold=calibration_threshold(values,.05)
    assert sum(v<threshold for v in values)==5
    assert calibration_threshold([-.5]*20,.05)==-.5


@pytest.mark.parametrize('rate',[0,.5,float('nan')])
def test_invalid_rate_rejected(rate):
    with pytest.raises(ValueError):calibration_threshold([0]*100,rate)


def test_small_calibration_rejected():
    with pytest.raises(ValueError,match='Insufficient'):
        calibration_threshold([-.5]*10,.05)


def test_reused_database_rejected(tmp_path):
    p=plan(tmp_path);p['evaluation']=p['training'][:1]
    with pytest.raises(ValueError,match='Reused'):
        validate_plan(p,tmp_path)


def test_overlapping_sessions_rejected(tmp_path):
    p=plan(tmp_path);p['evaluation']=[session(tmp_path,'overlap',1)]
    with pytest.raises(ValueError,match='Overlapping'):
        validate_plan(p,tmp_path)


def test_changed_database_rejected(tmp_path):
    p=plan(tmp_path)
    db=Path(p['calibration'][0]).parent/'telemetry.db'
    db.write_bytes(db.read_bytes()+b'changed')
    with pytest.raises(ValueError,match='checksum'):
        validate_plan(p,tmp_path)


def test_complete_workflow_freezes_threshold_before_evaluation(tmp_path,monkeypatch):
    import intentx.behavior.multisession as module
    p=plan(tmp_path); pp=tmp_path/'plan.json';pp.write_text(json.dumps(p))
    order=[]; original_windows=module.load_windows; original_cutoff=module.calibration_threshold
    def load(s):
        order.append(s['role']);return original_windows(s)
    def cutoff(*args):
        order.append('cutoff_frozen');return original_cutoff(*args)
    monkeypatch.setattr(module,'load_windows',load)
    monkeypatch.setattr(module,'calibration_threshold',cutoff)
    report=json.loads(run_workflow(pp,tmp_path/'output').read_text())
    assert order.index('cutoff_frozen')<order.index('evaluation')
    assert report['training_windows']==4
    assert report['calibration_windows']==20
    assert report['window_count']==2
    assert report['threshold_chosen_without_evaluation']
    assert report['observed_calibration_flag_rate']<=.05
    for w in report['windows']:
        assert w['decision_function']==pytest.approx(w['score_samples']-report['calibrated_score_threshold'])
        assert w['is_anomalous']==(w['score_samples']<report['calibrated_score_threshold'])


def multi_plan(tmp_path):
    return {'declared_lab_hostnames':['lab-a','lab-b'],
        'training':[session(tmp_path,'ta',0,hostname='lab-a'),session(tmp_path,'tb',0,hostname='lab-b')],
        'calibration':[session(tmp_path,'ca',10,windows=10,hostname='lab-a'),session(tmp_path,'cb',10,windows=10,hostname='lab-b')],
        'evaluation':[session(tmp_path,'ea',30,hostname='lab-a'),session(tmp_path,'eb',30,hostname='lab-b')]}


def test_explicit_multi_host_workflow_and_presentation(tmp_path):
    from intentx.behavior.presentation import read_validation_summary
    p=multi_plan(tmp_path);path=tmp_path/'plan';path.write_text(json.dumps(p))
    report_path=run_workflow(path,tmp_path/'output')
    result=json.loads(report_path.read_text())
    assert set(result['model_metadata']['training_hostnames'])=={'lab-a','lab-b'}
    assert result['window_count']==4
    projected=read_validation_summary(report_path)
    assert {w['hostname'] for w in projected['windows']}=={'lab-a','lab-b'}


def test_multi_host_requires_opt_in_and_training_coverage(tmp_path):
    p=multi_plan(tmp_path);p.pop('declared_lab_hostnames')
    with pytest.raises(ValueError,match='one declared'):validate_plan(p,tmp_path)
    p['declared_lab_hostnames']=['lab-a','lab-b']
    p['evaluation']=[session(tmp_path,'unseen',40,hostname='unseen')]
    with pytest.raises(ValueError,match='represented in training'):validate_plan(p,tmp_path)


def test_multi_host_keeps_overlap_and_duplicate_guards(tmp_path):
    p=multi_plan(tmp_path);p['evaluation']=[session(tmp_path,'overlap',1,hostname='lab-a')]
    with pytest.raises(ValueError,match='Overlapping'):validate_plan(p,tmp_path)
    p['evaluation']=p['training'][:1]
    with pytest.raises(ValueError,match='Reused'):validate_plan(p,tmp_path)


@pytest.mark.parametrize('hosts',[[],['lab-a','lab-a'],[{}],['../../secret'],'lab-a'])
def test_invalid_declared_host_list(tmp_path,hosts):
    with pytest.raises(ValueError,match='Invalid declared'):validate_plan({'declared_lab_hostnames':hosts},tmp_path)


def test_multi_host_rejects_repeated_observations_across_distinct_databases(tmp_path):
    import sqlite3
    p=multi_plan(tmp_path)
    path=Path(p['training'][1]);db=path.parent/'telemetry.db'
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE security_events SET event_id=replace(event_id,'tb-','ta-')")
    m=json.loads(path.read_text())
    m['artifacts']['telemetry_database_sha256']=hashlib.sha256(db.read_bytes()).hexdigest()
    path.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='Reused observations'):
        validate_plan(p,tmp_path)
