import hashlib
import json
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from intentx.api.app import create_app
from intentx.behavior import live
from intentx.telemetry.windowing import BehavioralWindow

NOW=datetime.now(timezone.utc)
def report(path, **kw):
    row=dict(start_utc=(NOW-timedelta(seconds=60)).isoformat(),end_utc=NOW.isoformat(),score=-.6,margin=-.1,flagged=True,coverage_complete=True,features=dict.fromkeys(BehavioralWindow.FEATURE_NAMES_V2,0.0))
    data=dict(version=1,state='collecting',updated_at=NOW.isoformat(),model_sha256='a'*64,feature_schema_version=2,threshold=-.5,model_retrained=False,windows=[row])
    data.update(kw);path.write_text(json.dumps(data));return data

def test_projection_and_stale(tmp_path):
    p=tmp_path/'report';report(p);before=p.read_bytes()
    d=live.read_live_scores(p,now=NOW)
    assert d['status']=='collecting' and d['windows'][0]['flagged'] is True
    assert len(d['windows'][0]['features'])==19
    assert live.read_live_scores(p,now=NOW+timedelta(seconds=31))['status']=='stale'
    assert p.read_bytes()==before

@pytest.mark.parametrize('change',[dict(state='healthy'),dict(model_retrained=True),dict(feature_schema_version=1),dict(threshold=float('nan')),dict(model_sha256='bad'),dict(windows=[{}]),dict(updated_at='bad'),dict(windows=[1]*21)])
def test_invalid(tmp_path,change):
    p=tmp_path/'report';report(p,**change)
    assert live.read_live_scores(p,now=NOW)=={'status':'unavailable','windows':[]}

@pytest.mark.parametrize('field,value',[('flagged',False),('coverage_complete',False),('margin',.1),('score',float('nan')),('features',list(BehavioralWindow.FEATURE_NAMES_V2))])
def test_inconsistent_evidence(tmp_path,field,value):
    p=tmp_path/'report';d=report(p);d['windows'][0][field]=value;p.write_text(json.dumps(d))
    assert live.read_live_scores(p,now=NOW)['status']=='unavailable'

def test_missing_bounds_and_api(tmp_path):
    p=tmp_path/'report'
    assert live.read_live_scores(None)['status']=='not_configured'
    assert live.read_live_scores(p)['status']=='unavailable'
    p.write_text(' '*131073);assert live.read_live_scores(p)['status']=='unavailable'
    report(p);c=TestClient(create_app(live_scores_path=p))
    assert c.get('/api/v1/behavior/live?path=/secret').json()['status']=='collecting'
    assert c.post('/api/v1/behavior/live').status_code==405
    assert 'Feature values show measured evidence' in c.get('/').text

def test_digest_checked_before_loading(tmp_path,monkeypatch):
    p=tmp_path/'model';p.write_bytes(b'model')
    monkeypatch.setattr(live,'load_behavioral_model',lambda *_:pytest.fail('loaded mismatched model'))
    with pytest.raises(ValueError,match='digest mismatch'):live.load_frozen_detector(p,'a'*64)


def test_contract_rejects_uncalibrated_model(tmp_path,monkeypatch):
    p=tmp_path/'model';p.write_bytes(b'model');digest=hashlib.sha256(p.read_bytes()).hexdigest()
    monkeypatch.setattr(live,'load_behavioral_model',lambda *_:None)
    monkeypatch.setattr(live,'BehavioralAnomalyDetector',lambda _:SimpleNamespace(metadata=SimpleNamespace(feature_schema_version=1,model_format_version=1,calibrated_score_threshold=None)))
    with pytest.raises(ValueError,match='calibrated schema'):live.load_frozen_detector(p,digest)


def test_rejected_coverage_never_scores(monkeypatch):
    monkeypatch.setattr(live,'_collect_on_schedule',lambda *args:None)
    monkeypatch.setattr(live,'_validate_collection_coverage',lambda *args:(_ for _ in ()).throw(RuntimeError('missing coverage')))
    detector=SimpleNamespace(score=lambda *_:pytest.fail('invalid coverage scored'))
    repo=SimpleNamespace(get_window=lambda **_:())
    with pytest.raises(RuntimeError,match='coverage'):
        live.score_batch(detector,repo,SimpleNamespace(duration_seconds=120,max_events=10000),NOW,collect=lambda:None)


def test_error_and_stop_are_published(tmp_path,monkeypatch):
    d=SimpleNamespace(metadata=SimpleNamespace(calibrated_score_threshold=-.5))
    runner=live.LiveScoringRunner(d,tmp_path/'model','a'*64,tmp_path/'scores',tmp_path/'status')
    monkeypatch.setattr(runner,'run_batch',lambda:(_ for _ in ()).throw(RuntimeError('private')))
    with pytest.raises(RuntimeError):runner.run()
    assert live.read_live_scores(tmp_path/'scores')['status']=='error'
    assert 'private' not in (tmp_path/'scores').read_text()
    monkeypatch.setattr(runner,'run_batch',lambda:(_ for _ in ()).throw(KeyboardInterrupt()))
    runner.run();assert live.read_live_scores(tmp_path/'scores')['status']=='stopped'

def test_validated_windows_use_schema2_and_measured_evidence(monkeypatch):
    vector=tuple(float(i) for i in range(19))
    class Window:
        window_start=NOW-timedelta(seconds=60)
        window_end=NOW
        def as_vector(self,version):
            assert version==2
            return vector
    def score(window,*,feature_schema_version):
        assert feature_schema_version==2
        return SimpleNamespace(score_samples=-.6,decision_function=-.1,is_anomalous=True)
    monkeypatch.setattr(live,'_collect_on_schedule',lambda *args:None)
    monkeypatch.setattr(live,'_validate_collection_coverage',lambda *args:{'complete':True})
    monkeypatch.setattr(live,'BaselineWindowBuilder',lambda **_:SimpleNamespace(build=lambda **_:SimpleNamespace(windows=[Window()])))
    rows=live.score_batch(SimpleNamespace(score=score),SimpleNamespace(get_window=lambda **_:()),SimpleNamespace(duration_seconds=120,max_events=10000,window_seconds=60),NOW,collect=lambda:None)
    assert rows[0]['features']==dict(zip(BehavioralWindow.FEATURE_NAMES_V2,vector))
    assert rows[0]['coverage_complete'] is True


def test_changed_model_discards_batch_and_cleans_telemetry(tmp_path,monkeypatch):
    p=tmp_path/'model';p.write_bytes(b'original');digest=hashlib.sha256(p.read_bytes()).hexdigest()
    d=SimpleNamespace(metadata=SimpleNamespace(calibrated_score_threshold=-.5))
    runner=live.LiveScoringRunner(d,p,digest,tmp_path/'scores',tmp_path/'status')
    def change(*args,**kwargs):
        p.write_bytes(b'changed');return [{'flagged':True}]
    monkeypatch.setattr(live,'score_batch',change)
    with pytest.raises(RuntimeError,match='changed'):runner.run_batch()
    assert runner.windows==[]
    assert not list(tmp_path.glob('intentx-live-*'))


@pytest.mark.parametrize('elapsed,expected', [(119, 'startup'), (120, 'steady_state'), (180, 'steady_state')])
def test_collection_phase_boundary_and_flags_preserved(tmp_path, elapsed, expected):
    p = tmp_path / 'report'
    report(p, collection_started_at=(NOW-timedelta(seconds=elapsed)).isoformat(), startup_seconds=120)
    d = live.read_live_scores(p, now=NOW)
    assert d['collection_phase'] == expected
    assert d['collection_age_seconds'] == elapsed
    assert d['windows'][0]['flagged'] is True
    assert d['windows'][0]['collection_phase'] == ('startup' if elapsed < 180 else 'steady_state')
    stale = live.read_live_scores(p, now=NOW+timedelta(seconds=60))
    assert stale['status'] == 'stale'
    assert stale['collection_age_seconds'] == elapsed
    assert stale['collection_phase'] == expected


def test_legacy_report_has_unknown_phase(tmp_path):
    p = tmp_path / 'report'; report(p)
    d = live.read_live_scores(p, now=NOW)
    assert d['collection_phase'] == 'unknown' and d['collection_age_seconds'] is None
    assert d['windows'][0]['collection_phase'] == 'unknown'
    assert d['windows'][0]['flagged'] is True


@pytest.mark.parametrize('change', [
    {'collection_started_at': NOW.isoformat()},
    {'startup_seconds': 120},
    {'collection_started_at': (NOW-timedelta(seconds=120)).isoformat(), 'startup_seconds': True},
    {'collection_started_at': (NOW-timedelta(seconds=120)).isoformat(), 'startup_seconds': 119},
    {'collection_started_at': NOW.replace(tzinfo=None).isoformat(), 'startup_seconds': 120},
    {'collection_started_at': (NOW+timedelta(seconds=1)).isoformat(), 'startup_seconds': 120},
    {'collection_started_at': (NOW-timedelta(seconds=30)).isoformat(), 'startup_seconds': 120},
])
def test_invalid_collection_phase_evidence(tmp_path, change):
    p = tmp_path / 'report'; report(p, **change)
    assert live.read_live_scores(p, now=NOW)['status'] == 'unavailable'


def test_collection_start_persists_across_batches(tmp_path, monkeypatch):
    p = tmp_path / 'model'; p.write_bytes(b'original')
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    d = SimpleNamespace(metadata=SimpleNamespace(calibrated_score_threshold=-.5))
    runner = live.LiveScoringRunner(d, p, digest, tmp_path/'scores', tmp_path/'status')
    starts = []
    monkeypatch.setattr(live, 'score_batch', lambda *args, **kw: starts.append(args[3]) or [])
    runner.run_batch(); runner.run_batch()
    assert runner.collection_started_at == starts[0]
    saved = json.loads((tmp_path/'scores').read_text())
    assert datetime.fromisoformat(saved['collection_started_at']) == starts[0]
    assert saved['startup_seconds'] == 120
    assert saved['model_retrained'] is False


def test_dashboard_explains_phase_without_suppressing_flags(tmp_path):
    p = tmp_path / 'report'; report(p, collection_started_at=(NOW-timedelta(seconds=120)).isoformat(), startup_seconds=120)
    c = TestClient(create_app(live_scores_path=p))
    d = c.get('/api/v1/behavior/live').json()
    assert d['windows'][0]['flagged'] is True and d['windows'][0]['collection_phase'] == 'startup'
    page = c.get('/').text
    assert 'All flags remain visible.' in page
    assert 'Last reported collection phase:' in page
    assert 'not model readiness or workload stability' in page
