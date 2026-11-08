from intentx.ui.metric_guide import FEATURE_HELP, GUIDE_HTML
from intentx.telemetry.windowing import BehavioralWindow
from intentx.ui.dashboard import DASHBOARD_HTML


def test_every_observed_feature_has_an_interpretation():
    assert set(FEATURE_HELP)==set(BehavioralWindow.FEATURE_NAMES_V2)
    assert 'not host RAM' in FEATURE_HELP['mean_cgroup_memory_used_ratio']
    assert 'coverage limitation' in FEATURE_HELP['sensor_unavailable_count']


def test_metrics_guide_covers_distinct_evidence_and_decisions():
    for text in ('Neither is a probability','not SHAP','older than 30 seconds','historical','Confidence','120-second batch'):
        assert text in GUIDE_HTML
    assert 'id="metric-guide"' in DASHBOARD_HTML
    assert 'const metricFeatureHelp' in DASHBOARD_HTML
    assert 'Latest completed window ended' in DASHBOARD_HTML


def test_live_explanation_discloses_method_and_preserves_window_times(tmp_path, monkeypatch):
    import json
    from datetime import datetime, timedelta, timezone
    from fastapi.testclient import TestClient
    from intentx.api.app import create_app
    from intentx.behavior.demo import build_attack_window
    now=datetime.now(timezone.utc)
    window=build_attack_window(now-timedelta(seconds=60),'process_churn')
    threshold=-0.5616504137954491
    window['margin']=window['score']-threshold
    payload=dict(version=1,state='collecting',updated_at=now.isoformat(),model_retrained=False,feature_schema_version=2,threshold=threshold,model_sha256='a'*64,windows=[window])
    path=tmp_path/'live.json';path.write_text(json.dumps(payload))
    c=TestClient(create_app(application_service=object(),live_scores_path=path))
    model_based=c.get('/api/v1/behavior/explain').json()
    assert model_based['explanation_method']=='model_path_and_reference_distance'
    assert 'estimated from model tree splits' in model_based['reference_notice']
    assert model_based['explanation']['window_start']==window['start_utc']
    assert model_based['explanation']['window_end']==window['end_utc']
    monkeypatch.chdir(tmp_path)
    fallback=c.get('/api/v1/behavior/explain').json()
    assert fallback['explanation_method']=='illustrative_fallback'
    assert 'assumes reference mean and scale of 1' in fallback['reference_notice']
    assert fallback['explanation']['window_start']==window['start_utc']
