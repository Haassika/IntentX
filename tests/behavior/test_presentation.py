import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from intentx.api.app import create_app
from intentx.behavior.presentation import read_validation_summary, ReportUnavailable


def report():
    return {'experiment_type':'multisession_v2_benign_validation','feature_schema_version':2,
        'threshold_chosen_without_evaluation':True,'window_count':1,'flagged_windows':1,
        'benign_flag_rate':1.,'calibrated_score_threshold':-.5,'training_windows':30,'calibration_windows':20,
        'observed_calibration_flag_rate':.05,'target_calibration_flag_rate':.05,'model_sha256':'a'*64,
        'model_metadata':{'feature_schema_version':2,'model_format_version':2,'calibrated_score_threshold':-.5},
        'sessions':[{'manifest':'/private/source/path'}],
        'windows':[{'window_start':'2026-10-03T00:00:00+00:00','window_end':'2026-10-03T00:01:00+00:00',
            'score_samples':-.6,'decision_function':-.1,'is_anomalous':True}]}


def test_bounded_read_only_projection_hides_source_paths(tmp_path):
    p=tmp_path/'report.json';p.write_text(json.dumps(report()))
    before=p.read_bytes()
    result=read_validation_summary(p)
    assert result['status']=='available'
    assert result['historical'] and result['experimental']
    assert result['flagged_windows']==1
    assert 'sessions' not in result and 'manifest' not in json.dumps(result)
    assert p.read_bytes()==before


@pytest.mark.parametrize('key,value',[('flagged_windows',0),('benign_flag_rate',.5),('feature_schema_version',1),('threshold_chosen_without_evaluation',False),('calibrated_score_threshold',float('nan'))])
def test_invalid_report_rejected(tmp_path,key,value):
    m=report();m[key]=value;p=tmp_path/'report';p.write_text(json.dumps(m))
    with pytest.raises(ReportUnavailable):read_validation_summary(p)


def test_missing_report_is_unknown_not_healthy(tmp_path):
    assert read_validation_summary(None)['status']=='not_configured'
    with pytest.raises(ReportUnavailable):read_validation_summary(tmp_path/'absent')


def test_oversized_report_rejected(tmp_path):
    p=tmp_path/'report';p.write_bytes(b' '*(2*1024*1024+1))
    with pytest.raises(ReportUnavailable):read_validation_summary(p)


def test_api_uses_configured_file_and_accepts_no_client_path(tmp_path):
    p=tmp_path/'report';p.write_text(json.dumps(report()))
    app=create_app(application_service=object(),behavior_report_path=p)
    client=TestClient(app)
    response=client.get('/api/v1/behavior/results?path=/etc/passwd')
    assert response.status_code==200
    assert response.json()['flagged_windows']==1
    assert client.post('/api/v1/behavior/results').status_code==405
    p.write_text('broken')
    response=client.get('/api/v1/behavior/results')
    assert response.status_code==503
    assert str(p) not in response.text


def test_dashboard_has_historical_behavior_panel_and_safe_rendering():
    from intentx.ui.dashboard import DASHBOARD_HTML
    assert 'id="behavior-panel"' in DASHBOARD_HTML
    assert 'Historical lab results' in DASHBOARD_HTML
    assert 'fetch("/api/v1/behavior/results"' in DASHBOARD_HTML
    assert 'td.textContent=value' in DASHBOARD_HTML


def test_multi_host_projection_rejects_undeclared_and_same_host_overlap(tmp_path):
    m=report();m['declared_lab_hostnames']=['lab-a','lab-b'];m['model_metadata']['training_hostnames']=['lab-a','lab-b']
    m['windows'][0]['hostname']='unseen';p=tmp_path/'report';p.write_text(json.dumps(m))
    with pytest.raises(ReportUnavailable):read_validation_summary(p)
    m['windows'][0]['hostname']='lab-a';m['windows'].append(dict(m['windows'][0]));m['window_count']=2;m['flagged_windows']=2
    p.write_text(json.dumps(m))
    with pytest.raises(ReportUnavailable):read_validation_summary(p)
