"""The presentation controller cannot execute commands or overwrite sensor evidence."""
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from intentx.api.app import create_app
from intentx.application.service import ApplicationResult
from intentx.behavior.demo import DemoController

class NoExecutionService:
    def handle(self, request):
        raise AssertionError('Scenario controls must never invoke application execution')

def client():
    return TestClient(create_app(application_service=NoExecutionService()))

def test_predefined_scenarios_are_isolated_and_reset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sensor = tmp_path / 'runtime/live-scores.json'
    sensor.parent.mkdir()
    sensor.write_text('real-evidence-sentinel')
    c = client()
    for scenario in ('baseline', 'process_churn', 'network_exfil', 'kernel'):
        r = c.post('/api/v1/demo/trigger', params={'scenario': scenario}, headers={'X-IntentX-Demo':'1'})
        assert r.status_code == 200
        d = r.json()
        assert d['provenance'] == 'controlled_simulation'
        assert d['windows'][-1]['flagged'] == (scenario != 'baseline')
        assert bool(d['mitigations']) == (scenario != 'baseline')
        assert c.get('/api/v1/demo/status').json() == d
    assert sensor.read_text() == 'real-evidence-sentinel'
    reset = c.post('/api/v1/demo/trigger?scenario=reset', headers={'X-IntentX-Demo':'1'}).json()
    assert reset['windows'] == [] and reset['explanation'] is None and reset['mitigations'] == []
    assert len(reset['timeline']) == 5

def test_rejects_arbitrary_commands_and_cross_origin_forms():
    c = client()
    for scenario in ('rm -rf /', 'kernel;id', '../reset', ''):
        assert c.post('/api/v1/demo/trigger', params={'scenario':scenario}, headers={'X-IntentX-Demo':'1'}).status_code == 400
    assert c.post('/api/v1/demo/trigger?scenario=kernel').status_code == 403
    assert c.post('/api/v1/demo/trigger?scenario=kernel&command=id', headers={'X-IntentX-Demo':'1'}).status_code == 400
    assert c.post('/api/v1/demo/trigger?scenario=kernel', json={'command':'id'}, headers={'X-IntentX-Demo':'1'}).status_code == 400
    assert c.get('/api/v1/demo/status').json()['status'] == 'idle'

def test_state_is_bounded_atomic_and_snapshots_are_independent():
    d = DemoController()
    with ThreadPoolExecutor(max_workers=4) as pool:
        states = list(pool.map(d.trigger, ['kernel', 'reset', 'baseline', 'network_exfil']*10))
    assert len(d.snapshot()['timeline']) == 30
    for state in states:
        assert (not state['windows']) == (state['scenario'] == 'reset')
    state=d.snapshot();state['timeline'].clear()
    assert len(d.snapshot()['timeline']) == 30


def test_attributions_compare_against_normal_fixture():
    d = DemoController()
    network = d.trigger("network_exfil")
    factors = {f["feature_name"]:f for f in network["explanation"]["all_attributions"]}
    assert factors["process_event_count"]["deviation_zscore"] == 0
    assert factors["network_connection_count"]["deviation_zscore"] > 0
    assert not any(m["category"] == "process" for m in network["mitigations"])
