import json
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from intentx.api.app import create_app
from intentx.telemetry.live_status import LiveStatusMonitor, SENSORS, read_live_status
from intentx.telemetry.collector import TelemetryCollectionError
from intentx.telemetry.models import SensorStatus, SensorCollectionStatus

NOW=datetime.now(timezone.utc)
def report(path, **kw):
    data=dict(version=1,state='collecting',updated_at=NOW.isoformat(),last_success_at=NOW.isoformat(),sensors=dict.fromkeys(SENSORS,'collected'))
    data.update(kw);path.write_text(json.dumps(data))

def test_fresh_stale_stopped(tmp_path):
    p=tmp_path/'status';report(p);before=p.read_bytes()
    assert read_live_status(p,now=NOW)['status']=='collecting'
    d=read_live_status(p,now=NOW+timedelta(seconds=31))
    assert d['status']=='stale' and set(d['sensors'].values())=={'unknown'}
    assert p.read_bytes()==before
    report(p,state='stopped');assert read_live_status(p,now=NOW)['status']=='stopped'

@pytest.mark.parametrize('change',[dict(version=2),dict(state='healthy'),dict(updated_at='bad'),dict(updated_at='2026-10-03T00:00:00'),dict(updated_at=(NOW+timedelta(seconds=6)).isoformat()),dict(sensors={}),dict(last_success_at='bad')])
def test_invalid(tmp_path,change):
    p=tmp_path/'status';report(p,**change)
    assert read_live_status(p,now=NOW)['status']=='unavailable'

def test_missing_and_size(tmp_path):
    assert read_live_status(None)['status']=='not_configured'
    p=tmp_path/'status';assert read_live_status(p)['status']=='unavailable'
    p.write_text(' '*16385);assert read_live_status(p)['status']=='unavailable'

def test_monitor(tmp_path):
    class Collector:
        def collect(self):
            return SimpleNamespace(captured_at=datetime.now(timezone.utc),network_sensor=SensorStatus(SensorCollectionStatus.UNAVAILABLE),cgroup_memory=SimpleNamespace(status=SensorStatus(SensorCollectionStatus.COLLECTED)))
    p=tmp_path/'status';m=LiveStatusMonitor(p,collector=Collector());m.collect_once()
    d=read_live_status(p);assert d['status']=='collecting'
    assert d['sensors']['network']=='unavailable' and d['sensors']['audit']=='unavailable'
    success=d['last_success_at']
    class Broken:
        def collect(self):raise TelemetryCollectionError('private detail')
    m.collector=Broken();m.collect_once();d=read_live_status(p)
    assert d['status']=='error' and d['last_success_at']==success
    assert 'private' not in p.read_text()
    stop=threading.Event();stop.set();m.run(stop,5)
    assert read_live_status(p)['status']=='stopped'

def test_api_ui(tmp_path):
    p=tmp_path/'status';report(p)
    c=TestClient(create_app(telemetry_status_path=p))
    assert c.get('/api/v1/telemetry/status?path=/secret').json()['status']=='collecting'
    assert c.post('/api/v1/telemetry/status').status_code==405
    html=c.get('/').text
    assert 'Live telemetry status' in html and 'No anomaly scoring' in html
    assert 'value.textContent=status' in html
