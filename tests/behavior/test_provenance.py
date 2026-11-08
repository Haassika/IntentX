import json
import os
from pathlib import Path

import pytest

from intentx.behavior.provenance import read_workload_profile, write_workload_profile
from intentx.behavior.workload import WorkloadConfig


def test_profile_records_config_and_hash(tmp_path):
    p=tmp_path/'workload-profile.json'
    write_workload_profile(WorkloadConfig(seed=47),p)
    result=read_workload_profile(p)
    assert result['status']=='recorded'
    assert result['record']['config']['seed']==47
    assert len(result['sha256'])==64
    assert 'not proof' in result['note']


def test_absent_profile_is_not_fabricated(tmp_path):
    assert read_workload_profile(tmp_path/'missing')['status']=='not_recorded'


def test_invalid_profile_is_explicit(tmp_path):
    p=tmp_path/'profile';p.write_text('{}')
    assert read_workload_profile(p)['status']=='invalid'


def test_other_host_profile_rejected(tmp_path):
    p=tmp_path/'profile';write_workload_profile(WorkloadConfig(),p)
    m=json.loads(p.read_text());m['hostname']='unrelated-host';p.write_text(json.dumps(m))
    assert read_workload_profile(p)['status']=='invalid'


def test_root_cannot_write_profile(tmp_path,monkeypatch):
    monkeypatch.setattr(os,'geteuid',lambda:0)
    with pytest.raises(RuntimeError,match='non-root'):
        write_workload_profile(WorkloadConfig(),tmp_path/'profile')
    assert not (tmp_path/'profile').exists()
