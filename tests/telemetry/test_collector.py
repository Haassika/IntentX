import subprocess

import pytest

from intentx.telemetry.collector import (
    LinuxTelemetryCollector,
    TelemetryCollectionError,
)
from intentx.telemetry.models import SensorCollectionStatus


def test_read_only_runner_uses_structured_argv(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs

        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="ok",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    output = LinuxTelemetryCollector._run_read_only(
        ("ps", "-ef")
    )

    assert output == "ok"
    assert captured["argv"] == ("ps", "-ef")
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["kwargs"]["timeout"] == 5


def test_required_command_failure_is_fail_closed(monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="",
            stderr="failed",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(TelemetryCollectionError):
        LinuxTelemetryCollector._run_read_only(
            ("ps", "-ef")
        )


def test_optional_command_failure_returns_empty(monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="",
            stderr="failed",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = LinuxTelemetryCollector._run_read_only(
        ("ss", "-tunap"),
        required=False,
    )

    assert result is None


def test_process_parser(monkeypatch):
    collector = LinuxTelemetryCollector()

    monkeypatch.setattr(
        collector,
        "_run_read_only",
        lambda *args, **kwargs: (
            "1 0 root 1.0 2.0 init\n"
            "25 1 intentx 60.0 3.0 worker\n"
        ),
    )

    processes = collector._read_processes()

    assert len(processes) == 2
    assert processes[0].pid == 1
    assert processes[0].user == "root"
    assert processes[1].pid == 25
    assert processes[1].cpu_percent == 60.0


def test_network_parser(monkeypatch):
    collector = LinuxTelemetryCollector()

    monkeypatch.setattr(
        collector,
        "_run_read_only",
        lambda *args, **kwargs: (
            "Netid State Recv-Q Send-Q Local Address:Port "
            "Peer Address:Port Process\n"
            "tcp ESTAB 0 0 127.0.0.1:8000 "
            "127.0.0.1:50000 users:((python,pid=10,fd=3))\n"
        ),
    )

    connections, status = collector._read_network_connections()

    assert len(connections) == 1
    assert connections[0].protocol == "tcp"
    assert connections[0].state == "ESTAB"
    assert connections[0].local_address == "127.0.0.1:8000"
    assert status.status is SensorCollectionStatus.COLLECTED



def test_network_collection_failure_is_explicit(monkeypatch):
    collector = LinuxTelemetryCollector()

    monkeypatch.setattr(
        collector,
        "_run_read_only",
        lambda *args, **kwargs: None,
    )

    connections, status = collector._read_network_connections()

    assert connections == []
    assert status.status is SensorCollectionStatus.UNAVAILABLE
    assert status.detail is not None


@pytest.mark.parametrize('membership,limit', [('0::/\n', '1073741824'), ('0::/lab\n', 'max')])
def test_cgroup_memory_uses_current_membership(monkeypatch, membership, limit):
    from pathlib import Path
    seen = []

    def read(path, **kwargs):
        seen.append(str(path))
        if str(path) == '/proc/self/cgroup':
            return membership
        if path.name == 'memory.current':
            return '268435456\n'
        if path.name == 'memory.max':
            return limit
        if path.name == 'memory.stat':
            return 'anon 123\nfile 456\nkernel 78\n'
        raise AssertionError(path)

    monkeypatch.setattr(Path, 'read_text', read)
    result = LinuxTelemetryCollector._read_cgroup_memory()
    assert result.status.status is SensorCollectionStatus.COLLECTED
    assert result.current_bytes == 268435456
    assert result.limit_bytes == (None if limit == 'max' else 1073741824)
    assert result.source_path.endswith('/lab') == ('/lab' in membership)
    assert not any('meminfo' in path for path in seen)


@pytest.mark.parametrize('membership,current,limit', [
    ('4:memory:/lab', '1', '100'),
    ('0::/../outside', '1', '100'),
    ('0::/', '-1', '100'),
    ('0::/', 'abc', '100'),
    ('0::/', '1', '0'),
    ('0::/', '1', '-1'),
])
def test_invalid_cgroup_data_is_explicitly_unavailable(monkeypatch, membership, current, limit):
    from pathlib import Path
    values = {'cgroup': membership, 'memory.current': current, 'memory.max': limit}
    monkeypatch.setattr(Path, 'read_text', lambda path, **kwargs: values[path.name])
    result = LinuxTelemetryCollector._read_cgroup_memory()
    assert result.status.status is SensorCollectionStatus.UNAVAILABLE
    assert result.current_bytes is None and result.limit_bytes is None
    assert result.status.detail


def test_unreadable_cgroup_does_not_fall_back_to_system_memory(monkeypatch):
    from pathlib import Path
    def fail(*args, **kwargs):
        raise PermissionError('denied')
    monkeypatch.setattr(Path, 'read_text', fail)
    result = LinuxTelemetryCollector._read_cgroup_memory()
    assert result.status.status is SensorCollectionStatus.UNAVAILABLE
    assert result.current_bytes is None


@pytest.mark.parametrize('stat', ['anon 1\nfile 2\nkernel 3\n', 'anon -1\nfile 2\nkernel 3\n', 'anon 1\nfile 2\n', 'anon 1\nanon 2\nfile 3\nkernel 4\n'])
def test_memory_breakdown_failure_does_not_discard_total(monkeypatch, stat):
    from pathlib import Path
    data={'cgroup':'0::/','memory.current':'100','memory.max':'1000','memory.stat':stat}
    monkeypatch.setattr(Path,'read_text',lambda path,**kwargs:data[path.name])
    result=LinuxTelemetryCollector._read_cgroup_memory()
    assert result.current_bytes==100
    assert result.status.status is SensorCollectionStatus.COLLECTED
    if stat=='anon 1\nfile 2\nkernel 3\n':
        assert (result.anon_bytes,result.file_bytes,result.kernel_bytes)==(1,2,3)
        assert result.breakdown_status.status is SensorCollectionStatus.COLLECTED
    else:
        assert result.breakdown_status.status is SensorCollectionStatus.UNAVAILABLE
        assert result.anon_bytes is None
