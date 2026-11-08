import os
import socket
import threading

import pytest

from intentx.behavior import workload


@pytest.mark.parametrize("field,value", [
    ("duration_seconds", float("nan")), ("duration_seconds", float("inf")),
    ("duration_seconds", 0), ("interval_seconds", 61),
    ("max_children", 4), ("max_children", True),
    ("file_bytes", 1048577), ("cpu_iterations", -1), ("seed", -1),
])
def test_limits(field, value):
    with pytest.raises(ValueError):
        workload.WorkloadConfig(**{field: value})


def test_rejects_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="non-root"):
        workload.run_workload(workload.WorkloadConfig(duration_seconds=.1))


def test_real_activity_and_cleanup(monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("Integration workload requires non-root")
    children, directories, addresses = [], [], []
    original_popen = workload.subprocess.Popen
    original_temporary = workload.tempfile.TemporaryDirectory
    original_socket = socket.socket

    def spawn(args, **kwargs):
        assert args == [workload.sys.executable, "-I", "-c", "import time; time.sleep(60)"]
        assert "shell" not in kwargs
        child = original_popen(args, **kwargs)
        children.append(child)
        return child

    def temporary(**kwargs):
        directory = original_temporary(**kwargs)
        directories.append(workload.Path(directory.name))
        return directory

    class CheckedSocket(original_socket):
        def bind(self, address):
            assert address == ("127.0.0.1", 0)
            addresses.append(address)
            return super().bind(address)

        def connect(self, address):
            assert address[0] == "127.0.0.1"
            return super().connect(address)

    monkeypatch.setattr(workload.subprocess, "Popen", spawn)
    monkeypatch.setattr(workload.tempfile, "TemporaryDirectory", temporary)
    monkeypatch.setattr(workload.socket, "socket", CheckedSocket)
    config = workload.WorkloadConfig(duration_seconds=.1, interval_seconds=.1)
    first = workload.run_workload(config)
    second = workload.run_workload(config)
    assert first == second
    assert first["cycles"] == 1
    assert first["children"] == first["connections"] > 0
    assert first["bytes_written"] > 0
    assert addresses
    assert all(child.poll() is not None for child in children)
    assert all(not directory.exists() for directory in directories)


def test_failure_reaps_children(monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("Integration workload requires non-root")
    children = []
    original = workload.subprocess.Popen

    def spawn(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    def fail(*args, **kwargs):
        raise OSError("injected write failure")

    monkeypatch.setattr(workload.subprocess, "Popen", spawn)
    monkeypatch.setattr(workload.Path, "write_bytes", fail)
    with pytest.raises(OSError, match="injected"):
        workload.run_workload(workload.WorkloadConfig(duration_seconds=.1))
    assert children and all(child.poll() is not None for child in children)


def test_stop_before_start():
    if os.geteuid() == 0:
        pytest.skip("Integration workload requires non-root")
    stop = threading.Event()
    stop.set()
    assert workload.run_workload(workload.WorkloadConfig(), stop)["cycles"] == 0


def test_stop_during_cycle_cleans_up(monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("Integration workload requires non-root")
    stop = threading.Event()
    children = []
    directories = []
    original_spawn = workload.subprocess.Popen
    original_write = workload.Path.write_bytes

    def spawn(*args, **kwargs):
        child = original_spawn(*args, **kwargs)
        children.append(child)
        return child

    def write(path, payload):
        directories.append(path.parent)
        result = original_write(path, payload)
        stop.set()
        return result

    monkeypatch.setattr(workload.subprocess, "Popen", spawn)
    monkeypatch.setattr(workload.Path, "write_bytes", write)
    result = workload.run_workload(workload.WorkloadConfig(), stop)
    assert result["cycles"] == 1
    assert children and all(child.poll() is not None for child in children)
    assert directories and all(not path.exists() for path in directories)
