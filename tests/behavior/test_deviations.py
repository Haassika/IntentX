import json
import math
import os
import signal
import socket
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from intentx.behavior import deviations
from intentx.behavior.experiment import _write_manifest_atomic


def test_rejects_unknown_profile():
    with pytest.raises(ValueError, match="Unknown fixed lab profile"):
        deviations.run_deviation("unsupported_deviation")


@pytest.mark.parametrize("invalid_duration", [
    float("nan"),
    float("inf"),
    -1.0,
    0,
    0.05,
    300.1,
    500,
    "120",
    None,
])
def test_rejects_invalid_duration(invalid_duration):
    with pytest.raises(ValueError, match="Duration must be finite"):
        deviations.run_deviation("control", duration_seconds=invalid_duration)


def test_rejects_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="non-root POSIX user"):
        deviations.run_deviation("control", duration_seconds=0.1)


def test_rejects_missing_geteuid(monkeypatch):
    monkeypatch.delattr(os, "geteuid", raising=False)
    with pytest.raises(RuntimeError, match="non-root POSIX user"):
        deviations.run_deviation("control", duration_seconds=0.1)


def test_control_profile_generates_no_children_or_sockets(monkeypatch):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("Test requires a non-root POSIX user")

    stop = threading.Event()
    counts = deviations.run_deviation("control", duration_seconds=0.1, stop=stop)

    assert counts["cycles"] >= 1
    assert counts["children"] == 0
    assert counts["connections"] == 0
    assert counts["first_activity_at"] is None


def test_process_churn_activity_and_cleanup(monkeypatch):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("Test requires a non-root POSIX user")

    children = []
    original_popen = subprocess.Popen

    def tracked_popen(args, **kwargs):
        assert args == [sys.executable, "-I", "-c", "import time; time.sleep(60)"]
        assert "shell" not in kwargs or not kwargs["shell"]
        child = original_popen(args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(deviations.subprocess, "Popen", tracked_popen)

    counts = deviations.run_deviation("process_churn", duration_seconds=0.1)

    assert counts["cycles"] >= 1
    assert counts["children"] > 0
    assert counts["connections"] == 0
    assert counts["first_activity_at"] is not None
    # All spawned subprocesses must be terminated and reaped
    assert len(children) > 0
    assert all(child.poll() is not None for child in children)


def test_loopback_burst_activity_and_cleanup(monkeypatch):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("Test requires a non-root POSIX user")

    counts = deviations.run_deviation("loopback_burst", duration_seconds=0.1)

    assert counts["cycles"] >= 1
    assert counts["children"] == 0
    assert counts["connections"] > 0
    assert counts["first_activity_at"] is not None


def test_stop_event_terminates_immediately(monkeypatch):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("Test requires a non-root POSIX user")

    stop = threading.Event()
    stop.set()

    counts = deviations.run_deviation("control", duration_seconds=10, stop=stop)
    assert counts["cycles"] == 0
    assert counts["children"] == 0
    assert counts["connections"] == 0


def test_failure_cleans_up_children(monkeypatch):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("Test requires a non-root POSIX user")

    children = []
    original_popen = subprocess.Popen

    def tracked_popen(args, **kwargs):
        child = original_popen(args, **kwargs)
        children.append(child)
        return child

    def failing_wait(self, timeout=None):
        raise RuntimeError("Injected failure during cycle")

    monkeypatch.setattr(deviations.subprocess, "Popen", tracked_popen)
    monkeypatch.setattr(threading.Event, "wait", failing_wait)

    with pytest.raises(RuntimeError, match="Injected failure during cycle"):
        deviations.run_deviation("process_churn", duration_seconds=5)

    assert len(children) > 0
    assert all(child.poll() is not None for child in children)


def test_main_rejects_non_linux(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(SystemExit):
        deviations.main()


def test_main_rejects_root(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit):
        deviations.main()


def test_main_rejects_missing_profile(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["deviations"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit):
        deviations.main()


def test_main_flow(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    # Setup directories and marker
    session_dir = tmp_path / "cohort-session"
    session_dir.mkdir(parents=True)
    marker = session_dir / "collection-start.json"
    report = tmp_path / "deviation-profile.json"

    now = datetime.now(timezone.utc)
    # Start was 120s ago so scheduled_start is now
    marker_data = {"start_utc": (now - timedelta(seconds=120)).isoformat()}
    marker.write_text(json.dumps(marker_data))

    monkeypatch.setattr(deviations, "Path", lambda p: marker if "collection-start" in str(p) else report)

    # Mock run_deviation to return quickly
    monkeypatch.setattr(deviations, "run_deviation", lambda profile, duration, stop: {"cycles": 1, "children": 0, "connections": 0, "first_activity_at": None})

    # Event.wait returns False on timeout (stop not set)
    monkeypatch.setattr(threading.Event, "wait", lambda self, timeout=None: False)

    deviations.main()

    assert report.exists()
    saved = json.loads(report.read_text())
    assert saved["profile"] == "control"
    assert saved["kind"] == "benign_control"
    assert saved["status"] == "complete"
    assert saved["counts"]["cycles"] == 1


def test_main_rejects_naive_marker_timestamp(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    session_dir = tmp_path / "cohort-session"
    session_dir.mkdir(parents=True)
    marker = session_dir / "collection-start.json"
    report = tmp_path / "deviation-profile.json"

    # Naive timestamp (no tz)
    marker.write_text(json.dumps({"start_utc": "2026-10-03T12:00:00"}))

    monkeypatch.setattr(deviations, "Path", lambda p: marker if "collection-start" in str(p) else report)

    with pytest.raises(ValueError, match="Collection start requires timezone"):
        deviations.main()


def test_main_rejects_excessive_lateness(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    session_dir = tmp_path / "cohort-session"
    session_dir.mkdir(parents=True)
    marker = session_dir / "collection-start.json"
    report = tmp_path / "deviation-profile.json"

    # Start was 200s ago, so scheduled_start was 80s ago (> 2.5s lateness)
    past = datetime.now(timezone.utc) - timedelta(seconds=200)
    marker.write_text(json.dumps({"start_utc": past.isoformat()}))

    monkeypatch.setattr(deviations, "Path", lambda p: marker if "collection-start" in str(p) else report)

    with pytest.raises(RuntimeError, match="Deviation activation outside declared timing bound"):
        deviations.main()


def test_process_churn_timeout_kills_children(monkeypatch):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("Test requires a non-root POSIX user")

    killed = []
    original_popen = subprocess.Popen

    class HangingChild:
        def __init__(self, real_child):
            self._real = real_child
            self._wait_called = False

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            if timeout is not None and not self._wait_called:
                self._wait_called = True
                raise subprocess.TimeoutExpired(cmd="sleep", timeout=timeout)
            return 0

        def kill(self):
            killed.append(self)
            self._real.kill()

    def hanging_popen(args, **kwargs):
        real_child = original_popen(args, **kwargs)
        return HangingChild(real_child)

    monkeypatch.setattr(deviations.subprocess, "Popen", hanging_popen)

    counts = deviations.run_deviation("process_churn", duration_seconds=0.1)
    assert len(killed) > 0


def test_main_failure_updates_status_to_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    session_dir = tmp_path / "cohort-session"
    session_dir.mkdir(parents=True)
    marker = session_dir / "collection-start.json"
    report = tmp_path / "deviation-profile.json"

    now = datetime.now(timezone.utc)
    marker_data = {"start_utc": (now - timedelta(seconds=120)).isoformat()}
    marker.write_text(json.dumps(marker_data))

    monkeypatch.setattr(deviations, "Path", lambda p: marker if "collection-start" in str(p) else report)

    def failing_run(*args, **kwargs):
        raise RuntimeError("Deviation failed unexpectedly")

    monkeypatch.setattr(deviations, "run_deviation", failing_run)
    monkeypatch.setattr(threading.Event, "wait", lambda self, timeout=None: False)

    with pytest.raises(RuntimeError, match="Deviation failed unexpectedly"):
        deviations.main()

    assert report.exists()
    saved = json.loads(report.read_text())
    assert saved["status"] == "failed"


def test_main_interrupted_updates_status_to_interrupted(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    session_dir = tmp_path / "cohort-session"
    session_dir.mkdir(parents=True)
    marker = session_dir / "collection-start.json"
    report = tmp_path / "deviation-profile.json"

    now = datetime.now(timezone.utc)
    marker_data = {"start_utc": (now - timedelta(seconds=120)).isoformat()}
    marker.write_text(json.dumps(marker_data))

    monkeypatch.setattr(deviations, "Path", lambda p: marker if "collection-start" in str(p) else report)

    def interrupting_run(profile, duration, stop):
        stop.set()
        return {"cycles": 1, "children": 0, "connections": 0, "first_activity_at": None}

    monkeypatch.setattr(deviations, "run_deviation", interrupting_run)
    monkeypatch.setattr(threading.Event, "wait", lambda self, timeout=None: False)

    deviations.main()

    assert report.exists()
    saved = json.loads(report.read_text())
    assert saved["status"] == "interrupted"


def test_main_marker_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["deviations", "--profile", "control"])
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    nonexistent_marker = tmp_path / "cohort-session" / "collection-start.json"
    report = tmp_path / "deviation-profile.json"

    monkeypatch.setattr(deviations, "Path", lambda p: nonexistent_marker if "collection-start" in str(p) else report)

    # First call: deadline = 0.0 + 180 = 180.0. Second call: monotonic() = 500.0 > 180.0
    clock = [0.0]

    def advancing_time():
        current = clock[0]
        clock[0] += 500.0
        return current

    monkeypatch.setattr(deviations.time, "monotonic", advancing_time)

    with pytest.raises(RuntimeError, match="No collection-start marker within bounded wait"):
        deviations.main()

