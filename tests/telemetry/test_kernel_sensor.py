from datetime import datetime, timezone
from pathlib import Path
import pytest

from intentx.telemetry.events import SecurityEventType, TelemetrySource
from intentx.telemetry.kernel_sensor import KernelSecuritySensor, TAINT_BIT_FLAGS
from intentx.telemetry.models import (
    KernelSecurityObservation,
    ProcessObservation,
    SecuritySnapshot,
    SensorCollectionStatus,
    SensorStatus,
)
from intentx.telemetry.normalizer import TelemetryEventNormalizer


def test_kernel_sensor_clean_system(tmp_path):
    proc_sys = tmp_path / "proc" / "sys" / "kernel"
    proc_sys.mkdir(parents=True)
    (proc_sys / "tainted").write_text("0\n")
    yama = proc_sys / "yama"
    yama.mkdir()
    (yama / "ptrace_scope").write_text("1\n")
    (proc_sys / "modules_disabled").write_text("0\n")
    (proc_sys / "dmesg_restrict").write_text("1\n")

    sensor = KernelSecuritySensor(proc_sys_root=proc_sys, kmsg_path=tmp_path / "kmsg")
    obs = sensor.collect()

    assert isinstance(obs, KernelSecurityObservation)
    assert obs.tainted == 0
    assert obs.taint_flags == ()
    assert obs.ptrace_scope == 1
    assert obs.modules_disabled == 0
    assert obs.dmesg_restrict == 1
    assert obs.security_event_count == 0


def test_kernel_sensor_tainted_system_decoding(tmp_path):
    proc_sys = tmp_path / "proc" / "sys" / "kernel"
    proc_sys.mkdir(parents=True)
    # Taint: 1 (PROPRIETARY_MODULE) + 2 (FORCED_MODULE) + 4096 (OUT_OF_TREE_MODULE) = 4099
    (proc_sys / "tainted").write_text("4099\n")

    kmsg_file = tmp_path / "kmsg"
    kmsg_file.write_text("kernel: [ 10.0 ] SECCOMP: syscall 123 blocked by filter\n")

    sensor = KernelSecuritySensor(proc_sys_root=proc_sys, kmsg_path=kmsg_file)
    obs = sensor.collect()

    assert obs.tainted == 4099
    assert "PROPRIETARY_MODULE" in obs.taint_flags
    assert "FORCED_MODULE" in obs.taint_flags
    assert "OUT_OF_TREE_MODULE" in obs.taint_flags
    assert obs.security_event_count >= 2
    assert any("KERNEL_TAINT_ACTIVE" in ev for ev in obs.security_events)
    assert any("SECCOMP" in ev for ev in obs.security_events)


def test_normalizer_creates_kernel_and_audit_events():
    obs = KernelSecurityObservation(
        tainted=1,
        taint_flags=("PROPRIETARY_MODULE",),
        ptrace_scope=0,  # Unrestricted ptrace
        modules_disabled=0,
        security_event_count=1,
        security_events=("KERNEL_TAINT_ACTIVE: bitmask=1",),
        status=SensorStatus(status=SensorCollectionStatus.COLLECTED),
    )

    snapshot = SecuritySnapshot(
        captured_at=datetime.now(timezone.utc),
        hostname="testhost",
        load_1m=0.1,
        load_5m=0.1,
        load_15m=0.1,
        memory_total_kb=1000,
        memory_available_kb=800,
        process_count=1,
        processes=(),
        network_connections=(),
        kernel_security=obs,
    )

    normalizer = TelemetryEventNormalizer()
    events = normalizer.normalize_snapshot(snapshot)

    kernel_events = [e for e in events if e.event_type == SecurityEventType.KERNEL_EVENT]
    audit_events = [e for e in events if e.event_type == SecurityEventType.AUDIT_EVENT]

    assert len(kernel_events) >= 1
    assert kernel_events[0].source == TelemetrySource.KERNEL
    assert kernel_events[0].attributes["tainted"] == 1

    assert len(audit_events) >= 1
    assert audit_events[0].source == TelemetrySource.LINUX_AUDIT
    assert audit_events[0].attributes["warning"] == "ptrace_scope_unrestricted"

