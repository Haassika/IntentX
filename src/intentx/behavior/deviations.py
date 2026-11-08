"""Fixed, bounded lab workload deviations; no attack or shell execution."""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROFILES = ('control', 'process_churn', 'loopback_burst')


def run_deviation(profile, duration_seconds=120, stop=None):
    if profile not in PROFILES:
        raise ValueError('Unknown fixed lab profile')
    if type(duration_seconds) not in (int, float) or not math.isfinite(duration_seconds) or not .1 <= duration_seconds <= 300:
        raise ValueError('Duration must be finite and between 0.1 and 300 seconds')
    if not hasattr(os, 'geteuid') or os.geteuid() == 0:
        raise RuntimeError('Lab deviations require a non-root POSIX user')
    stop = stop if stop is not None else threading.Event()
    counts = {'cycles': 0, 'children': 0, 'connections': 0, 'first_activity_at': None}
    deadline = time.monotonic() + duration_seconds
    with tempfile.TemporaryDirectory(prefix='intentx-deviation-', dir='/tmp') as directory, ExitStack() as outer:
        listener = None
        if profile == 'loopback_burst' and not stop.is_set():
            listener = outer.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.bind(('127.0.0.1', 0))
            listener.listen(16)
            listener.settimeout(1)
        while not stop.is_set() and time.monotonic() < deadline:
            cycle_end = min(deadline, time.monotonic() + 10)
            children = []
            try:
                with ExitStack() as sockets:
                    for _ in range(8 if profile == 'process_churn' else 16 if profile == 'loopback_burst' else 0):
                        if stop.is_set() or time.monotonic() >= cycle_end:
                            break
                        if profile == 'process_churn':
                            children.append(subprocess.Popen(
                                [sys.executable, '-I', '-c', 'import time; time.sleep(60)'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, close_fds=True, cwd=directory))
                            counts['children'] += 1
                        else:
                            client = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                            client.settimeout(1)
                            client.connect(listener.getsockname())
                            server, _ = listener.accept()
                            sockets.enter_context(server)
                            counts['connections'] += 1
                        if counts['first_activity_at'] is None:
                            counts['first_activity_at'] = datetime.now(timezone.utc).isoformat()
                    counts['cycles'] += 1
                    stop.wait(max(0, cycle_end - time.monotonic()))
            finally:
                for child in children:
                    if child.poll() is None:
                        child.terminate()
                for child in children:
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() == 0:
        parser.error('Run in hardened Linux as a non-root user')
    from intentx.behavior.experiment import _write_manifest_atomic
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    marker = Path('/app/runtime/cohort-session/collection-start.json')
    report = Path('/app/runtime/deviation-profile.json')
    deadline = time.monotonic() + 180
    while not marker.exists():
        if stop.wait(.1) or time.monotonic() > deadline:
            raise RuntimeError('No collection-start marker within bounded wait')
    data = json.loads(marker.read_text())
    collection_start = datetime.fromisoformat(data['start_utc'])
    if collection_start.tzinfo is None:
        raise ValueError('Collection start requires timezone')
    scheduled_start = collection_start + timedelta(seconds=120)
    if stop.wait(max(0, (scheduled_start-datetime.now(timezone.utc)).total_seconds())):
        return
    actual_start = datetime.now(timezone.utc)
    lateness = (actual_start-scheduled_start).total_seconds()
    if not 0 <= lateness <= 2.5:
        raise RuntimeError('Deviation activation outside declared timing bound')
    record = {'profile': args.profile, 'kind': 'controlled_lab_deviation' if args.profile != 'control' else 'benign_control',
              'scheduled_start_utc': scheduled_start.isoformat(), 'actual_start_utc': actual_start.isoformat(),
              'planned_duration_seconds': 120, 'uid': os.geteuid(), 'status': 'active'}
    _write_manifest_atomic(report, record)
    try:
        counts = run_deviation(args.profile, 120, stop)
        record.update(counts=counts, actual_end_utc=datetime.now(timezone.utc).isoformat(), status='interrupted' if stop.is_set() else 'complete')
        _write_manifest_atomic(report, record)
    except BaseException:
        record.update(status='failed', actual_end_utc=datetime.now(timezone.utc).isoformat())
        _write_manifest_atomic(report, record)
        raise
    # Keep one controller process present in every arm through recovery collection.
    stop.wait(max(0, (collection_start+timedelta(seconds=365)-datetime.now(timezone.utc)).total_seconds()))
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
