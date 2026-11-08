"""Read-only collection monitor and bounded dashboard status projection."""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from intentx.telemetry.collector import LinuxTelemetryCollector, TelemetryCollectionError

SENSORS = ('resource', 'process', 'network', 'cgroup_memory', 'authentication', 'audit', 'kernel')


def read_live_status(path, *, now=None):
    if not path:
        return {'status': 'not_configured', 'sensors': {}}
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError('oversized')
        data = json.loads(raw)
        if data['version'] != 1 or data['state'] not in ('collecting', 'error', 'stopped'):
            raise ValueError('invalid status')
        stamp = datetime.fromisoformat(data['updated_at'])
        now = now or datetime.now(timezone.utc)
        if stamp.tzinfo is None:
            raise ValueError('naive timestamp')
        age = (now - stamp).total_seconds()
        if age < -5:
            raise ValueError('future timestamp')
        sensors = data['sensors']
        if set(sensors) != set(SENSORS) or any(v not in ('collected', 'unavailable', 'unknown') for v in sensors.values()):
            raise ValueError('invalid sensors')
        success = data.get('last_success_at')
        if success is not None:
            parsed = datetime.fromisoformat(success)
            if parsed.tzinfo is None or parsed > stamp:
                raise ValueError('invalid success time')
            success = parsed.isoformat()
        stale = age > 30
        return {'status': 'stale' if stale else data['state'],
                'updated_at': stamp.isoformat(), 'last_success_at': success,
                'age_seconds': max(0, round(age, 1)),
                'sensors': {k: 'unknown' if stale or data['state'] != 'collecting' else sensors[k] for k in SENSORS}}
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        return {'status': 'unavailable', 'sensors': {}}


class LiveStatusMonitor:
    def __init__(self, path, *, collector=None):
        self.path = Path(path)
        self.collector = collector or LinuxTelemetryCollector()
        self.last_success = None

    def publish(self, state, sensors):
        data = {'version': 1, 'state': state,
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'last_success_at': self.last_success, 'sensors': sensors}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + '.tmp')
        temporary.write_text(json.dumps(data), encoding='utf-8')
        temporary.replace(self.path)

    def collect_once(self):
        sensors = dict.fromkeys(SENSORS, 'unavailable')
        try:
            snapshot = self.collector.collect()
            self.last_success = snapshot.captured_at.isoformat()
            sensors.update(resource='collected', process='collected',
                           network=snapshot.network_sensor.status.value,
                           cgroup_memory=snapshot.cgroup_memory.status.status.value)
            self.publish('collecting', sensors)
        except TelemetryCollectionError:
            self.publish('error', dict.fromkeys(SENSORS, 'unknown'))

    def run(self, stop, interval):
        try:
            while not stop.is_set():
                self.collect_once()
                stop.wait(interval)
        finally:
            self.publish('stopped', dict.fromkeys(SENSORS, 'unknown'))


def main():
    parser = argparse.ArgumentParser(description='Publish observational Linux telemetry status; no anomaly scoring or execution.')
    parser.add_argument('--status-path', default='/app/runtime/telemetry/live-status.json')
    parser.add_argument('--interval-seconds', type=float, default=5)
    args = parser.parse_args()
    if not math.isfinite(args.interval_seconds) or not 1 <= args.interval_seconds <= 10:
        parser.error('interval must be between 1 and 10 seconds')
    if sys.platform != 'linux' or os.geteuid() == 0:
        parser.error('run inside Linux as a non-root user')
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    LiveStatusMonitor(args.status_path).run(stop, args.interval_seconds)


if __name__ == '__main__':
    main()
