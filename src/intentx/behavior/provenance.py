"""Optional recorded workload configuration; not proof of executed activity."""
from __future__ import annotations

import hashlib
import json
import os
import socket
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

PROFILE_PATH = Path('/app/runtime/behavior/workload-profile.json')


def write_workload_profile(config, path=PROFILE_PATH):
    if not hasattr(os, 'geteuid') or os.geteuid() == 0:
        raise RuntimeError('Workload profile requires a non-root user')
    payload = {'schema_version':1, 'profile':'controlled_lab_normal_behavior',
        'config':asdict(config), 'hostname':socket.gethostname(),
        'pid':os.getpid(), 'uid':os.geteuid(),
        'started_at_utc':datetime.now(timezone.utc).isoformat(),
        'note':'Recorded configuration, not proof that every scheduled activity executed'}
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(payload,indent=2)+'\n')
    temporary.replace(path)


def read_workload_profile(path=PROFILE_PATH):
    path=Path(path)
    try:
        raw=path.read_bytes()
    except FileNotFoundError:
        return {'status':'not_recorded'}
    except OSError as exc:
        return {'status':'unavailable','detail':str(exc)}
    try:
        from intentx.behavior.workload import WorkloadConfig
        payload=json.loads(raw)
        if payload['schema_version']!=1 or payload['profile']!='controlled_lab_normal_behavior':
            raise ValueError('unsupported workload profile')
        WorkloadConfig(**payload['config'])
        if payload['hostname']!=socket.gethostname():
            raise ValueError('workload profile hostname mismatch')
        stamp=datetime.fromisoformat(payload['started_at_utc'])
        if stamp.tzinfo is None:
            raise ValueError('workload profile timestamp must have timezone')
        return {'status':'recorded','sha256':hashlib.sha256(raw).hexdigest(),'record':payload,
            'note':'Profile may be stale; recorded configuration is not proof of workload execution'}
    except (ValueError,KeyError,TypeError) as exc:
        return {'status':'invalid','detail':str(exc)}
