"""Bounded, read-only projection of a configured historical validation report."""
from __future__ import annotations

import json
import math
import re
from datetime import datetime
from pathlib import Path


class ReportUnavailable(ValueError):
    pass


def read_validation_summary(path):
    if path is None:
        return {'status':'not_configured','historical':True,'experimental':True}
    try:
        with Path(path).open('rb') as handle:
            raw=handle.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:
            raise ValueError('report too large')
        m=json.loads(raw)
        if m['experiment_type']!='multisession_v2_benign_validation' or m['feature_schema_version']!=2:
            raise ValueError('unsupported report')
        if m['threshold_chosen_without_evaluation'] is not True:
            raise ValueError('threshold independence not established')
        def number(value):
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value):
                raise ValueError('invalid numeric report field')
            return value
        def count(value):
            if type(value) is not int or value<0:raise ValueError('invalid count')
            return value
        total=count(m['window_count']);flags=count(m['flagged_windows'])
        if not 1<=total<=1000 or flags>total or len(m['windows'])!=total:
            raise ValueError('inconsistent window counts')
        cutoff=number(m['calibrated_score_threshold'])
        if not math.isclose(number(m['benign_flag_rate']),flags/total,abs_tol=1e-9):
            raise ValueError('inconsistent flag rate')
        metadata=m['model_metadata']
        if metadata['feature_schema_version']!=2 or metadata['model_format_version']!=2:
            raise ValueError('inconsistent model version')
        if not math.isclose(number(metadata['calibrated_score_threshold']),cutoff,abs_tol=1e-12):
            raise ValueError('inconsistent threshold')
        training=count(m['training_windows']);calibration=count(m['calibration_windows'])
        if training<2 or calibration<1:raise ValueError('insufficient report counts')
        declared=m.get('declared_lab_hostnames')
        if declared is not None:
            if (not isinstance(declared,list) or not declared or any(not isinstance(h,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',h) for h in declared)
                    or len(set(declared))!=len(declared) or set(declared)!=set(metadata['training_hostnames'])):
                raise ValueError('invalid declared hosts')
        windows=[];previous_ends={};previous_start=None
        for w in m['windows']:
            start=datetime.fromisoformat(w['window_start']);end=datetime.fromisoformat(w['window_end'])
            if start.tzinfo is None or end.tzinfo is None or end<=start:
                raise ValueError('invalid window timestamp')
            hostname=w.get('hostname','')
            if not isinstance(hostname,str) or (hostname and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',hostname)):
                raise ValueError('invalid window host')
            if declared is not None and hostname not in declared:raise ValueError('undeclared window host')
            key=hostname if declared is not None else 'single_host'
            if key in previous_ends and start<previous_ends[key]:raise ValueError('overlapping windows')
            if previous_start is not None and start<previous_start:raise ValueError('nonchronological windows')
            previous_ends[key]=end;previous_start=start
            score=number(w['score_samples']);margin=number(w['decision_function'])
            if not math.isclose(margin,score-cutoff,abs_tol=1e-9):raise ValueError('inconsistent score margin')
            if type(w['is_anomalous']) is not bool or w['is_anomalous']!=(score<cutoff):
                raise ValueError('inconsistent flag')
            windows.append({'hostname':hostname,'start_utc':start.isoformat(),'end_utc':end.isoformat(),
                'score':score,'margin':margin,'flagged':w['is_anomalous']})
        if sum(w['flagged'] for w in windows)!=flags:raise ValueError('inconsistent flag count')
        digest=m['model_sha256']
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid model fingerprint')
        return {'status':'available','historical':True,'experimental':True,
            'training_windows':training,'calibration_windows':calibration,
            'evaluation_windows':total,'flagged_windows':flags,'benign_flag_rate':flags/total,
            'feature_schema_version':2,'model_format_version':2,'threshold':cutoff,
            'model_sha256':digest,'collection_status':'Coverage checked by saved validation workflow',
            'sensor_status':'Live sensor status is not available in this historical report',
            'calibration_flag_rate':number(m['observed_calibration_flag_rate']),
            'target_calibration_flag_rate':number(m['target_calibration_flag_rate']),
            'windows':windows}
    except (OSError,ValueError,KeyError,TypeError,OverflowError) as exc:
        raise ReportUnavailable('Saved behavioral report is unavailable or invalid') from exc
