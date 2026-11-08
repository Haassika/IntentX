"""Isolated, bounded synthetic presentation fixtures. Never writes sensor files."""
from datetime import datetime, timedelta, timezone
from threading import RLock
from copy import deepcopy

def build_normal_window(start: datetime, hostname: str = "intentx-v2-cohort") -> dict:
    end = start + timedelta(seconds=60)
    features = {
        "event_count": 36.0,
        "process_event_count": 24.0,
        "unique_process_count": 13.0,
        "root_process_event_count": 0.0,
        "network_connection_count": 2.0,
        "network_listener_count": 1.0,
        "unique_remote_address_count": 1.0,
        "auth_success_count": 1.0,
        "auth_failure_count": 0.0,
        "privilege_activity_count": 0.0,
        "file_activity_count": 0.0,
        "audit_event_count": 0.0,
        "kernel_event_count": 0.0,
        "sensor_unavailable_count": 0.0,
        "sensor_error_count": 0.0,
        "mean_process_count": 2.0,
        "max_process_count": 2.0,
        "mean_cgroup_memory_used_ratio": 0.088,
        "max_cgroup_memory_used_ratio": 0.090,
    }
    # Score slightly above threshold (-0.56165)
    score = -0.4755
    margin = score - (-0.56165)
    return {
        "start_utc": start.isoformat(),
        "end_utc": end.isoformat(),
        "features": features,
        "score": score,
        "margin": margin,
        "flagged": False,
        "coverage_complete": True,
    }

def build_attack_window(start: datetime, attack_type: str, hostname: str = "intentx-v2-cohort") -> dict:
    end = start + timedelta(seconds=60)
    features = {
        "event_count": 36.0,
        "process_event_count": 24.0,
        "unique_process_count": 13.0,
        "root_process_event_count": 0.0,
        "network_connection_count": 2.0,
        "network_listener_count": 1.0,
        "unique_remote_address_count": 1.0,
        "auth_success_count": 0.0,
        "auth_failure_count": 0.0,
        "privilege_activity_count": 0.0,
        "file_activity_count": 0.0,
        "audit_event_count": 0.0,
        "kernel_event_count": 0.0,
        "sensor_unavailable_count": 0.0,
        "sensor_error_count": 0.0,
        "mean_process_count": 2.0,
        "max_process_count": 2.0,
        "mean_cgroup_memory_used_ratio": 0.088,
        "max_cgroup_memory_used_ratio": 0.090,
    }

    if attack_type == "kernel":
        # Kernel-Level Rootkit & Module Taint Intrusion
        features.update({
            "kernel_event_count": 48.0,
            "audit_event_count": 32.0,
            "privilege_activity_count": 14.0,
            "root_process_event_count": 18.0,
            "event_count": 185.0,
        })
        score = -0.7420
    elif attack_type == "process_churn":
        # Behavioral Churn / Fork Bomb / Unauthorized Cryptominer
        features.update({
            "process_event_count": 160.0,
            "unique_process_count": 78.0,
            "mean_process_count": 48.0,
            "max_process_count": 65.0,
            "mean_cgroup_memory_used_ratio": 0.68,
            "max_cgroup_memory_used_ratio": 0.89,
            "event_count": 220.0,
        })
        score = -0.7180
    elif attack_type == "network_exfil":
        # Rogue Network Listener & Data Exfiltration
        features.update({
            "network_connection_count": 42.0,
            "network_listener_count": 6.0,
            "unique_remote_address_count": 18.0,
            "event_count": 140.0,
        })
        score = -0.6850
    else:
        raise ValueError(f"Unknown attack type: {attack_type}")

    margin = score - (-0.56165)
    return {
        "start_utc": start.isoformat(),
        "end_utc": end.isoformat(),
        "features": features,
        "score": score,
        "margin": margin,
        "flagged": True,
        "coverage_complete": True,
    }

def compute_xai_and_mitigations(target_window: dict):
    from intentx.behavior.explainer import FeatureAttribution, WindowExplanation
    from intentx.behavior.mitigation import MitigationRecommender
    from intentx.telemetry.windowing import BehavioralWindow

    features = target_window["features"]
    names = BehavioralWindow.FEATURE_NAMES_V2

    baseline = build_normal_window(datetime.now(timezone.utc))["features"]
    attrs = []
    total_dev = 0.0
    z_scores = []
    for name in names:
        val = float(features.get(name, 0.0))
        z = max(0.0, val - baseline.get(name, 0.0)) / max(1.0, baseline.get(name, 0.0) * 0.1)
        z_scores.append(z)
        total_dev += z

    for idx, name in enumerate(names):
        val = float(features.get(name, 0.0))
        z = z_scores[idx]
        attr = z / total_dev if total_dev > 0 else 1.0 / len(names)
        desc = (
            f"{name.replace('_', ' ')} is elevated ({val:.2f})"
            if z > 1.0
            else f"{name.replace('_', ' ')} is normal ({val:.2f})"
        )
        attrs.append(
            FeatureAttribution(
                feature_name=name,
                observed_value=val,
                baseline_mean=baseline.get(name, 0.0),
                baseline_std=max(1.0, baseline.get(name, 0.0) * 0.1),
                deviation_zscore=z,
                attribution_score=attr,
                contribution_percentage=attr * 100.0,
                description=desc,
            )
        )

    ranked = sorted(attrs, key=lambda a: a.attribution_score, reverse=True)
    primary = tuple(ranked[:4]) if total_dev > 0 else ()
    is_anomalous = bool(target_window.get("flagged", False))
    score = float(target_window.get("score", 0.0))
    margin = float(target_window.get("margin", 0.0))

    summary = (
        f"Window flagged as ANOMALOUS (score: {score:.4f}, margin: {margin:+.4f}). Primary factors: "
        + ", ".join(f"{f.feature_name} ({f.contribution_percentage:.1f}%)" for f in primary[:3])
        if is_anomalous
        else f"Window classified as NORMAL (score: {score:.4f}, margin: {margin:+.4f}). Indicators within baseline."
    )

    explanation = WindowExplanation(
        hostname="intentx-v2-cohort",
        window_start=datetime.fromisoformat(target_window["start_utc"]),
        window_end=datetime.fromisoformat(target_window["end_utc"]),
        is_anomalous=is_anomalous,
        score=score,
        decision_margin=margin,
        summary=summary,
        primary_factors=primary,
        all_attributions=tuple(attrs),
    )

    mitigations = MitigationRecommender.recommend(explanation) if is_anomalous else []
    return explanation, mitigations

class DemoController:
    SCENARIOS = {"baseline", "process_churn", "network_exfil", "kernel", "reset"}
    def __init__(self):
        self._lock = RLock()
        self._state = {"scenario": None, "status": "idle", "provenance": "controlled_simulation", "timeline": [], "windows": [], "explanation": None, "mitigations": []}

    def snapshot(self):
        with self._lock:
            return deepcopy(self._state)

    def trigger(self, scenario):
        if scenario not in self.SCENARIOS:
            raise ValueError("Unknown predefined scenario")
        with self._lock:
            now = datetime.now(timezone.utc)
            windows = [] if scenario == "reset" else [build_normal_window(now-timedelta(seconds=120))]
            if windows:
                windows.append(build_normal_window(now-timedelta(seconds=60)) if scenario == "baseline" else build_attack_window(now-timedelta(seconds=60), scenario))
                for w in windows:
                    w["margin"] = w["score"] - (-0.5616504137954491)
                    w["flagged"] = w["margin"] < 0
                explanation, mitigations = compute_xai_and_mitigations(windows[-1])
            timeline = (self._state["timeline"] + [{"at": now.isoformat(), "scenario": scenario, "status": "completed"}])[-30:]
            self._state = {"scenario": scenario, "status": "completed", "updated_at": now.isoformat(), "provenance": "controlled_simulation", "score_method": "fixed presentation fixtures; not model inference", "explanation_method": "illustrative deviation from normal fixture; scale = max(1, 10% of baseline)", "threshold": -0.5616504137954491, "timeline": timeline, "windows": windows, "explanation": explanation.to_dict() if windows else None, "mitigations": [m.to_dict() for m in mitigations] if windows else []}
            return deepcopy(self._state)
