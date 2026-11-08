#!/usr/bin/env python3
"""
Interactive Demonstration Script for Academic Evaluation:
AI-Powered Explainable Linux Security Assistant for Kernel-Level Intrusion & Behavioral Threat Detection

Usage:
    python scripts/demo_intrusion_scenario.py                     # Guided step-by-step interactive presentation
    python scripts/demo_intrusion_scenario.py --mode baseline    # Set system to normal baseline
    python scripts/demo_intrusion_scenario.py --mode intrusion --type kernel         # Kernel-level rootkit attack
    python scripts/demo_intrusion_scenario.py --mode intrusion --type process_churn  # Process churn / fork bomb attack
    python scripts/demo_intrusion_scenario.py --mode intrusion --type network_exfil  # Network listener / exfiltration attack
    python scripts/demo_intrusion_scenario.py --mode execute-mitigation             # Safely evaluate mitigation intent
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure IntentX package is on python path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from intentx.behavior.anomaly import (
    BehavioralAnomalyDetector,
    BehavioralModelArtifact,
    load_behavioral_model,
)
from intentx.behavior.explainer import (
    BehavioralAnomalyExplainer,
    FeatureAttribution,
    WindowExplanation,
)
from intentx.behavior.mitigation import (
    MitigationRecommendation,
    MitigationRecommender,
)
from intentx.telemetry.windowing import BehavioralWindow
from intentx.application.service import (
    ApplicationRequest,
    IntentXApplicationService,
)

from intentx.behavior.demo import build_normal_window, build_attack_window, compute_xai_and_mitigations

LIVE_SCORES_PATH = REPO_ROOT / "runtime" / "demo" / "live-scores.json"
TELEMETRY_STATUS_PATH = REPO_ROOT / "runtime" / "demo" / "telemetry-status.json"
BEHAVIOR_REPORT_PATH = REPO_ROOT / "runtime" / "behavior-report.json"
DEFAULT_MODEL_PATH = REPO_ROOT / "runtime" / "behavior" / "v2-cohort" / "validated-model" / "behavioral_model.joblib"

# ANSI Colors for Terminal Presentation
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


def load_model_if_available():
    if DEFAULT_MODEL_PATH.exists():
        try:
            return load_behavioral_model(DEFAULT_MODEL_PATH)
        except Exception:
            pass
    return None


def write_telemetry_status(state: str, sensors: dict[str, str], last_event_desc: str):
    TELEMETRY_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": state,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "active_sensors": sensors,
        "last_event_description": last_event_desc,
        "monitored_subsystems": [
            "kernel_taint",
            "audit_syscalls",
            "cgroup_memory",
            "process_tree",
            "network_sockets",
        ],
    }
    with open(TELEMETRY_STATUS_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def write_live_scores_file(
    windows: list[dict],
    threshold: float = -0.5616504137954491,
    state: str = "collecting",
    model_sha256: str = "3284d6ae28dd37310b8d0a8ca5fd810a938d14314db4569b47cf60f90f0eb148",
):
    LIVE_SCORES_PATH.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    if windows:
        first_start = datetime.fromisoformat(windows[0]["start_utc"])
        started = first_start - timedelta(seconds=5)
    else:
        started = now - timedelta(seconds=120)

    # Ensure margin and threshold math match exactly
    for w in windows:
        w["margin"] = w["score"] - threshold
        w["flagged"] = bool(w["score"] < threshold)

    payload = {
        "version": 1,
        "state": state,
        "updated_at": now.isoformat(),
        "collection_started_at": started.isoformat(),
        "startup_seconds": 120,
        "model_sha256": model_sha256,
        "threshold": threshold,
        "feature_schema_version": 2,
        "model_retrained": False,
        "windows": windows,
    }
    with open(LIVE_SCORES_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)








def print_banner(title: str, color: str = CYAN):
    width = 76
    print(f"\n{color}{'=' * width}")
    print(f" {BOLD}{title}{RESET}{color}")
    print(f"{'=' * width}{RESET}")


def run_baseline_scenario():
    print_banner("1. INITIALIZING CLEAN SYSTEM BASELINE", GREEN)
    now = datetime.now(timezone.utc)
    w1 = build_normal_window(now - timedelta(seconds=120))
    w2 = build_normal_window(now - timedelta(seconds=60))
    write_live_scores_file([w1, w2])
    write_telemetry_status(
        state="collecting",
        sensors={
            "kernel_taint": "clean (0)",
            "audit_syscalls": "normal",
            "cgroup_memory": "active (8.8% used)",
            "process_sensor": "collected (2 active)",
            "network_sensor": "collected (1 listener)",
        },
        last_event_desc="Normal system workload; telemetry within established baseline distributions.",
    )

    print(f"  • Telemetry Status: {GREEN}ONLINE & CLEAN{RESET}")
    print(f"  • Isolation Forest Score: {GREEN}{w2['score']:.4f}{RESET} (Threshold: -0.5617)")
    print(f"  • Decision Margin: {GREEN}{w2['margin']:+.4f} (NORMAL){RESET}")
    print(f"  • Active Windows: 2 normal windows recorded")
    print(f"  • Web Dashboard URL: {CYAN}http://127.0.0.1:8000/{RESET}")
    print(f"  {GREEN}✓ Dashboard status is GREEN. No anomalies detected.{RESET}\n")


def run_intrusion_scenario(attack_type: str = "kernel"):
    attack_names = {
        "kernel": "Kernel-Level Module Insertion & Root Privilege Escalation",
        "process_churn": "Rogue Process Burst & Resource Exhaustion (Fork Bomb)",
        "network_exfil": "Unauthorized Network Listener & Data Exfiltration",
    }
    print_banner(f"2. INJECTING INTRUSION ATTACK: {attack_names.get(attack_type, attack_type)}", RED)
    now = datetime.now(timezone.utc)
    w_norm = build_normal_window(now - timedelta(seconds=120))
    w_attack = build_attack_window(now - timedelta(seconds=60), attack_type)

    write_live_scores_file([w_norm, w_attack])

    sensor_states = {
        "kernel": {
            "kernel_taint": "ALERT: Tainted kernel bitmask (0x1000 - out of tree module)",
            "audit_syscalls": "CRITICAL: Unauthorized execve / ptrace syscall burst",
            "cgroup_memory": "active (8.8% used)",
            "process_sensor": "elevated (18 root processes)",
            "network_sensor": "collected (1 listener)",
        },
        "process_churn": {
            "kernel_taint": "clean (0)",
            "audit_syscalls": "elevated fork/clone syscalls",
            "cgroup_memory": "WARNING: Memory ratio surged to 89%",
            "process_sensor": "CRITICAL: 65 concurrent processes running",
            "network_sensor": "collected",
        },
        "network_exfil": {
            "kernel_taint": "clean (0)",
            "audit_syscalls": "socket / bind syscalls detected",
            "cgroup_memory": "active (9.2% used)",
            "process_sensor": "collected",
            "network_sensor": "ALERT: 6 active listeners, 42 outbound connections",
        },
    }

    write_telemetry_status(
        state="collecting",
        sensors=sensor_states.get(attack_type, {}),
        last_event_desc=f"ANOMALY DETECTED: {attack_names.get(attack_type)} triggered behavioral threshold violation.",
    )

    explanation, mitigations = compute_xai_and_mitigations(w_attack)

    print(f"{RED}{BOLD}🚨 [THREAT ALERT] BEHAVIORAL ANOMALY DETECTED BY ISOLATION FOREST!{RESET}")
    print(f"  • Anomaly Score:   {RED}{w_attack['score']:.4f}{RESET} (Threshold: -0.5617)")
    print(f"  • Decision Margin: {RED}{w_attack['margin']:+.4f} (NEGATIVE = MALICIOUS DEVIATION){RESET}")
    print(f"  • Timestamp:       {w_attack['end_utc']}")

    print_banner("3. EXPLAINABLE AI (XAI) ATTRIBUTION BREAKDOWN", YELLOW)
    print(f"  {BOLD}{explanation.summary}{RESET}\n")
    print(f"  {'Feature Name':<30} | {'Observed':<10} | {'Contribution %':<16} | {'Description'}")
    print(f"  {'-' * 76}")
    for factor in explanation.primary_factors:
        pct = f"{factor.contribution_percentage:.1f}%"
        print(f"  {CYAN}{factor.feature_name:<30}{RESET} | {factor.observed_value:<10.2f} | {YELLOW}{pct:<16}{RESET} | {factor.description}")

    print_banner("4. AUTOMATED INTELLIGENT MITIGATION RECOMMENDATIONS", MAGENTA)
    print(f"  Generated {len(mitigations)} prioritized countermeasures:\n")
    for idx, m in enumerate(mitigations, start=1):
        color = RED if m.priority == "CRITICAL" else YELLOW if m.priority == "HIGH" else BLUE
        print(f"  {idx}. {color}[{m.priority}] {m.title}{RESET}")
        print(f"     Rationale:       {m.rationale}")
        print(f"     System Command:  {BOLD}{m.command_hint}{RESET}")
        print(f"     Console Intent:  {CYAN}\"{m.suggested_intent}\"{RESET}\n")

    print(f"{GREEN}✓ Live Web Dashboard (http://127.0.0.1:8000/) has updated with this intrusion, XAI graph, and 1-Click Adopt buttons!{RESET}")
    return explanation, mitigations


def run_execute_mitigation_scenario(suggested_intent: str = "lock kernel modules"):
    print_banner("5. SAFE MITIGATION EXECUTION VIA DETERMINISTIC INTENTX ENGINE", BLUE)
    print(f"  Simulating adoption of mitigation intent: {CYAN}\"{suggested_intent}\"{RESET}\n")

    service = IntentXApplicationService()
    request = ApplicationRequest(
        text=suggested_intent,
        role="operator",
        environment="dev",
        correlation_id=f"demo-{int(time.time())}",
        execute=False,  # Planning & Policy Stage
    )

    print("  • Step 5a: Natural Language Intent Parsing & Safety Planning...")
    result = service.handle(request)

    print(f"    - Predicted Intent:  {BOLD}{result.predicted_intent}{RESET} (Confidence: {result.confidence:.2%})")
    print(f"    - Status:            {GREEN if 'PLAN' in result.status or 'READY' in result.status else YELLOW}{result.status}{RESET}")
    if result.plan:
        print(f"    - Deterministic Executable: {BOLD}{result.plan.executable}{RESET}")
        print(f"    - Whitelisted Arguments:    {list(result.plan.arguments)}")
        print(f"    - Privilege Required:       {result.plan.privilege_required}")
        print(f"    - Critical Operation:       {result.plan.critical_operation}")

    if result.security_assessment:
        sa = result.security_assessment
        print("\n  • Step 5b: Deterministic Policy & Risk Assessment Gate:")
        if sa.risk:
            print(f"    - Risk Score:        {BOLD}{sa.risk.score}/100{RESET} (Level: {sa.risk.level})")
        if sa.policy:
            print(f"    - Policy Decision:   {GREEN if sa.policy.decision == 'ALLOW' else YELLOW}{sa.policy.decision}{RESET}")
        print("    - Security Principles: Zero raw shell execution (shell=False), parameter whitelisting, non-root enforcement.")

    print(f"\n{GREEN}✓ Academic Verification Complete: AI suggested the mitigation, but deterministic controls gate execution!{RESET}\n")


def run_interactive_presentation():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║               AI-POWERED EXPLAINABLE LINUX SECURITY ASSISTANT                ║
║           Kernel-Level Intrusion & Behavioral Threat Detection Demo          ║
╚══════════════════════════════════════════════════════════════════════════════╝{RESET}
Academic Dissertation & Capstone Demonstration Suite
Stack: Linux POSIX Telemetry • Isolation Forest ML • XAI Feature Attribution • IntentX
Web Dashboard: {CYAN}http://127.0.0.1:8000/{RESET}
""")

    try:
        input(f"{BOLD}Press [ENTER] to start Step 1: Initialize Normal System Baseline...{RESET} ")
    except (KeyboardInterrupt, EOFError):
        return
    run_baseline_scenario()

    try:
        input(f"{BOLD}Press [ENTER] to start Step 2: Simulate Kernel-Level Rootkit & Intrusion Attack...{RESET} ")
    except (KeyboardInterrupt, EOFError):
        return
    explanation, mitigations = run_intrusion_scenario("kernel")

    best_intent = mitigations[0].suggested_intent if mitigations else "lock kernel modules"

    try:
        input(f"\n{BOLD}Press [ENTER] to start Step 3: Demonstrate Safe Policy Evaluation of \"{best_intent}\"...{RESET} ")
    except (KeyboardInterrupt, EOFError):
        return
    run_execute_mitigation_scenario(best_intent)

    try:
        choice = input(f"{BOLD}Press [ENTER] to restore clean baseline (or type 'keep' to keep intrusion on dashboard): {RESET}")
    except (KeyboardInterrupt, EOFError):
        choice = ""

    if choice.strip().lower() != "keep":
        run_baseline_scenario()
        print(f"{GREEN}✓ Baseline restored. Presentation demonstration concluded successfully.{RESET}")
    else:
        print(f"{YELLOW}✓ Intrusion state kept active on dashboard for professor inspection.{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Demo script for AI-Powered Explainable Linux Security Assistant"
    )
    parser.add_argument(
        "--mode",
        choices=["interactive", "baseline", "intrusion", "execute-mitigation"],
        default="interactive",
        help="Demo mode to execute (default: interactive)",
    )
    parser.add_argument(
        "--type",
        choices=["kernel", "process_churn", "network_exfil"],
        default="kernel",
        help="Type of intrusion to simulate in 'intrusion' mode (default: kernel)",
    )
    parser.add_argument(
        "--intent",
        default="lock kernel modules",
        help="Intent to evaluate in 'execute-mitigation' mode",
    )
    args = parser.parse_args()

    if args.mode == "interactive":
        run_interactive_presentation()
    elif args.mode == "baseline":
        run_baseline_scenario()
    elif args.mode == "intrusion":
        run_intrusion_scenario(args.type)
    elif args.mode == "execute-mitigation":
        run_execute_mitigation_scenario(args.intent)


if __name__ == "__main__":
    main()
