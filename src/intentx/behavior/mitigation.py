"""Intelligent mitigation recommendations engine for detected behavioral threats."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Sequence

from intentx.application.service import ApplicationRequest
from intentx.behavior.explainer import FeatureAttribution, WindowExplanation


@dataclass(frozen=True)
class MitigationRecommendation:
    """An intelligent operational mitigation recommendation for an anomaly alert."""

    recommendation_id: str
    category: str
    title: str
    suggested_intent: str
    rationale: str
    priority: str
    state_changing: bool
    requires_privilege: bool
    requires_approval: bool
    command_hint: str
    target_entity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "category": self.category,
            "title": self.title,
            "suggested_intent": self.suggested_intent,
            "rationale": self.rationale,
            "priority": self.priority,
            "state_changing": self.state_changing,
            "requires_privilege": self.requires_privilege,
            "requires_approval": self.requires_approval,
            "command_hint": self.command_hint,
            "target_entity": self.target_entity,
        }

    def to_application_request(
        self,
        *,
        role: str = "OPERATOR",
        environment: str = "DEV",
        execute: bool = False,
    ) -> ApplicationRequest:
        """
        Convert the recommended mitigation into an authoritative IntentX ApplicationRequest.
        Pass this to IntentXApplicationService.handle() to enforce deterministic
        validation, risk scoring, and policy checks before any execution.
        """
        return ApplicationRequest(
            text=self.suggested_intent,
            role=role,
            environment=environment,
            correlation_id=f"mitigation-{self.recommendation_id}",
            execute=execute,
        )


class MitigationRecommender:
    """
    Intelligent decision-support engine that analyzes explainable anomaly outputs
    and produces actionable, policy-safe administrative mitigation plans.
    """

    @classmethod
    def recommend(
        cls,
        explanation: WindowExplanation,
        *,
        max_recommendations: int = 4,
    ) -> list[MitigationRecommendation]:
        """Generate structured mitigation recommendations based on the anomaly explanation."""
        if not explanation.is_anomalous:
            return []

        recommendations: list[MitigationRecommendation] = []
        top_factors = explanation.primary_factors

        # Map anomalous feature domains to specific mitigation strategies
        has_process_anomaly = any(
            f.feature_name in {"process_event_count", "unique_process_count", "max_process_count", "mean_process_count"}
            and f.deviation_zscore > 1.0
            and f.observed_value > f.baseline_mean
            for f in top_factors
        )
        has_network_anomaly = any(
            f.feature_name in {"network_connection_count", "network_listener_count", "unique_remote_address_count"}
            and f.deviation_zscore > 1.0
            and f.observed_value > f.baseline_mean
            for f in top_factors
        )
        has_memory_anomaly = any(
            f.feature_name in {"mean_cgroup_memory_used_ratio", "max_cgroup_memory_used_ratio"}
            and f.deviation_zscore > 1.0
            and f.observed_value > f.baseline_mean
            for f in top_factors
        )
        has_privilege_anomaly = any(
            f.feature_name in {"auth_failure_count", "privilege_activity_count", "root_process_event_count"}
            and f.deviation_zscore > 1.0
            and f.observed_value > f.baseline_mean
            for f in top_factors
        )
        has_kernel_anomaly = any(
            f.feature_name in {"kernel_event_count", "audit_event_count"}
            and f.deviation_zscore > 1.0
            and f.observed_value > f.baseline_mean
            for f in top_factors
        )

        # 1. Process Churn / Spike Mitigations
        if has_process_anomaly:
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="process_inspection",
                    title="Inspect Active Process Tree",
                    suggested_intent="show running processes",
                    rationale="Process indicators are above the explanation reference. Inspect running processes and workload context; this does not identify a malicious PID.",
                    priority="HIGH",
                    state_changing=False,
                    requires_privilege=False,
                    requires_approval=False,
                    command_hint="ps -ef",
                )
            )
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="process_management",
                    title="Review Termination of a Verified Process",
                    suggested_intent="terminate process",
                    rationale="Process activity is above the explanation reference. Verify the workload, resource limits and a specific target before considering termination; a model flag alone is insufficient.",
                    priority="CRITICAL",
                    state_changing=True,
                    requires_privilege=True,
                    requires_approval=True,
                    command_hint="kill -15 <pid>",
                )
            )

        # 2. Network Socket / Loopback Burst Mitigations
        if has_network_anomaly:
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="network_inspection",
                    title="Inspect Active Network Connections & Sockets",
                    suggested_intent="show network connections",
                    rationale="Network indicators are above the explanation reference. Inspect active sockets and listeners before drawing a security conclusion.",
                    priority="HIGH",
                    state_changing=False,
                    requires_privilege=False,
                    requires_approval=False,
                    command_hint="ss -tulpn",
                )
            )
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="network_management",
                    title="Review Isolation of a Verified Listener",
                    suggested_intent="block network port",
                    rationale="Network activity is above the explanation reference. Inspect the listener, identify its owner and verify a specific target before considering isolation.",
                    priority="CRITICAL",
                    state_changing=True,
                    requires_privilege=True,
                    requires_approval=True,
                    command_hint="iptables -A INPUT -p tcp --dport <port> -j DROP",
                )
            )

        # 3. Memory & Resource Exhaustion Mitigations
        if has_memory_anomaly:
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="storage_inspection",
                    title="Inspect Memory & Swap Utilization",
                    suggested_intent="show memory usage",
                    rationale="Memory usage differs upward from the explanation reference. Inspect the actual ratio and container limit before concluding that capacity is exhausted.",
                    priority="MEDIUM",
                    state_changing=False,
                    requires_privilege=False,
                    requires_approval=False,
                    command_hint="free -h",
                )
            )
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="storage_maintenance",
                    title="Inspect Filesystem & Clean Temporary Storage",
                    suggested_intent="show disk space",
                    rationale="High memory/storage contention detected. Check filesystem utilization to prevent OOM.",
                    priority="HIGH",
                    state_changing=False,
                    requires_privilege=False,
                    requires_approval=False,
                    command_hint="df -h",
                )
            )

        # 4. Privilege & Authentication Mitigations
        if has_privilege_anomaly:
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="security_audit",
                    title="Audit Privileged Actions & Auth Failures",
                    suggested_intent="show authentication logs",
                    rationale="Privilege elevation or repeated auth failures detected. Verify identity legitimacy.",
                    priority="CRITICAL",
                    state_changing=False,
                    requires_privilege=True,
                    requires_approval=False,
                    command_hint="last -F",
                )
            )

        # 5. Kernel-Level Intrusion & Tampering Mitigations
        if has_kernel_anomaly:
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="kernel_hardening",
                    title="Lock Kernel Module Insertion",
                    suggested_intent="lock kernel modules",
                    rationale="Kernel-level intrusion indicators or taint flags detected. Lock runtime kernel module loading to prevent rootkit insertion.",
                    priority="CRITICAL",
                    state_changing=True,
                    requires_privilege=True,
                    requires_approval=True,
                    command_hint="sysctl -w kernel.modules_disabled=1",
                )
            )
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="kernel_hardening",
                    title="Restrict Process Tracing & Injection",
                    suggested_intent="restrict process tracing",
                    rationale="Prevent unauthorized process memory injection and ptrace attachment across PID boundaries.",
                    priority="HIGH",
                    state_changing=True,
                    requires_privilege=True,
                    requires_approval=True,
                    command_hint="sysctl -w kernel.yama.ptrace_scope=2",
                )
            )
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="system_information",
                    title="Audit Kernel Integrity & Taint Status",
                    suggested_intent="show kernel information",
                    rationale="Inspect active kernel taint flags, oops status, and loaded module provenance.",
                    priority="HIGH",
                    state_changing=False,
                    requires_privilege=False,
                    requires_approval=False,
                    command_hint="uname -a && cat /proc/sys/kernel/tainted",
                )
            )

        # Fallback general recommendation if no single category dominated but window is anomalous
        if not recommendations:
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"rec-{uuid.uuid4().hex[:8]}",
                    category="system_information",
                    title="Inspect General System State",
                    suggested_intent="show system information",
                    rationale=f"System behavioral drift detected (margin: {explanation.decision_margin:+.4f}). Inspect overall system status.",
                    priority="MEDIUM",
                    state_changing=False,
                    requires_privilege=False,
                    requires_approval=False,
                    command_hint="uname -a",
                )
            )

        return recommendations[:max_recommendations]
