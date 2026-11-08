"""Deterministic feature extraction for behavioral security analysis."""

from __future__ import annotations

from intentx.telemetry.models import (
    BehavioralFeatures,
    SecuritySnapshot,
)


class BehavioralFeatureExtractor:
    """Converts a telemetry snapshot into deterministic numerical features."""

    HIGH_CPU_THRESHOLD = 50.0
    HIGH_MEMORY_THRESHOLD = 20.0

    def extract(self, snapshot: SecuritySnapshot) -> BehavioralFeatures:
        if snapshot.memory_total_kb <= 0:
            memory_used_ratio = 0.0
        else:
            used = max(
                snapshot.memory_total_kb - snapshot.memory_available_kb,
                0,
            )
            memory_used_ratio = min(
                used / snapshot.memory_total_kb,
                1.0,
            )

        root_processes = sum(
            1 for process in snapshot.processes
            if process.user == "root"
        )

        high_cpu = sum(
            1 for process in snapshot.processes
            if process.cpu_percent >= self.HIGH_CPU_THRESHOLD
        )

        high_memory = sum(
            1 for process in snapshot.processes
            if process.memory_percent >= self.HIGH_MEMORY_THRESHOLD
        )

        established = sum(
            1 for connection in snapshot.network_connections
            if connection.state.upper() == "ESTAB"
        )

        return BehavioralFeatures(
            load_1m=snapshot.load_1m,
            load_5m=snapshot.load_5m,
            load_15m=snapshot.load_15m,
            memory_used_ratio=memory_used_ratio,
            process_count=snapshot.process_count,
            root_process_count=root_processes,
            high_cpu_process_count=high_cpu,
            high_memory_process_count=high_memory,
            network_connection_count=len(snapshot.network_connections),
            established_connection_count=established,
        )
