"""
Read-only deterministic security assessment.

This package contains no process execution,
executable resolution, or operating-system
command-launching capability.
"""

from intentx.security.assessment import (
    SecurityAssessment,
    SecurityAssessmentService,
)

__all__ = [
    "SecurityAssessment",
    "SecurityAssessmentService",
]
