# Dashboard metric interpretation update

Open the dashboard and expand **Understand the metrics and their significance** near the top. Each section explains the measurement, its use and its limits. The feature glossary covers all 19 version 2 features. The six synthetic evidence cards and expanded live windows now include explanations next to their values.

## Read the evidence in this order

1. **Source:** upper SOC windows are simulated, lower scoring windows are measured container observations, and saved validation is historical.
2. **Freshness:** collecting describes recent activity; stale means the heartbeat is over 30 seconds old. A fresh heartbeat does not mean a new score has completed.
3. **Decision:** anomaly score is compared with its own threshold. Margin equals score minus threshold. A negative margin is flagged for review, not proof of compromise.
4. **Explanation:** contributions rank reference deviations. Above and below reference both matter. Contribution percentages are not probabilities, causal attribution or severity.
5. **Response:** inspect the workload and verify a target before considering any change. Intent classification confidence, operation risk and policy are separate from behavioral detection.

## Corrections

- Model-backed XAI descriptions now state above, below or at the reference instead of calling every absolute deviation elevated.
- Existing scores, thresholds and attribution math are preserved. The JSON deviation_zscore field remains an absolute distance for compatibility; direction is exposed separately.
- The default live reference is estimated from tree splits, not an empirical training-set mean or standard deviation. The UI discloses this, and discloses the illustrative fallback when a model explanation cannot be loaded.
- Explained window timestamps now match the selected completed window, rather than the time the page requested an explanation. Report status is shown beside the explanation to distinguish current and historical data.
- Below-reference process/network/memory/privilege/kernel values no longer trigger countermeasures whose rationale assumes an upward spike. Generic inspection remains available for unexplained drift.
- Recommendations no longer assert that a model deviation alone establishes a rogue process or exceeded resource limits.
- Memory ratios display a percentage of the observed cgroup limit, not total Mac or Windows RAM. Unavailable-source counters do not prove no events occurred. Kernel/audit-labeled counters can include repeated procfs state warnings even though the heartbeat does not attest full sensor coverage; they are not counts of distinct intrusions.

## Files changed for this update

- src/intentx/ui/metric_guide.py — new shared feature glossary and collapsible interpretation guide.
- src/intentx/ui/soc.py — inline help and synthetic score calculation.
- src/intentx/ui/dashboard.py — live score interpretation, readable feature rows, explanation method/source/timestamps.
- src/intentx/behavior/explainer.py — directionally accurate explanations.
- src/intentx/behavior/mitigation.py — upward-spike recommendations require an upward deviation.
- src/intentx/api/app.py — explanation provenance and original window timestamps.
- tests/behavior/test_metric_interpretation.py and tests/test_metric_guide.py — direction, recommendation and provenance checks.

The previously added clarification suggestions are included. Browser/API execution authority and predefined scenario restrictions are preserved.

## Deployment

Rebuild from this updated folder and recreate only the dashboard container with its existing environment variables, model bind mount and live-data volume. Do not delete the volume. The already-running collector can continue with its frozen model; this update does not change scoring. Running containers do not receive file changes merely because a new project folder was extracted.
