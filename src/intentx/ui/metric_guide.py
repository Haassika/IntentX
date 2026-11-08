"""Plain-language interpretation shared by the SOC guide and live feature rows."""
from html import escape

FEATURE_HELP = {
    "event_count": "Total normalized events in this window. This is an observation count, not a number of attacks.",
    "process_event_count": "Process-related events in the window. Higher counts can reflect normal work or process churn; inspect the workload.",
    "unique_process_count": "Distinct process identities represented in this window; not necessarily the number running at one instant.",
    "root_process_event_count": "Process events associated with root privileges. Root activity alone does not establish malicious behavior.",
    "network_connection_count": "Connection observations in the window. Compare with the workload and collection scope before judging a change.",
    "network_listener_count": "Listener observations in the window. Inspect ownership and expected services before taking action.",
    "unique_remote_address_count": "Distinct remote addresses represented in the window. Diversity can change with legitimate network activity.",
    "auth_success_count": "Successful authentication events, only when an authentication event source is available.",
    "auth_failure_count": "Failed authentication events, only when the source is available; missing coverage is not zero failures.",
    "privilege_activity_count": "Privilege-related activity events. Verify context and sensor coverage.",
    "file_activity_count": "File-related activity events. Counts depend on the connected event source.",
    "audit_event_count": "Audit-labeled normalized observations. Some may come from procfs security warnings rather than a full audit stream; verify mechanism and coverage.",
    "kernel_event_count": "Kernel-related normalized observations. Repeated samples of one taint or state warning can increase the count; it is not a count of distinct intrusions. Verify provenance and coverage.",
    "sensor_unavailable_count": "Unavailable-sensor observations. This is a coverage limitation, not a threat count.",
    "sensor_error_count": "Sensor-error observations. Investigate collection reliability before interpreting missing activity.",
    "mean_process_count": "Average sampled process count during the window; separate from total process events.",
    "max_process_count": "Highest sampled process count during the window. A deviation does not prove a resource limit was exceeded.",
    "mean_cgroup_memory_used_ratio": "Average fraction of the observed cgroup memory limit in use. 0.25 means 25 percent of that limit, not host RAM.",
    "max_cgroup_memory_used_ratio": "Peak fraction of the observed cgroup memory limit in use. Check the limit and trend before concluding memory pressure.",
}

GUIDE_SECTIONS = (
    ("Anomaly score and threshold", "A lower, more negative score is more anomalous in this interface. The threshold is the decision boundary for the selected model. Upper demo scores are fixed fixtures; lower live scores come from the collector and frozen model. Neither is a probability of attack."),
    ("Decision margin and assessment", "Margin = score minus threshold. A negative margin is flagged; zero or positive is unflagged. Example: -0.7420 minus -0.5616504 is -0.1803496. Review means investigate, not confirmed compromise. Thresholds should not be changed simply to remove flags."),
    ("XAI contribution and direction", "Contribution percent ranks explanation factors; it is not severity or causation. A feature may be above or below its reference. The demo uses illustrative fixture deviations. The live explainer combines model path weights with absolute reference distance. Its default reference is estimated from tree splits, not measured training-set statistics. This is not SHAP."),
    ("Telemetry freshness and sensor availability", "Collecting means recent collection activity, not a healthy or attack-free host. A status record older than 30 seconds is stale. Unavailable and unknown describe coverage gaps. A zero feature from an unavailable source does not establish that no event occurred."),
    ("Live windows and historical validation", "The worker scores completed 60-second windows after a valid 120-second batch. The heartbeat can refresh while scores remain unchanged. Startup covers the first two minutes; steady state is elapsed time, not proof of stability. Saved validation is historical: benign flag rate is the fraction of benign windows flagged, not attack detection accuracy."),
    ("Confidence risk and policy", "Confidence belongs to natural-language intent classification. Operation risk is a separate policy index from 0 to 100. Role category permission, risk and hard safety checks determine policy. Analyze does not execute. Suggestions and recommendations do not grant execution authority."),
    ("Why some values do not change", "The frozen threshold and historical report remain fixed. Only selecting a demo changes synthetic scenario values. Real telemetry changes with observed workload; constant values are possible. Recommendations may be empty for unflagged windows. The basic worker heartbeat does not attest full kernel or audit coverage. Related counters can still include repeated procfs warnings; a nonzero counter does not establish a complete kernel or audit sensor."),
)

GUIDE_HTML = '<details id="metric-guide" class="soc-card" style="margin:16px 0"><summary style="cursor:pointer;font-weight:700">Understand the metrics and their significance</summary><p>Read the evidence source and freshness first, then the decision and its limits.</p>'
GUIDE_HTML += ''.join(f'<details style="margin:12px 0"><summary>{escape(title)}</summary><p>{escape(body)}</p></details>' for title, body in GUIDE_SECTIONS)
GUIDE_HTML += '<details><summary>Behavioral feature glossary with units and coverage notes</summary><dl>'
GUIDE_HTML += ''.join(f'<dt style="margin-top:12px;font-weight:700">{escape(name.replace("_", " "))}</dt><dd style="margin:4px 0 12px">{escape(description)}</dd>' for name, description in FEATURE_HELP.items())
GUIDE_HTML += '</dl></details></details>'
