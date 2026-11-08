# Collection phases in live scoring

New live reports record the first batch collection start and a fixed 120-second startup period. This is a display convention measured from scorer collection, not workload startup, host boot, baseline readiness, or evidence of stable behavior. Collection starts immediately; scoring still requires complete windows and validated coverage. Neither scores nor flags depend on the phase label.

The report reader derives the last reported phase and age from the saved heartbeat timestamp. Below 120 seconds is startup; at 120 seconds and afterward is steady-state collection. A window is labeled startup if any part begins before the boundary; a window starting at or after it is steady-state collection. Labels do not filter results. The existing rolling retention remains twenty scored windows, regardless of phase or flag.

On stale, stopped or failed reports, phase and age refer to the saved report, not inferred ongoing collection. Old reports without phase evidence remain readable and show unknown phase/age. Malformed, future, naive or inconsistent start-time evidence is rejected. A scorer restart begins a new collection session.

The earlier startup experiments motivate making this context visible. They do not establish that a two-minute delay cures false alarms. The collection-phase label should not be confused with those experiments' delay measured from workload startup. Historical validation results retain their original interpretation.
