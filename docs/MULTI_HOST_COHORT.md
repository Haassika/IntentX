# Explicit parallel lab cohort

Single-host validation plans retain their original behavior: all sessions must
share a lab identity and have disjoint observation periods. A plan may opt into
multiple declared lab hosts with `declared_lab_hostnames`, a list of unique host
names represented in training. Calibration/evaluation hosts must be among them.

Observations on distinct hosts may overlap in time. Same-host overlaps, reused
DB hashes, repeated event IDs, checksum changes, incomplete coverage and schema
mismatches are still rejected. Multi-host training uses the existing explicit
dataset option; models record every represented training hostname. No feature
meaning or anomaly threshold contract changes.

Different Docker hostnames identify separate container sessions, not independent
physical machines. Parallel sessions share the Docker host and may contend for
CPU/memory. Record resources and workload provenance, and limit conclusions to
the declared cohort. Validation covering only a subset of training host identities
does not independently validate the remaining identities.

Fit training data, calibrate using the separate declared calibration role, freeze
the cutoff, then load evaluation feature vectors. Historical presentation supports
parallel windows only for a report with an explicit host declaration matching model
metadata, and rejects overlaps per host. The table includes host identity.
