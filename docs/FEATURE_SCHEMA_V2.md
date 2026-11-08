# Container feature schema v2

Select `--feature-schema-version 2` for newly trained container baselines.
The existing CLI default remains version 1 for explicit backward compatibility.

V1 uses the established 25 features. V2 has 19: it retains process/network/event
counts and other security-event counts, removes Linux-system load and memory
ratios plus procps lifetime CPU/system memory percentages, and adds mean/max
cgroup memory usage ratios. These are charged memory divided by the local finite
cgroup memory limit, including cache. V2 requires every resource observation in
each window to include collected, finite-limit cgroup memory accounting with
finite nonnegative ratios. Missing/unlimited/malformed observations reject the
baseline before training; they are not converted to zeros or VM values.

Models and manifests store `feature_schema_version` and exact ordered names.
Unknown versions, inconsistent names, and explicitly mismatched input versions
are rejected. Older model artifacts without a version are treated as v1.
Scoring selects the frozen model's schema; v2 scoring requires cgroup data,
while legacy scoring continues using its original measurements. Evaluation
records the version and never retrains the model.

The existing baseline and evaluation remain v1 evidence. Do not relabel old
models or infer cgroup measurements from their VM memory ratios. Fresh v2
training and independent evaluation are required; this migration does not
establish improved false-alarm performance by itself.

Next validation: build the new image and run a two-minute v2 smoke experiment
with the same hardened settings and finite memory limit. Confirm 24 samples,
two windows, 19 feature names, and version 2 in its manifest. Only then collect
multiple benign sessions and reserve independent data for threshold calibration
and final evaluation. Schema selection does not address startup transients.
