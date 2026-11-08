# Multi-session controlled benign validation

Declare dataset roles before inspecting their scores. Use fresh disjoint benign
sessions from the same lab configuration and identity, with varied workload seeds.
Each input is a schema-v2 baseline experiment manifest with its telemetry database.
The per-session trained models are ignored; the workflow fits a new model on the
combined training windows. Their training is an artifact of the existing collector
runner, not part of calibration or final evaluation.

A plan JSON contains manifest paths (absolute or relative to the plan):

```json
{
  "training": ["train-a/manifest.json", "train-b/manifest.json"],
  "calibration": ["calibration-a/manifest.json"],
  "evaluation": ["final-a/manifest.json"]
}
```

Run offline after those sessions have been collected and exported:

```sh
python -m intentx.behavior.multisession \
  --plan validation-plan.json \
  --output-root runtime/behavior/multisession-v2 \
  --target-rate 0.05
```

At least two training sessions, one calibration session, and one final evaluation
session are required. Database checksums and collection completeness are rechecked.
Duplicate databases, overlapping same-host observation periods, inconsistent
window durations, and mixed lab hostnames are rejected. Operators must separately
ensure equivalent resource limits and benign workload profiles; a hostname is not
proof of equivalence. The plan is not a substitute for workload provenance.

A 5% target requires at least 20 calibration windows; this is a minimum for
empirical cutoff resolution, not evidence of statistical precision. More independent
sessions are preferable. The lower-tail cutoff on Isolation Forest score_samples
flags scores strictly below the chosen value, leaving ties unflagged. It may
produce fewer flags than the target. No future false-alarm guarantee is claimed.
Evaluation data is not read into feature vectors until after the cutoff is fixed.
Do not change the cutoff using final evaluation results and still call that run
independent validation.

Outputs are a new model and validation.json recording session roles/checksums,
training/calibration counts, threshold, observed calibration rate, and final benign
flag rate with individual window scores. Calibrated models use artifact format 2
so older loaders reject them instead of silently ignoring the threshold. Feature
schema remains v2. The reported decision margin is raw score minus calibrated
threshold, with negative margins flagged; the original uncalibrated model
prediction is retained separately. Existing uncalibrated models retain format 1
and their original scoring behavior.

Current pilot results are exploratory evidence, not a pristine final test set:
we already inspected their scores. Collect fresh final sessions for this workflow.
This supports benign validation only, not attack detection claims.
