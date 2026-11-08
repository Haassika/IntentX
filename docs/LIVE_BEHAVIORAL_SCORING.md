# Experimental live behavioral scoring

The Linux worker loads an operator-selected, trusted local model after checking its
SHA-256 digest. Joblib is executable serialization: only use the project's trusted
artifact. The browser/API never load models or accept model paths. Schema 2, calibrated
model format 2, exact sklearn version and the declared training hostname are required.
A matching hostname does not establish workload equivalence. This monitoring runtime
has a different process/workload profile from training; scores are experimental.

Start one worker per report/status pair in a hardened, non-root Linux container:

```bash
python -m intentx.behavior.live \
  --model-path /baseline/behavioral_model.joblib \
  --model-sha256 ACTUAL_TRUSTED_MODEL_SHA256
```

Mount the model read-only and a writable Docker volume at `/app/runtime`. Set the
container's declared lab hostname to the model's training identity. No host mounts,
privileged mode, network access, or shell execution are needed for collection.

The worker collects every five seconds and validates schedule/resource coverage for
120-second batches before scoring their two 60-second windows. Missing observations,
incomplete cgroup evidence, model changes, or scoring errors reject the batch. There
is no retraining, threshold adjustment, mitigation, or command authorization.

A bounded temporary database is removed after each batch, including failed batches.
Only the latest twenty completed windows are retained in the atomic report. Raw
telemetry is not retained for forensic replay. Measured feature vectors accompany
scores as observations, not causal explanations. Pausing/restarting begins a new
batch; uninterrupted coverage across batch boundaries is not claimed.

Configure the API with `INTENTX_LIVE_SCORES=/app/runtime/behavior/live-scores.json`
and `INTENTX_TELEMETRY_STATUS=/app/runtime/telemetry/live-status.json`, using read-only
access to the worker's volume. Do not run the status-only monitor against the same
status file: the scoring worker publishes its own collector heartbeat.

The dashboard refreshes every ten seconds. First scores take about two minutes.
Warmup, failure, stopped, stale, and unconfigured states are explicit. Old completed
results stay historical when the scorer is not active. Reports are size-bounded and
validated before curated JSON is returned from `GET /api/v1/behavior/live`.

The existing command console remains separate. A model flag never authorizes an
execution or confirms an intrusion. Linux Audit, authentication and kernel sensors
are not validated by this worker.
