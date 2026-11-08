# Historical behavioral results panel

The existing command console now includes a read-only behavioral validation
panel. Configure `INTENTX_BEHAVIOR_REPORT` on the server to point to a saved
multisession-v2 validation.json file. For a local preview:

```sh
INTENTX_BEHAVIOR_REPORT=/absolute/path/to/validation.json \
  python -m uvicorn intentx.api.app:app --host 127.0.0.1 --port 8765
```

The GET `/api/v1/behavior/results` endpoint projects a bounded JSON report into
model versions, threshold, train/calibration/evaluation counts, benign flag rate,
and per-window scores/margins. It does not accept client-supplied paths, load
joblib models, collect telemetry, or trigger training/execution. Source file paths
and session-manifest locations are omitted. Invalid/missing configured reports
return 503; an unconfigured server returns an explicit not-configured state.

The UI labels results historical, experimental, and read-only. It states that
live monitoring and sensor availability are not connected. Coverage information
is attributed to the saved workflow; the UI does not recheck its source databases.
Flagged windows are model observations, not attack classifications. Refresh only
reloads the configured saved report. Existing Analyze/Execute behavior is intact.

Scope: presentation of saved validation evidence. Live collection, alert delivery,
authenticated identity, and authoritative execution audit history remain separate
integration work. Do not expose the prototype publicly without addressing its
existing authentication/deployment requirements.
