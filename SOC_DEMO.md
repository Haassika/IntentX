# IntentX SOC presentation

Use Python 3.11 or newer. Extract this project, open its IntentX directory, and run:

```sh
bash run_soc.sh
```

If your default Python is older, use `INTENTX_PYTHON=python3.11 bash run_soc.sh`.
The first launch creates `.venv` and installs the project dependencies. Open
http://127.0.0.1:8000. Stop the foreground server with Ctrl+C.
Use one server worker; demo state is process-local and shared across browser tabs.
The launcher binds only to loopback and does not start privileged sensors.

## Presentation flow

1. Select **Normal baseline**: see the normal score and positive margin.
2. Select **Process anomaly**: process evidence changes and the margin becomes negative.
3. Select **Network anomaly**: inspect connections, listeners and explanation factors.
4. Select **Kernel security**: synthetic kernel/audit counters appear, explicitly labeled simulation.
5. Select **Review intent** on a recommendation. This only copies the suggested intent into the existing console. Choose the appropriate role/environment and Analyze Request to inspect the existing validation, risk and policy assessment. Execution remains a separate broker-controlled action.
6. Select **Reset demo**: clear synthetic windows, explanations and recommendations. The bounded timeline remains until server restart.

The dashboard polls every two seconds while visible, reports disconnected/stale display state on request failure, and disables controls during scenario changes. Scenarios are synchronous fixture preparation; “completed” means the synthetic evidence is ready, not that an attack ran. No scenario executes processes, changes kernel settings, opens sockets, or calls the execution service.

## Evidence and explanation boundaries

Demo scores are existing fixed presentation fixtures, not new Isolation Forest inference. Synthetic explanation contributions compare each feature with the normal fixture using an illustrative scale of `max(1, 10% of baseline)`. They are not causal SHAP values, calibrated statistical deviations, or evidence of compromise. Existing explanation data classes and MitigationRecommender generate the presentation response. The normal fixture has no elevated factors. Live scoring/model-grounded explanation routes remain separate and unchanged.

`GET /api/v1/demo/status` reads demo state. `POST /api/v1/demo/trigger?scenario=...` accepts only `baseline`, `process_churn`, `network_exfil`, `kernel`, or `reset`; it requires the `X-IntentX-Demo: 1` header. Unknown scenarios, extra query keys and non-empty request bodies are rejected. No shell or command parameter exists. The header is a same-origin browser safeguard, not user authentication. This remains a local lab presentation interface.

The host telemetry panel reads the existing `/api/v1/telemetry/status` endpoint. It does not attest that real kernel sensors are active. Missing, unavailable or stale telemetry must not be presented as healthy monitoring. Existing uploaded runtime records are historical and may contain old CLI demo data.

For genuine Linux telemetry, use the existing collector/kernel-sensor instructions and explicitly configure fresh sensor files through `INTENTX_TELEMETRY_STATUS`, `INTENTX_LIVE_SCORES`, and `INTENTX_BEHAVIOR_REPORT` where appropriate. Real kernel validation requires the intended Linux host; it was not performed on this macOS test host. Do not point these variables at `runtime/demo`.

The legacy terminal demo still exists, with shared fixture builders. Its synthetic output now goes under `runtime/demo/`, never the root live sensor files. The original `run.sh` is legacy; use `run_soc.sh` for this dashboard presentation.

## Changed files

- `src/intentx/ui/soc.py`: responsive SOC panels, score/threshold visualization, scenario controls, evidence cards, XAI, recommendations, timeline, polling and failure states.
- `src/intentx/ui/dashboard.py`: integrates SOC presentation above the existing operations console and labels historical evidence. Supersedes the old simulated cockpit.
- `src/intentx/behavior/demo.py`: shared predefined fixtures, illustrative explanations and thread-safe bounded demo state; no sensor-file writes.
- `src/intentx/api/app.py`: isolated demo status and restricted trigger routes; existing intent and telemetry APIs preserved.
- `scripts/demo_intrusion_scenario.py`: reuses shared fixture functions; isolates legacy synthetic output in `runtime/demo`.
- `tests/test_soc_demo.py`: allowlist/body/header rejection, evidence isolation, concurrency, reset and attribution tests.
- `run_soc.sh`, `SOC_DEMO.md`, `README.md`: launcher and presentation guidance.

## Verification

Python 3.12; FastAPI 0.141.1; scikit-learn 1.9.1. Full regression results are included in `SOC_TEST_RESULTS.txt`. The suite requires loopback networking for existing workload tests. A Starlette warning recommends its newer httpx2 test adapter; the tests pass using httpx.

```sh
python -m pip install pytest httpx
PYTHONPATH=src python -m pytest -q
```

Browser smoke checks cover scenario controls, score changes, evidence labels, recommendations, reset, and polling. No real attack or privileged kernel operation was run.
