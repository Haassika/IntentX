> **Metric interpretation update:** Expand “Understand the metrics and their significance” on the dashboard. See [METRICS_UPDATE.md](METRICS_UPDATE.md) for the guide and XAI corrections.

> **SOC dashboard upgrade:** Start with `bash run_soc.sh` and read [SOC_DEMO.md](SOC_DEMO.md) for the presentation flow, evidence boundaries, changed files and tests.

# IntentX: AI-Powered Explainable Linux Security Assistant

> **AI-Powered Explainable Linux Security Assistant for Kernel-Level Intrusion & Behavioral Threat Detection**

IntentX provides an intent-aware safety and behavioral detection layer for Linux systems. The system bridges natural language administrative requests, deterministic policy enforcement, sandbox execution, real-time security telemetry, and explainable behavioral anomaly detection.

---

## 1. Abstract

Modern Linux systems are continuously exposed to cyber threats such as malware, privilege escalation, unauthorized access, and abnormal process behavior. Traditional security solutions mainly rely on predefined signatures and rules, making them less effective against unknown or zero-day attacks.

**IntentX** introduces an AI-powered Explainable Linux Security Assistant that:
1. **Understands Intent**: Parses natural language administrative operations using trained machine learning classifiers.
2. **Deterministic Safety Controls**: Enforces strict operational boundaries, risk factor scoring, and fail-closed RBAC policies before any command can touch the operating system (*"AI understands the request; deterministic controls decide whether it may execute"*).
3. **Continuous System Telemetry**: Collects normalized Linux metrics including process churn, network socket activity, CPU/memory resource usage, and security events.
4. **Behavioral Anomaly Detection**: Trains unsupervised models (Isolation Forest) on validated baseline normal behavior and detects suspicious system deviations in real time.
5. **Explainable AI (XAI)**: Provides transparent rationale, feature factor contributions, and audit trails to assist system administrators in making informed security decisions.

---

## 2. Architecture & Pipeline

```
User (Natural Language / Web Console / API)
  │
  ▼
Intent Classification & Confidence Assessment (Scikit-Learn ML)
  │
  ▼
Entity Extraction & Canonicalization
  │
  ▼
Deterministic Operation Planner (Command Resolution)
  │
  ▼
Validation & Contract Verification
  │
  ▼
Risk Engine (Blast Radius & Sensitivity Scoring: 0–100)
  │
  ▼
Policy Engine (RBAC & Environment Rules)
  │
  ├──► [ALLOW] ────────┐
  ├──► [REQUIRE_APPROVAL]
  └──► [DENY]
                       │
                       ▼
Controlled Execution Broker (Hardened Subprocess / Container Isolation)
                       │
                       ▼
Real-Time Telemetry & Behavioral Scoring (Isolation Forest Drift Detection)
                       │
                       ▼
Explainable Security Assessment & Audit Trail
```

---

## 3. Project Structure

- `src/intentx/`
  - `analysis/`: Intent classification pipelines and feature tokenizers.
  - `api/`: FastAPI web application endpoints and serialization.
  - `application/`: Application service layer coordinating planning, risk, and execution.
  - `behavior/`: Unsupervised Isolation Forest anomaly detection, baseline datasets, safe benign workloads, and lab deviation generators.
  - `entities/`: Entity extraction and semantic validators.
  - `execution/`: Sandboxed process runners, execution brokers, and audit loggers.
  - `ml/`: Model training scripts and evaluation routines.
  - `persistence/`: Session and audit log storage.
  - `planning/`: Operation planning and executable resolvers.
  - `policy/`: Deterministic RBAC policy engine (`ALLOW`, `REQUIRE_APPROVAL`, `DENY`).
  - `risk/`: Multi-factor risk scoring engine.
  - `security/`: Container isolation constraints and privilege validation.
  - `telemetry/`: Continuous Linux telemetry collection, windowing, and normalizers.
  - `ui/`: Real-time web console and dashboard.
  - `validation/`: Operation contract and input validation pipelines.
- `configs/`: Security policies, intent catalogs, and dataset generation parameters.
- `docs/`: In-depth architectural, mathematical, and security specifications.
- `models/`: Serialized model artifacts (`v1` and `v2`) with metrics.
- `tests/`: Comprehensive test suite (1,400+ unit, integration, and behavioral tests).

---

## 4. Quickstart & Demonstration (No IDE Required)

Anyone with a standard Terminal and Web Browser can run the entire system in **one command**:

```bash
# 1-Command Setup & Interactive Demo Runner
./run.sh
```
Then open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in any web browser.

---

### Demonstrating All Threat Scenarios

The suite includes built-in real-time demonstrations for **all threat and operational cases**:

| Scenario / Case | Command | What It Demonstrates |
| :--- | :--- | :--- |
| **Case 1: Normal Baseline** | `./run.sh --mode baseline` | Shows healthy system telemetry. Dashboard status is **GREEN (`NORMAL`)**, Isolation Forest margin is positive (`+0.086`), 0 mitigations needed. |
| **Case 2: Kernel Rootkit Intrusion** | `./run.sh --mode intrusion --type kernel` | Simulates unauthorized kernel module taint (`0x1000`), ptrace injection, and root privilege escalation. Status turns **RED (`ANOMALOUS`)**, score drops (`-0.742`). |
| **Case 3: Rogue Process Burst** | `./run.sh --mode intrusion --type process_churn` | Simulates fork bombs, rogue cryptominers, and PID exhaustion. XAI highlights `process_event_count (28%)`, `max_process_count (11%)`. |
| **Case 4: Rogue Network Exfiltration** | `./run.sh --mode intrusion --type network_exfil` | Simulates unauthorized reverse shells and listener sockets. XAI highlights `network_connection_count (44%)`. |
| **Case 5: XAI & Mitigation Adoption** | Interactive UI on `http://127.0.0.1:8000/` | View mathematical XAI factor contributions. Click **"Adopt in Console"** to safely plan, evaluate risk (0–100), and execute countermeasures without shell injection. |

For detailed step-by-step presentation scripts and academic defense Q&A, refer to [DEMO_GUIDE.md](file:///Users/apple/Documents/Projects/IntentX/DEMO_GUIDE.md).

---

## 5. Manual Setup & Testing

### Prerequisites
- Python >= 3.11
- Linux or macOS (POSIX compliant)

### Installation
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package and dependencies
pip install -e ".[test]" -r requirements.txt
```

### Running Tests
```bash
pytest -v
```

### Running the Web Console & API
```bash
INTENTX_LIVE_SCORES=runtime/live-scores.json \
INTENTX_TELEMETRY_STATUS=runtime/telemetry-status.json \
INTENTX_BEHAVIOR_REPORT=runtime/behavior-report.json \
uvicorn intentx.api.app:app --host 127.0.0.1 --port 8000
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

---

## 6. Security Principles
- **Fail-Closed**: Any unclassified intent or invalid contract results in rejection.
- **Least Privilege**: Commands execute under dedicated, unprivileged POSIX identities.
- **Zero Shell Invocation**: Operating system commands are executed directly via `execve` parameter lists without shell interpolation (`shell=False`).
- **Separation of Concerns**: Machine learning models never hold execution authority.
