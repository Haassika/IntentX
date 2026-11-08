# IntentX — System Architecture

## 1. Architecture Goal

IntentX provides an intent-aware safety layer between a user and a
Linux operating system.

The architecture deliberately separates AI-based interpretation from
security-sensitive authorization and execution.

The fundamental principle is:

**AI understands the request. Deterministic controls decide whether it
may execute.**

---

## 2. High-Level Architecture

User
  |
  v
User Interface / API
  |
  v
Natural-Language Request
  |
  v
Intent Classification
  |
  +----> Confidence Evaluation
  |
  v
Entity Extraction
  |
  v
Entity Validation
  |
  v
Operation Planner
  |
  v
Intent-Operation Validator
  |
  v
Context Collector
  |
  v
Risk Assessment Engine
  |
  v
Policy Engine
  |
  +-------------------------------+
  |               |               |
  v               v               v
ALLOW        REQUIRE_APPROVAL     DENY
  |               |
  |               v
  |          Approval Workflow
  |               |
  +---------------+
          |
          v
Controlled Execution Broker
          |
          v
Isolated Linux Environment
          |
          v
Execution Result

All important stages
          |
          v
Audit & Logging System

---

## 3. Layer 1 — User Interface / API

The user submits a natural-language request.

Example:

"Restart nginx."

The interface does not execute commands directly.

Its responsibility is to collect the request and send it to the
backend analysis pipeline.

---

## 4. Layer 2 — Intent Classification

The NLP/ML component determines what the user is attempting to do.

Example:

Input:
"Restart nginx"

Output:

intent = service_management

The initial baseline model uses:

- TF-IDF
- Logistic Regression

The model also produces a confidence value.

ML classification does not grant execution permission.

---

## 5. Layer 3 — Entity Extraction

IntentX identifies important parameters from the request.

Example:

Input:
"Restart nginx"

Output:

intent = service_management
action = restart
SERVICE = nginx

Another example:

"Stop process 4321"

produces:

intent = process_termination
action = terminate
PID = 4321

---

## 6. Layer 4 — Entity Validation

Extracted entities are treated as untrusted input.

They must be checked before they are used.

Examples include validating:

- paths
- process identifiers
- service names
- package names
- permission values
- device identifiers

Missing required entities may cause:

CLARIFICATION_REQUIRED

Invalid entities may cause:

DENY

---

## 7. Layer 5 — Operation Planner

The planner converts a validated intent and validated entities into a
controlled structured operation.

Example:

intent:
service_management

action:
restart

entity:
SERVICE = nginx

may become conceptually:

StructuredOperation(
    executable="systemctl",
    arguments=["restart", "nginx"]
)

The planner does not accept unrestricted shell text as an executable
operation.

---

## 8. Layer 6 — Intent-Operation Validation

IntentX verifies that the proposed operation belongs to the classified
intent.

Example:

Predicted intent:
storage_inspection

Proposed executable:
rm

Result:

DENY

The proposed executable does not belong to the allowed executable
family for storage inspection.

---

## 9. Layer 7 — Context Collection

Relevant system context may be collected before risk evaluation.

Examples:

- DEV / TEST / PROD environment
- current user
- current directory
- file metadata
- process state
- service state
- privilege requirements
- operating system information

Context is collected only when required for analysis.

---

## 10. Layer 8 — Risk Assessment Engine

The risk engine estimates the potential impact of the proposed
operation.

Risk score:

0–100

Risk levels:

LOW
MEDIUM
HIGH
CRITICAL

Risk factors may include:

- destructive behavior
- privilege requirement
- recursive behavior
- forced execution
- sensitive target
- service interruption
- reversibility
- environment
- system modification

The risk engine also produces human-readable reasons.

---

## 11. Layer 9 — Policy Engine

The policy engine answers:

"Is this operation permitted for this user in this environment under
the configured security policy?"

Policy inputs may include:

- user role
- environment
- intent
- operation
- risk level
- hard safety boundaries

Possible decisions:

ALLOW

REQUIRE_APPROVAL

DENY

CLARIFICATION_REQUIRED

---

## 12. Layer 10 — Approval Workflow

Operations requiring approval shall not execute until the required
approval state has been satisfied.

Analysis and approval are separate from execution.

---

## 13. Layer 11 — Controlled Execution Broker

Only approved structured operations may reach the execution broker.

The broker shall:

- verify authorization again
- use an approved executable
- use validated arguments
- avoid unrestricted shell execution
- enforce timeout limits
- limit output
- record execution results

Execution testing shall occur in an isolated Linux environment.

---

## 14. Layer 12 — Audit System

The audit system records security-relevant events.

Examples:

- request received
- intent predicted
- entities extracted
- validation performed
- risk calculated
- policy decision made
- approval recorded
- execution attempted
- execution completed

A correlation ID links events belonging to the same request.

---

## 15. Configuration Layer

IntentX uses configuration files to separate policy from application
logic.

intent_catalog.yaml
defines supported intent families and operation characteristics.

security_policy.yaml
defines safety and authorization behavior.

---

## 16. ML Training Architecture

Training is separate from runtime execution.

Training flow:

Dataset
  |
  v
Data Validation
  |
  v
Train / Validation / Test Split
  |
  v
TF-IDF Feature Extraction
  |
  v
Logistic Regression Training
  |
  v
Evaluation
  |
  v
Versioned Model Artifact

The runtime application loads an approved model artifact.

The runtime application does not retrain itself from arbitrary user
requests.

---

## 17. Deployment Model

Development architecture:

macOS Development Machine
        |
        +---- VS Code
        |
        +---- Python Development Environment
        |
        +---- Git
        |
        v
IntentX Application
        |
        v
Isolated Linux Container / VM
        |
        v
Controlled Linux Test Environment

Potentially destructive testing shall not target the developer's
primary macOS environment.

---

## 18. Future Enterprise Deployment

A future production architecture could separate:

- web frontend
- API service
- ML inference service
- policy service
- approval service
- execution agents
- audit storage
- identity provider
- monitoring system

Execution agents could be deployed close to managed Linux systems while
central services provide policy and governance.

This architecture is future work and is not claimed as implemented in
IntentX V1.