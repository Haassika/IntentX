# IntentX — System Requirements Specification

## 1. Project Title

**IntentX — AI-Based System Intent Engine for Safe Linux Command Execution**

---

## 2. Purpose

IntentX is an enterprise-style prototype that provides a safety and
decision layer between a user and Linux command execution.

Instead of requiring a user to directly construct and execute shell
commands, IntentX accepts a natural-language request, determines the
user's intended operation, validates the requested operation, evaluates
its potential risk, applies authorization and security policy, explains
the resulting decision, and executes only explicitly permitted
operations through a controlled execution mechanism.

IntentX is designed according to the principle:

> AI may interpret user intent, but deterministic security controls
> retain authority over execution.

---

## 3. Problem Statement

Traditional Linux shells execute commands according to their syntax and
the privileges of the invoking user. They do not independently verify
whether a command accurately represents the user's original intention.

Mistakes involving destructive operations, incorrect targets, elevated
privileges, recursive operations, service management, permissions, or
storage devices may therefore cause unintended system changes.

IntentX introduces an intermediate safety layer that evaluates both
intent and operation before execution.

---

## 4. Target Users

The prototype considers the following user types:

- Linux beginners
- Developers
- System operators
- DevOps/SRE personnel
- System administrators
- Security-conscious enterprise teams

---

## 5. Target Environments

IntentX V1 models three organizational environments:

- DEV
- TEST
- PROD

The same operation may receive different policy treatment depending on
the target environment.

---

## 6. High-Level Processing Pipeline

Natural-language request

→ Intent classification

→ Confidence evaluation

→ Entity extraction

→ Entity validation

→ Controlled operation planning

→ Intent-operation validation

→ System/context collection

→ Risk assessment

→ Policy evaluation

→ Explanation generation

→ ALLOW / REQUIRE_APPROVAL / DENY / CLARIFICATION_REQUIRED

→ Controlled execution where permitted

→ Audit logging

→ Result reporting

---

# 7. Functional Requirements

## FR-01 — Natural-Language Input

The system shall accept a natural-language description of a supported
Linux operation.

Example:

"Show available disk space."

---

## FR-02 — Intent Classification

The system shall classify supported requests into an intent defined in
the IntentX intent catalog.

The initial ML baseline shall use TF-IDF feature extraction and Logistic
Regression.

---

## FR-03 — Confidence Handling

The intent classifier shall expose prediction confidence or an
equivalent decision score.

Requests that do not satisfy the configured confidence policy shall not
continue to executable operation planning.

The system shall return:

CLARIFICATION_REQUIRED

The final confidence threshold shall be selected using experimental
evaluation rather than assumed without evidence.

---

## FR-04 — Out-of-Scope Detection

Requests that cannot be safely mapped to a supported IntentX intent
shall be treated as out of scope.

Out-of-scope requests shall not be executable.

---

## FR-05 — Entity Extraction

The system shall extract entities required by supported intents.

Supported entity types may include:

- PATH
- SOURCE_PATH
- DESTINATION_PATH
- SERVICE
- PID
- PACKAGE
- USERNAME
- PERMISSION
- PORT
- PATTERN
- DEVICE

---

## FR-06 — Entity Validation

Extracted entities shall be validated before being used to construct an
operation.

Invalid, unsupported, malformed, or missing required entities shall
prevent execution.

---

## FR-07 — Controlled Operation Planning

The system shall generate operations from predefined intent/action
definitions.

The AI intent classifier shall not directly generate unrestricted
executable shell strings.

---

## FR-08 — Structured Operation Representation

Before execution, a proposed operation shall be represented
structurally.

The representation should include relevant fields such as:

- intent
- action
- executable
- arguments
- entities
- target
- privilege requirement

Unsupported shell constructs shall not be automatically executable.

---

## FR-09 — Intent-Operation Validation

The system shall verify that the proposed operation is consistent with
the classified intent.

An intent-operation mismatch shall result in DENY.

---

## FR-10 — Risk Assessment

The system shall assign an explainable risk score from 0 to 100.

Risk levels:

- LOW: 0–25
- MEDIUM: 26–50
- HIGH: 51–75
- CRITICAL: 76–100

Risk assessment may consider:

- operation type
- destructive capability
- target sensitivity
- recursive behavior
- force behavior
- privilege requirement
- system modification
- service availability impact
- reversibility
- target environment
- user context
- model confidence

---

## FR-11 — Policy Evaluation

Risk and authorization shall be treated as separate concepts.

Policy evaluation shall consider relevant factors including:

- authenticated role
- requested operation
- target environment
- risk level
- hard safety boundaries

---

## FR-12 — Decision Engine

The system shall support the following decisions:

- ALLOW
- REQUIRE_APPROVAL
- DENY
- CLARIFICATION_REQUIRED

Critical operations shall not be automatically executed.

---

## FR-13 — Explainability

For analyzed requests, the system shall provide a human-readable
explanation containing, where applicable:

- interpreted intent
- model confidence
- extracted entities
- proposed operation
- risk score
- risk level
- contributing risk factors
- applicable policy
- final decision

---

## FR-14 — Safer Alternative

Where appropriate, the system should recommend a lower-risk diagnostic,
reversible, or less disruptive operation.

Example:

Requested:
restart nginx

Possible recommendation:
inspect nginx service status first.

---

## FR-15 — Controlled Execution

Only previously validated and authorized operations may reach the
execution layer.

The execution mechanism shall:

- use approved executable families
- use validated arguments
- avoid unrestricted shell execution
- enforce timeouts
- limit captured output
- follow least-privilege principles
- generate an audit record

---

## FR-16 — Audit Logging

Each analyzed request shall receive a correlation identifier.

The audit system should record:

- timestamp
- correlation ID
- user
- role
- environment
- natural-language request
- model version
- predicted intent
- confidence
- extracted entities
- proposed operation
- validation result
- risk score
- risk factors
- policy decision
- approval state
- execution state
- execution result
- duration

Sensitive information shall not be unnecessarily recorded.

---

## FR-17 — Linux Context

The system may collect relevant read-only Linux context required for
safety analysis.

Examples include:

- current user
- operating system
- kernel
- current working directory
- process state
- service state
- file metadata
- system load

---

## FR-18 — API

The application shall eventually expose backend functionality through a
versioned API.

Analysis and execution shall be separate operations.

An analysis request shall never implicitly execute a Linux operation.

---

## FR-19 — Authentication and Authorization

The enterprise-style prototype shall support role-based access control.

Initial roles:

- VIEWER
- OPERATOR
- SENIOR_OPERATOR
- ADMINISTRATOR

Authorization shall be enforced by the backend rather than only by the
user interface.

---

## FR-20 — User Interface

The final prototype shall provide an interface displaying:

- natural-language request
- target environment/host
- interpreted intent
- confidence
- proposed operation
- risk score
- risk explanation
- policy decision
- safer alternative where available
- approval requirement
- execution result
- audit reference

---

# 8. Non-Functional Requirements

## NFR-01 — Safety

The system shall fail closed when required safety information is
missing, invalid, unsupported, or ambiguous.

---

## NFR-02 — Least Privilege

IntentX components shall operate using the minimum privileges required
for their responsibilities.

---

## NFR-03 — Deterministic Authorization

Probabilistic ML output shall not independently authorize Linux
execution.

---

## NFR-04 — Explainability

Security decisions shall be traceable to identifiable risk and policy
factors.

---

## NFR-05 — Auditability

Important security decisions and execution attempts shall be
traceable through audit records.

---

## NFR-06 — Modularity

ML, entity extraction, planning, validation, risk, policy, execution,
audit, telemetry, and API functionality shall be separated into
independent modules.

---

## NFR-07 — Testability

Security-critical modules shall support automated unit and integration
testing.

---

## NFR-08 — Reproducibility

ML training and evaluation shall use reproducible configurations and
documented datasets.

---

## NFR-09 — Maintainability

Intent definitions and security policies should be configurable without
requiring extensive changes to application source code.

---

## NFR-10 — Performance

Intent analysis and policy evaluation should provide sufficiently low
latency for interactive use.

Actual latency targets shall be established after baseline performance
measurement.

---

# 9. V1 Non-Goals

IntentX V1 will not provide automatic execution of:

- arbitrary Bash scripts
- arbitrary user-supplied shell commands
- unrestricted root shells
- arbitrary command substitution
- unrestricted pipelines
- unrestricted redirection
- arbitrary remote code execution
- unknown executables
- unsupported command combinations

IntentX V1 is not intended to replace:

- Linux kernel security
- sudo
- PAM
- SELinux/AppArmor
- enterprise IAM
- EDR
- SIEM
- production change-management systems

Instead, IntentX is an additional intent-aware safety and decision
layer.

---

# 10. Security Principle

The central security principle of IntentX is:

**AI interprets intent; deterministic controls authorize execution.**

No operation shall be executable solely because an AI or ML component
suggested it.

---

# 11. Prototype Boundary

IntentX V1 is an enterprise-style research prototype.

Development and potentially destructive testing shall occur only in
controlled disposable Linux environments.

The prototype shall not be described as a production-certified
security product.

---

# 12. Completion Criteria

IntentX V1 shall be considered functionally complete when:

1. Supported intents are formally defined.
2. A reproducible intent-classification model is implemented.
3. Unknown and low-confidence requests fail safely.
4. Required entities are extracted and validated.
5. Operations are generated from controlled definitions.
6. Intent-operation alignment is validated.
7. Explainable risk assessment is implemented.
8. Role/environment policy evaluation is implemented.
9. Controlled execution operates in an isolated Linux test environment.
10. Audit records are generated.
11. API functionality is available.
12. A usable demonstration interface is available.
13. Automated tests cover security-critical modules.
14. ML, security, and performance experiments are completed.
15. Dissertation results are generated from actual measured experiments.