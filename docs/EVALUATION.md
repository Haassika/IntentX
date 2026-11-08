# IntentX Evaluation

## 1. Evaluation Purpose

This document records the final empirical evaluation of IntentX.

The evaluation considers two complementary aspects:

1. machine-learning intent classification performance; and
2. deterministic security and controlled-execution behaviour.

The purpose is not to claim that IntentX is universally secure or that
the machine-learning classifier is always correct. Instead, the evaluation
measures the implemented system against the defined dataset, automated
security tests, and controlled Linux execution scenarios.

---

## 2. Machine-Learning Evaluation

### 2.1 Evaluation Protocol

The IntentX V2 classifier uses a combination of word-level and
character-level TF-IDF features with multinomial classification implemented
using Logistic Regression.

The dataset was separated into:

| Partition | Examples | Purpose |
|---|---:|---|
| Training | 1089 | Model fitting |
| Validation | 241 | Model selection and confidence analysis |
| Test | 241 | Final held-out evaluation |

The final V2 model was fitted using the training partition.

The validation partition was used during model development and model
selection. The test partition was reserved for the final held-out
evaluation and was not used to retrain or tune the final V2 model.

The final test partition contains all 21 IntentX intent classes.

### 2.2 Template-Separated Evaluation

Generated template families were deliberately separated to reduce
template leakage between training and evaluation data.

Observed unique generated template families:

| Partition | Unique generated template families |
|---|---:|
| Training | 189 |
| Validation | 40 |
| Test | 40 |

Observed overlap:

| Comparison | Overlapping generated templates |
|---|---:|
| Training vs Validation | 0 |
| Training vs Test | 0 |
| Validation vs Test | 1 |
| Present in all three | 0 |

The single validation-to-test overlap was:

`remove {value}`

Most importantly, there was zero generated-template-family overlap between
the training and final test partitions. Therefore, the final test result
measures generalisation to generated language patterns not present in the
training partition rather than simple memorisation of identical templates.

### 2.3 Final Held-Out Test Performance

The frozen V2 classifier was evaluated once against the 241-example
held-out test partition.

| Metric | Result |
|---|---:|
| Accuracy | 0.9336 |
| Macro F1 | 0.9247 |
| Weighted F1 | 0.9199 |
| Correct predictions | 225 |
| Misclassifications | 16 |

The validation and final test results were:

| Metric | Validation | Held-out test |
|---|---:|---:|
| Accuracy | 0.8423 | 0.9336 |
| Macro F1 | 0.8432 | 0.9247 |
| Weighted F1 | 0.8448 | 0.9199 |

The higher test score does not indicate that the model improved after
validation. The model remained unchanged. The difference reflects the
properties of the respective evaluation partitions.

### 2.4 Per-Intent Test Performance

| Intent | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| disk_management | 1.000 | 1.000 | 1.000 | 5 |
| file_copy | 1.000 | 1.000 | 1.000 | 17 |
| file_create | 0.941 | 1.000 | 0.970 | 16 |
| file_delete | 0.941 | 1.000 | 0.970 | 16 |
| file_listing | 1.000 | 1.000 | 1.000 | 16 |
| file_move | 0.556 | 1.000 | 0.714 | 15 |
| file_read | 1.000 | 1.000 | 1.000 | 15 |
| file_search | 1.000 | 1.000 | 1.000 | 10 |
| memory_inspection | 1.000 | 1.000 | 1.000 | 2 |
| network_inspection | 1.000 | 1.000 | 1.000 | 4 |
| out_of_scope | 0.750 | 0.750 | 0.750 | 4 |
| package_management | 1.000 | 0.933 | 0.966 | 15 |
| permission_change | 1.000 | 0.133 | 0.235 | 15 |
| process_inspection | 1.000 | 1.000 | 1.000 | 11 |
| process_termination | 1.000 | 1.000 | 1.000 | 15 |
| service_inspection | 1.000 | 1.000 | 1.000 | 16 |
| service_management | 1.000 | 1.000 | 1.000 | 15 |
| storage_inspection | 0.917 | 1.000 | 0.957 | 11 |
| system_information | 1.000 | 0.750 | 0.857 | 4 |
| system_power | 1.000 | 1.000 | 1.000 | 2 |
| text_search | 1.000 | 1.000 | 1.000 | 17 |

Per-class results with very small support, particularly classes containing
only two to five test examples, should be interpreted cautiously.

### 2.5 Error Analysis

Sixteen test examples were misclassified.

The dominant confusion was:

`permission_change -> file_move`

This occurred 12 times.

The test partition contains 13 generated permission-change examples using
the previously unseen template:

`chmod {path} to {permission}`

The training partition instead contains permission-change expressions such
as:

- `make {path} permission {permission}`
- `set permissions on {path} to {permission}`
- ownership-related natural-language templates.

This indicates a generalisation weakness around the Linux-specific `chmod`
wording rather than uniform classification failure across the intent set.

Other observed errors included:

- `make script.sh executable`: permission_change -> file_create
- `remove nginx`: package_management -> file_delete
- `how do I cook pasta`: out_of_scope -> storage_inspection
- `show machine name`: system_information -> out_of_scope

These errors demonstrate why ML classification is treated as an
interpretation mechanism rather than an execution-authorisation mechanism.

---

## 3. Confidence-Gated Classification

### 3.1 Confidence Behaviour

Average confidence on the held-out test set was:

| Prediction outcome | Average confidence |
|---|---:|
| Correct | 0.6104 |
| Incorrect | 0.2211 |

### 3.2 Selective Classification

Observed behaviour at different confidence thresholds:

| Threshold | Coverage | Accepted | Selective accuracy |
|---:|---:|---:|---:|
| 0.00 | 100.00% | 241 | 93.36% |
| 0.40 | 77.59% | 187 | 99.47% |
| 0.50 | 67.63% | 163 | 100.00% |
| 0.60 | 46.06% | 111 | 100.00% |
| 0.70 | 35.27% | 85 | 100.00% |
| 0.80 | 19.92% | 48 | 100.00% |
| 0.90 | 3.32% | 8 | 100.00% |

At the preselected confidence threshold of 0.50:

| Outcome | Count |
|---|---:|
| Total test examples | 241 |
| Accepted | 163 |
| Rejected / abstained | 78 |
| Correct accepted | 163 |
| Incorrect accepted | 0 |
| Correct rejected | 62 |
| Incorrect rejected | 16 |

This corresponds to:

- 67.63% coverage;
- 100.00% observed selective accuracy;
- 100.00% observed error rejection; and
- 27.56% rejection of otherwise correct predictions.

These values describe the held-out evaluation dataset only. They do not
guarantee that every future prediction above a confidence of 0.50 will be
correct.

The result demonstrates the trade-off introduced by abstention: accepting
fewer requests can improve observed classification reliability, but some
correct predictions are also rejected.

---

## 4. Security Evaluation

### 4.1 Automated Security-Focused Tests

A security-focused subset of the automated IntentX test suite was
identified across validation, risk, policy, execution, audit, API, and
container boundaries.

Collected security-focused test cases: 799

Observed execution result:

| Result | Count |
|---|---:|
| Passed | 799 |
| Failed | 0 |
| Warnings | 1 |

Execution time: 9.18 seconds.

The warning was a Starlette/AnyIO `BlockingPortal` deprecation warning and
was not a security-test failure.

### 4.2 Evaluated Security Properties

| Security property | Threat | Implemented control | Observed result |
|---|---|---|---|
| Structured execution | Shell interpretation/injection | Structured argv and `shell=False` | Passed |
| Executable restriction | Executable/PATH substitution | Trusted executable resolver and canonical path validation | Passed |
| Plan integrity | Tampered operation plan | Independent operation revalidation | Passed |
| Risk integrity | Forged risk information | Policy independently recomputes risk | Passed |
| RBAC | Unauthorized operation | Deterministic role/category policy | Passed |
| Approval boundary | Approval requirement treated as execution authority | Non-ALLOW decisions cannot execute | Passed |
| Hard safety boundary | Critical destructive operation | Deterministic hard-boundary DENY | Passed |
| Audit-before-execution | Unrecorded process launch | Mandatory attempted-event prewrite | Passed |
| Audit failure | Execution despite unavailable audit | Fail closed before process launch | Passed |
| Environment isolation | Parent environment/PATH manipulation | Fixed runtime environment with no parent inheritance | Passed |
| Timeout control | Hanging process | Runtime timeout and termination handling | Passed |
| Output control | Excessive stdout/stderr | Bounded output collection | Passed |
| Container privilege | Root/privileged runtime | Non-root container and hardened runtime options | Passed in evaluated configuration |

### 4.3 Security Test Evidence

The automated tests include explicit checks for:

- rejection of non-allowlisted executables;
- rejection of privilege metadata mismatch;
- validation not being treated as authorisation;
- tampered risk score, level, and factors;
- hard safety boundary precedence;
- unknown roles and environments;
- trusted executable directory validation;
- path traversal and symlink escape rejection;
- parent `PATH` not controlling executable resolution;
- tampered-plan revalidation before the process boundary;
- `REQUIRE_APPROVAL` not being execution authority;
- audit prewrite occurring before runner invocation;
- audit-prewrite failure blocking process launch;
- timeout and terminal audit handling;
- disabled shell mode;
- fixed process environment;
- exclusion of untrusted PATH locations;
- absence of sensitive process-influencing environment variables;
- bounded stdout and stderr;
- literal handling of shell metacharacters;
- structured arguments without shell parsing;
- no inherited parent stdin;
- creation of a separate process session;
- timeout escalation;
- non-root container runtime;
- absence of `sudo`;
- absence of privileged Docker execution configuration; and
- no shell wrapper in the container command.

---

## 5. Controlled Linux Runtime Evaluation

Automated unit and integration tests were complemented by controlled
execution inside a disposable Linux Docker environment.

The container was run as a non-root user with hardened runtime options,
including dropped capabilities and `no-new-privileges`.

No Docker socket, privileged mode, host PID namespace, or unnecessary host
filesystem mount was provided.

### 5.1 Authorized Safe Operation

Request:

`show memory usage`

Context:

- Role: VIEWER
- Environment: DEV
- Execution requested: true

Observed pipeline:

1. classified as `memory_inspection`;
2. operation planned as `free -h`;
3. operation validation succeeded;
4. deterministic risk score was 0 / LOW;
5. deterministic policy decision was ALLOW;
6. executable resolved to `/usr/bin/free`;
7. execution-attempt audit event was written;
8. process executed with controlled runtime settings; and
9. execution-completed audit event was written.

Observed return code: 0.

### 5.2 RBAC Denial

Request:

`kill process 1234`

Context:

- Role: VIEWER
- Environment: DEV
- Execution requested: true

The operation was independently validated and assessed as MEDIUM risk, but
policy returned DENY because the VIEWER role was not permitted to perform
the administration-category operation.

Observed result:

- status: BLOCKED;
- return code: none;
- audit event: `EXECUTION_BLOCKED`;
- reason: `ROLE_CATEGORY_NOT_ALLOWED`.

No execution-attempt or execution-completed event was produced for this
request.

### 5.3 Hard Safety Boundary

Request:

`format device /dev/fake-intentx-test`

Context:

- Role: ADMINISTRATOR
- Environment: DEV
- Execution requested: true

The operation was planned as a critical disk-management operation and
received a CRITICAL risk score of 100.

Policy returned DENY due to the `destructive_disk_operation` hard safety
boundary despite the ADMINISTRATOR role.

Observed result:

- status: BLOCKED;
- return code: none;
- reason: `HARD_SAFETY_BOUNDARY`;
- audit event: `EXECUTION_BLOCKED`.

The `mkfs` operation was never manually executed.

---

## 6. Security Architecture Interpretation

The evaluation supports the architectural principle:

> AI interprets intent; deterministic controls authorize execution.

The ML classifier does not grant execution authority.

A high-confidence intent prediction is therefore insufficient by itself to
launch a process. Execution requires the request to pass deterministic
operation validation, risk assessment, policy/RBAC evaluation, trusted
executable resolution, and the mandatory audit boundary.

Similarly, the read-only security assessment shown by the application/UI
is descriptive and is not execution authority. Any real execution request
must independently pass through the ExecutionBroker.

---

## 7. Limitations and Residual Risk

The evaluation demonstrates behaviour under the implemented automated test
suite and controlled runtime scenarios. It does not prove universal system
security.

Known or relevant limitations include:

1. The ML evaluation dataset is relatively small and several intent classes
   have low test support.

2. Generated examples form a substantial proportion of the dataset.
   Performance on broader real-world language may differ.

3. The `permission_change` results demonstrate a generalisation weakness
   for unseen Linux-specific wording such as `chmod`.

4. Confidence-threshold results are empirical observations on the held-out
   dataset and must not be interpreted as probabilistic guarantees.

5. Executable validation and process creation retain a residual filesystem
   time-of-check/time-of-use risk.

6. Process-output collector handling could be further hardened against
   unusual descendant processes retaining inherited pipe descriptors.

7. Container dependency and base-image reproducibility could be improved
   through stronger version/digest pinning.

8. Automated container tests primarily validate configuration invariants;
   the controlled Linux runtime evaluation covers a smaller set of actual
   execution scenarios.

9. Additional adversarial, fuzz, concurrency, and long-duration testing
   would provide further assurance.

---

## 8. Evaluation Summary

The final held-out V2 intent classifier achieved:

- 93.36% accuracy;
- 92.47% macro F1; and
- 91.99% weighted F1.

At the preselected confidence threshold of 0.50, the held-out evaluation
showed:

- 67.63% coverage;
- 100% observed selective accuracy; and
- rejection of all 16 observed classification errors.

Security evaluation included 799 security-focused automated test cases,
all of which passed, together with controlled Linux runtime scenarios
demonstrating both authorized safe execution and deterministic blocking of
unauthorized or hard-boundary operations.

These results support the design objective of combining probabilistic
natural-language interpretation with deterministic safety controls rather
than relying on ML predictions as execution authority.
