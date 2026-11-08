# Clarification help update

When an intent request returns CLARIFICATION_REQUIRED, the dashboard now shows related curated examples, missing entity details and a supported-example browser. Selecting an example only fills the input. It clears prior execution readiness and requires a new Analyze Request action. Suggested requests do not override classifier confidence, validation, role, risk or execution checks. File-creation examples are labeled state-changing and use explicit disposable demo paths.

Changed: src/intentx/ui/clarification.py, src/intentx/ui/dashboard.py, src/intentx/api/app.py, tests/test_clarification_help.py.

Validation: 1,440 regression tests passed. All curated suggestions were checked against the shipped analysis model without execution. Browser verified that unclear input shows suggestions and selecting one keeps Execute Safely disabled.

For Windows, extract this updated project and rebuild the Docker image using its Dockerfile; a running container built from the previous ZIP will not automatically receive these changes. Preserve existing volumes and report files, then recreate the dashboard container with the same configured mounts and environment settings. See the presentation guide for the connected collector setup; create /app/runtime/behavior/v2-cohort/validated-model inside the collector volume before mounting the model beneath a read-only dashboard volume.
