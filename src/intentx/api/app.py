from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    field_validator,
)

from intentx.application.service import (
    ApplicationRequest,
    ApplicationResult,
    IntentXApplicationService,
)
from intentx.ui.dashboard import (
    DASHBOARD_HTML,
)


class IntentRequestModel(BaseModel):
    """
    External HTTP representation of an IntentX request.

    Execution is explicitly opt-in and defaults to
    False. This model does not grant execution
    authority.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    text: str
    role: str
    environment: str
    correlation_id: str
    execute: StrictBool = False
    execution_id: Optional[str] = None

    @field_validator(
        "text",
        "role",
        "environment",
        "correlation_id",
    )
    @classmethod
    def validate_required_string(
        cls,
        value: str,
    ) -> str:
        if not isinstance(value, str):
            raise ValueError(
                "value must be a string"
            )

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "value cannot be empty"
            )

        return cleaned

    @field_validator("execution_id")
    @classmethod
    def validate_execution_id(
        cls,
        value: Optional[str],
    ) -> Optional[str]:
        if value is None:
            return None

        if not isinstance(value, str):
            raise ValueError(
                "execution_id must be a string"
            )

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "execution_id cannot be empty"
            )

        return cleaned


def _serialize_application_result(
    result: ApplicationResult,
) -> Dict[str, Any]:
    """
    Convert the internal immutable application result
    into an HTTP-safe dictionary.

    security_assessment is read-only descriptive
    information. Serialization does not convert it
    into execution authority.

    Serialization has no authorization or execution
    responsibilities.
    """

    payload: Dict[str, Any] = {
        "status": result.status,
        "stage": result.stage,
        "reason": result.reason,
        "executed": result.executed,
        "predicted_intent":
            result.predicted_intent,
        "confidence": result.confidence,
        "missing_entities":
            list(result.missing_entities),
        "plan": None,
        "security_assessment": None,
        "execution_result": None,
    }

    if result.plan is not None:
        payload["plan"] = (
            result.plan.to_dict()
        )

    if (
        result.security_assessment
        is not None
    ):
        payload["security_assessment"] = (
            result.security_assessment.to_dict()
        )

    if result.execution_result is not None:
        execution = result.execution_result

        payload["execution_result"] = {
            "execution_id":
                execution.execution_id,
            "status":
                execution.status,
            "executable":
                execution.executable,
            "arguments":
                list(execution.arguments),
            "return_code":
                execution.return_code,
            "stdout":
                execution.stdout,
            "stderr":
                execution.stderr,
            "stdout_truncated":
                execution.stdout_truncated,
            "stderr_truncated":
                execution.stderr_truncated,
            "reason_code":
                execution.reason_code,
            "reason":
                execution.reason,
            "metadata":
                dict(execution.metadata),
        }

    return payload


def create_app(
    application_service=None,
    *,
    behavior_report_path=None,
    telemetry_status_path=None,
    live_scores_path=None,
) -> FastAPI:
    """
    Build the IntentX HTTP application.

    Security boundary:
        Browser / HTTP
          -> ApplicationRequest
          -> IntentXApplicationService

    The API may serialize read-only deterministic
    security-assessment results produced by the
    application layer.

    The API and dashboard never call ProcessRunner,
    subprocess, policy authorization, or operating-
    system commands directly.
    """

    service = (
        application_service
        or IntentXApplicationService()
    )

    app = FastAPI(
        title="IntentX API",
        version="0.1.0",
        description=(
            "Intent-aware safety layer for "
            "controlled Linux command execution."
        ),
    )

    @app.get(
        "/",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def dashboard() -> HTMLResponse:
        return HTMLResponse(
            content=DASHBOARD_HTML,
            status_code=200,
        )

    configured_report = behavior_report_path or os.getenv("INTENTX_BEHAVIOR_REPORT")

    @app.get("/api/v1/behavior/results")
    def behavioral_results():
        from intentx.behavior.presentation import read_validation_summary, ReportUnavailable
        try:
            return read_validation_summary(configured_report)
        except ReportUnavailable:
            raise HTTPException(status_code=503, detail="Saved behavioral report is unavailable or invalid")

    configured_status = telemetry_status_path or os.getenv("INTENTX_TELEMETRY_STATUS")

    @app.get("/api/v1/telemetry/status")
    def telemetry_status():
        from intentx.telemetry.live_status import read_live_status
        return read_live_status(configured_status)

    configured_scores = live_scores_path or os.getenv("INTENTX_LIVE_SCORES")

    @app.get("/api/v1/behavior/live")
    def live_scores():
        from intentx.behavior.live import read_live_scores
        return read_live_scores(configured_scores)

    @app.get("/api/v1/behavior/explain")
    def behavioral_explanation():
        from datetime import datetime, timezone
        from pathlib import Path
        from intentx.behavior.live import read_live_scores
        from intentx.behavior.explainer import FeatureAttribution, WindowExplanation
        from intentx.behavior.mitigation import MitigationRecommender
        from intentx.telemetry.windowing import BehavioralWindow

        scores = read_live_scores(configured_scores)
        windows = scores.get("windows", [])
        if not windows:
            return {
                "status": "no_data",
                "message": "No live behavioral windows available to explain.",
                "explanation": None,
                "mitigations": [],
            }

        target = next((w for w in reversed(windows) if w.get("flagged")), windows[-1])
        features = target.get("features", {})
        is_anomalous = bool(target.get("flagged", False))
        score = float(target.get("score", 0.0))
        margin = float(target.get("margin", 0.0))

        # 1. Try real model-grounded explainer if model artifact is present
        model_path = Path("runtime/behavior/v2-cohort/validated-model/behavioral_model.joblib")
        if model_path.exists():
            try:
                from intentx.behavior.anomaly import load_behavioral_model
                from intentx.behavior.explainer import BehavioralAnomalyExplainer
                art = load_behavioral_model(model_path)
                explainer = BehavioralAnomalyExplainer(art)
                vec = [float(features.get(k, 0.0)) for k in explainer.feature_names]
                explanation = explainer.explain_vector(
                    vec,
                    hostname=target.get("hostname", "localhost"),
                    score=score,
                    decision_margin=margin,
                    is_anomalous=is_anomalous,
                    window_start=datetime.fromisoformat(target["start_utc"]),
                    window_end=datetime.fromisoformat(target["end_utc"]),
                )
                mitigations = MitigationRecommender.recommend(explanation) if is_anomalous else []
                return {
                    "status": "available",
                    "explanation": explanation.to_dict(),
                    "source_status": scores.get("status", "unknown"),
                    "explanation_method": "model_path_and_reference_distance",
                    "reference_notice": "Reference values are estimated from model tree splits; they are not measured training-set means or standard deviations. Contributions combine path weights and absolute reference distance, not causal SHAP values.",
                    "mitigations": [m.to_dict() for m in mitigations],
                }
            except Exception:
                pass

        # 2. Resilient fallback calculation
        names = BehavioralWindow.FEATURE_NAMES_V2
        attrs = []
        total_dev = 0.0
        z_scores = []
        for name in names:
            val = float(features.get(name, 0.0))
            z = max(0.0, val - 1.0)
            z_scores.append(z)
            total_dev += z

        for idx, name in enumerate(names):
            val = float(features.get(name, 0.0))
            z = z_scores[idx]
            attr = z / total_dev if total_dev > 0 else 1.0 / len(names)
            desc = (
                f"{name.replace('_', ' ')} is elevated ({val:.2f})"
                if z > 1.0
                else f"{name.replace('_', ' ')} is normal ({val:.2f})"
            )
            attrs.append(
                FeatureAttribution(
                    feature_name=name,
                    observed_value=val,
                    baseline_mean=1.0,
                    baseline_std=1.0,
                    deviation_zscore=z,
                    attribution_score=attr,
                    contribution_percentage=attr * 100.0,
                    description=desc,
                )
            )

        ranked = sorted(attrs, key=lambda a: a.attribution_score, reverse=True)
        primary = tuple(ranked[:4])
        summary = (
            f"Window flagged as ANOMALOUS (score: {score:.4f}, margin: {margin:+.4f}). Primary factors: "
            + ", ".join(f"{f.feature_name} ({f.contribution_percentage:.1f}%)" for f in primary[:3])
            if is_anomalous
            else f"Window classified as NORMAL (score: {score:.4f}, margin: {margin:+.4f}). Indicators within baseline."
        )

        explanation = WindowExplanation(
            hostname=target.get("hostname", "localhost"),
            window_start=datetime.fromisoformat(target["start_utc"]),
            window_end=datetime.fromisoformat(target["end_utc"]),
            is_anomalous=is_anomalous,
            score=score,
            decision_margin=margin,
            summary=summary,
            primary_factors=primary,
            all_attributions=tuple(attrs),
        )

        mitigations = MitigationRecommender.recommend(explanation) if is_anomalous else []

        return {
            "status": "available",
            "explanation": explanation.to_dict(),
            "source_status": scores.get("status", "unknown"),
            "explanation_method": "illustrative_fallback",
            "reference_notice": "Model explanation unavailable. This fallback assumes reference mean and scale of 1; treat contributions as illustrative, not a learned or causal explanation.",
            "mitigations": [m.to_dict() for m in mitigations],
        }

    @app.get("/api/v1/behavior/mitigations")
    def behavioral_mitigations():
        data = behavioral_explanation()
        return {
            "status": data.get("status", "unknown"),
            "mitigations": data.get("mitigations", []),
        }

    from intentx.behavior.demo import DemoController
    demo = DemoController()

    @app.get("/api/v1/demo/status")
    def demo_status():
        return demo.snapshot()

    @app.post("/api/v1/demo/trigger")
    def trigger_demo_scenario(request: Request, scenario: str = "baseline") -> Dict[str, Any]:
        # A custom header prevents cross-origin form submissions; no CORS enabled.
        if request.headers.get("x-intentx-demo") != "1":
            raise HTTPException(status_code=403, detail="Use the same-origin demo controller")
        if set(request.query_params) - {"scenario"} or request.headers.get("content-length", "0") != "0":
            raise HTTPException(status_code=400, detail="Only a predefined scenario is accepted")
        try:
            return demo.trigger(scenario)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {
            "status": "ok",
            "service": "intentx",
        }

    @app.post("/api/v1/intent")
    def process_intent(
        body: IntentRequestModel,
    ) -> Dict[str, Any]:
        try:
            request = ApplicationRequest(
                text=body.text,
                role=body.role,
                environment=body.environment,
                correlation_id=(
                    body.correlation_id
                ),
                execute=body.execute,
                execution_id=body.execution_id,
            )

            result = service.handle(request)

        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc

        payload = _serialize_application_result(result)
        if result.status == "CLARIFICATION_REQUIRED":
            from intentx.ui.clarification import clarification_help
            payload["clarification"] = clarification_help(
                body.text, missing_entities=result.missing_entities
            )
        return payload

    return app


app = create_app()