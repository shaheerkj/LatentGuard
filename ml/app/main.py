from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router as api_router
from .auth import require_auth
from .auth_router import router as auth_router
from .consensus import ConsensusMode, decide, get_config
from .models import get_store
from .schemas import HealthResponse, ScoreRequest, ScoreResponse

logger = logging.getLogger("latentguard.ml")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

app = FastAPI(
    title="LatentGuard ML",
    version="0.3.0",
    summary="Scoring + mining + rule-synthesis service for the LatentGuard adaptive WAF",
    description=(
        "Backend for the LatentGuard operator dashboard and the Go reverse-"
        "proxy that fronts the protected web app.\n\n"
        "## Layers\n"
        "- **M4 Autoencoder** + **M5 HDBSCAN** + **M6 Consensus** score every "
        "request the proxy forwards on `/score`.\n"
        "- **M7 Audit log** lives in MongoDB and is the source of truth for "
        "everything below.\n"
        "- **M8 FP-Growth miner** + **M9 rule-synthesis orchestrator** turn "
        "blocked-request patterns into draft Coraza rules; **M10 HITL** lets "
        "an operator approve them, after which they are hot-loaded into the "
        "live ruleset.\n"
        "- **M11 drift watch** flags when AE anomaly scores drift from "
        "baseline.\n\n"
        "## Auth\n"
        "Every `/api/*` route requires a `Bearer <jwt>` header. Obtain one "
        "from `POST /api/auth/login`. Role-gated routes return **403** "
        "(not 401) when the token is valid but the role is wrong, so the "
        "dashboard can show 'no permission' without bouncing to login.\n"
        "Roles: `admin`, `security-operator`, `ml-engineer`, `auditor`.\n\n"
        "## Conventions\n"
        "- Timestamps: ISO-8601 UTC.\n"
        "- Pagination: `limit` + `offset` with a `total` count.\n"
        "- Errors: `{ detail: str }` body with the HTTP status carrying "
        "the verdict.\n"
    ),
    contact={
        "name": "Syed Shaheer Khalid",
        "email": "shaheerkjaffer@gmail.com",
    },
    license_info={"name": "Academic FYP -- see LICENSE"},
    openapi_tags=[
        {"name": "auth", "description": "Login, MFA, user management, brute-force alerts"},
        {"name": "dashboard", "description": "Read-only views for the operator console"},
        {"name": "mining", "description": "FP-Growth pattern mining (M8)"},
        {"name": "rules", "description": "Candidate-rule lifecycle (M9 + M10)"},
        {"name": "models", "description": "Autoencoder / HDBSCAN status, retraining, accuracy, drift"},
        {"name": "siem", "description": "CEF/Syslog forwarder status"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Auth endpoints are UN-protected (login + status); everything else under
# /api/* requires a valid bearer token via the require_auth dependency.
app.include_router(auth_router)
app.include_router(api_router, dependencies=[Depends(require_auth)])


@app.on_event("startup")
def _warmup() -> None:
    """Eagerly load models AND run a throwaway predict so the first real /score
    doesn't pay the keras JIT-compile cost (which can be 1-2 seconds and would
    trip the proxy's 300 ms safe-mode timeout)."""
    try:
        store = get_store()
        store.ensure_loaded()
        # Dummy zero vector through both models. Result is discarded.
        if store.ae_model is not None:
            store.score([0.0] * 7)
            logger.info("model warmup complete")
    except Exception as exc:
        logger.warning("model warmup failed (continuing in degraded mode): %s", exc)

    # RBAC bootstrap: seed the first admin from env if the users
    # collection is empty. Idempotent -- safe across restarts. Done at
    # startup so first /api/auth/login does not race with another worker
    # also trying to bootstrap.
    try:
        from .users import ensure_bootstrap_admin
        ensure_bootstrap_admin()
    except Exception as exc:
        logger.warning("users bootstrap deferred: %s", exc)

    # SI-6 SIEM forwarder: no-op unless SYSLOG_HOST or SIEM_LOG_PATH is set.
    try:
        from . import siem
        siem.start_in_background(asyncio.get_event_loop(), app.version)
    except Exception as exc:
        logger.warning("siem worker not started: %s", exc)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    status = "ok"
    s = get_store()
    if not (s.ae_model and s.hdb_model):
        status = "degraded"
    return HealthResponse(
        status=status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        version=app.version,
    )


@app.post("/score", response_model=ScoreResponse)
def score(request: ScoreRequest) -> ScoreResponse:
    feats = request.features
    vec = [
        float(feats.length),
        float(feats.entropy),
        float(feats.token_count),
        float(feats.special_ratio),
        float(feats.digit_ratio),
        float(feats.uppercase_ratio),
        1.0 if feats.method_is_post else 0.0,
        float(feats.ngram3_entropy),
        float(feats.ngram3_unique_ratio),
        float(feats.ngram4_entropy),
        float(feats.ngram4_unique_ratio),
    ]

    store = get_store()
    ms = store.score(vec)
    cfg = get_config()
    rule_score = float(request.rule_score or 0.0)

    decision = decide(ms.anomaly_score, ms.outlier_score, rule_score, cfg)

    reasons: list[str] = []
    if not ms.autoencoder_loaded:
        reasons.append("autoencoder not loaded - operating without M4 signal")
    if not ms.hdbscan_loaded:
        reasons.append("hdbscan not loaded - operating without M5 signal")
    reasons.extend(ms.notes)
    reasons.extend(decision.reasons)
    if request.rule_matched:
        reasons.append(f"coraza matched: {','.join(request.rule_matched)}")

    return ScoreResponse(
        action=decision.action,
        score=round(decision.score, 4),
        anomaly_score=round(ms.anomaly_score, 4),
        outlier_score=round(ms.outlier_score, 4),
        rule_score=round(rule_score, 4),
        reasons=reasons,
        fallback_used=False,
    )
