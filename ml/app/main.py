from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router as api_router
from .consensus import ConsensusMode, decide, get_config
from .models import get_store
from .schemas import HealthResponse, ScoreRequest, ScoreResponse

logger = logging.getLogger("latentguard.ml")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

app = FastAPI(
    title="LatentGuard ML",
    version="0.2.0",
    description="Scoring service for the LatentGuard dual-layer WAF.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)

app.include_router(api_router)


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
