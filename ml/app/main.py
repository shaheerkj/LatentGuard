from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router as api_router
from .schemas import HealthResponse, ScoreRequest, ScoreResponse

logger = logging.getLogger("latentguard.ml")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

app = FastAPI(
    title="LatentGuard ML",
    version="0.1.0",
    description="Scoring service for the LatentGuard dual-layer WAF.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version=app.version,
    )


@app.post("/score", response_model=ScoreResponse)
def score(request: ScoreRequest) -> ScoreResponse:
    # Phase 0 stub: always allow with zero scores. M4/M5/M6 wire in here later.
    return ScoreResponse(
        action="allow",
        score=0.0,
        anomaly_score=0.0,
        outlier_score=0.0,
        rule_score=request.rule_score or 0.0,
        reasons=["stub: ML scoring not yet implemented"],
        fallback_used=False,
    )
