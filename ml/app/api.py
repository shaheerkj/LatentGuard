from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

from .consensus import ConsensusConfig, ConsensusMode, get_config, save_config
from .db import requests_collection, rules_collection
from .models import get_store

logger = logging.getLogger("latentguard.ml.api")

router = APIRouter(prefix="/api", tags=["dashboard"])

ML_DIR = Path(__file__).resolve().parents[1]


def _serialize(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    if "_id" in out:
        out["_id"] = str(out["_id"])
    if "timestamp" in out and out["timestamp"] is not None:
        ts = out["timestamp"]
        if hasattr(ts, "isoformat"):
            out["timestamp"] = ts.isoformat()
    return out


@router.get("/metrics")
def get_metrics() -> dict[str, Any]:
    try:
        col = requests_collection()
        total = col.count_documents({})
        blocked = col.count_documents({"final_action": "block"})
        review = col.count_documents({"final_action": "review"})
        allowed = col.count_documents({"final_action": "allow"})
        block_rate = round(blocked / total, 4) if total else 0.0
        # 95th-percentile latency over the last 1000 requests.
        last = list(
            col.find({}, {"latency_ms": 1, "_id": 0})
            .sort("timestamp", -1)
            .limit(1000)
        )
        latencies = sorted(d["latency_ms"] for d in last if "latency_ms" in d)
        p95 = latencies[int(0.95 * (len(latencies) - 1))] if latencies else 0
        return {
            "total_requests": total,
            "blocked": blocked,
            "review": review,
            "allowed": allowed,
            "block_rate": block_rate,
            "p95_latency_ms": p95,
        }
    except PyMongoError as exc:
        logger.warning("metrics: mongo error %s", exc)
        raise HTTPException(status_code=503, detail="storage unavailable") from exc


@router.get("/logs")
def get_logs(
    limit: int = Query(default=50, ge=1, le=500),
    action: str | None = Query(default=None, regex="^(allow|review|block)$"),
) -> list[dict[str, Any]]:
    try:
        col = requests_collection()
        query: dict[str, Any] = {}
        if action:
            query["final_action"] = action
        cursor = col.find(query).sort("timestamp", -1).limit(limit)
        return [_serialize(doc) for doc in cursor]
    except PyMongoError as exc:
        logger.warning("logs: mongo error %s", exc)
        raise HTTPException(status_code=503, detail="storage unavailable") from exc


@router.get("/rules")
def get_rules(status: str | None = Query(default=None)) -> list[dict[str, Any]]:
    try:
        col = rules_collection()
        query: dict[str, Any] = {}
        if status:
            query["status"] = status
        return [_serialize(doc) for doc in col.find(query).sort("created_at", -1).limit(500)]
    except PyMongoError as exc:
        logger.warning("rules: mongo error %s", exc)
        raise HTTPException(status_code=503, detail="storage unavailable") from exc


@router.get("/timeseries")
def get_timeseries(minutes: int = Query(default=60, ge=5, le=1440)) -> dict[str, Any]:
    """Per-minute request counts split by final_action for the dashboard chart."""
    try:
        from datetime import datetime, timedelta, timezone

        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        col = requests_collection()
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}}},
            {
                "$group": {
                    "_id": {
                        "minute": {
                            "$dateTrunc": {"date": "$timestamp", "unit": "minute"}
                        },
                        "action": "$final_action",
                    },
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id.minute": 1}},
        ]
        rows = list(col.aggregate(pipeline))
        series: dict[str, list[dict[str, Any]]] = {"allow": [], "review": [], "block": []}
        for r in rows:
            action = r["_id"]["action"]
            if action in series:
                series[action].append(
                    {"t": r["_id"]["minute"].isoformat(), "n": r["count"]}
                )
        return series
    except PyMongoError as exc:
        logger.warning("timeseries: mongo error %s", exc)
        raise HTTPException(status_code=503, detail="storage unavailable") from exc


class ConsensusConfigPayload(BaseModel):
    mode: Literal["weighted", "majority", "strict"] = "weighted"
    weight_autoencoder: int = Field(ge=0, le=100, default=40)
    weight_hdbscan: int = Field(ge=0, le=100, default=30)
    weight_rule: int = Field(ge=0, le=100, default=30)
    threshold: float = Field(ge=0.0, le=1.0, default=0.65)
    per_model_threshold: float = Field(ge=0.0, le=1.0, default=0.5)


def _config_to_payload(cfg: ConsensusConfig) -> dict[str, Any]:
    return {
        "mode": cfg.mode.value if isinstance(cfg.mode, ConsensusMode) else cfg.mode,
        "weight_autoencoder": cfg.weight_autoencoder,
        "weight_hdbscan": cfg.weight_hdbscan,
        "weight_rule": cfg.weight_rule,
        "threshold": cfg.threshold,
        "per_model_threshold": cfg.per_model_threshold,
    }


@router.get("/consensus/config")
def consensus_config_get() -> dict[str, Any]:
    return _config_to_payload(get_config())


@router.put("/consensus/config")
def consensus_config_put(payload: ConsensusConfigPayload) -> dict[str, Any]:
    cfg = ConsensusConfig(
        mode=ConsensusMode(payload.mode),
        weight_autoencoder=payload.weight_autoencoder,
        weight_hdbscan=payload.weight_hdbscan,
        weight_rule=payload.weight_rule,
        threshold=payload.threshold,
        per_model_threshold=payload.per_model_threshold,
    )
    try:
        save_config(cfg)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="storage unavailable") from exc
    return _config_to_payload(cfg)


@router.get("/models/status")
def models_status() -> dict[str, Any]:
    return get_store().status()


_RETRAIN_MODULES = {
    "autoencoder": "training.train_autoencoder",
    "hdbscan": "training.train_hdbscan",
}


def _run_training(module: str) -> None:
    log_path = ML_DIR / "models" / f"{module.split('.')[-1]}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", module]
    logger.info("retrain: launching %s", " ".join(cmd))
    with open(log_path, "wb") as fp:
        rc = subprocess.call(cmd, cwd=str(ML_DIR), stdout=fp, stderr=subprocess.STDOUT)
    logger.info("retrain: %s exited %d (log: %s)", module, rc, log_path)
    if rc == 0:
        try:
            get_store().reload()
        except Exception as exc:
            logger.warning("retrain: reload failed: %s", exc)


@router.post("/models/retrain")
def models_retrain(
    bg: BackgroundTasks,
    model: Literal["autoencoder", "hdbscan"] = Query(...),
) -> dict[str, Any]:
    module = _RETRAIN_MODULES[model]
    bg.add_task(_run_training, module)
    return {"status": "started", "model": model}
