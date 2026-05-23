from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

from .consensus import ConsensusConfig, ConsensusMode, get_config, save_config
from .db import requests_collection, rules_collection
from .mining import MinerConfig, mine_patterns
from .models import get_store
from .rulegen import (
    RuleStatus,
    approve_rule,
    delete_rule,
    edit_rule,
    expire_rule,
    generate_candidates,
    get_rule,
    list_rules,
    reject_rule,
)
from .rulegen.promoter import promote_approved, remove_expired

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
    offset: int = Query(default=0, ge=0),
    action: str | None = Query(default=None, regex="^(allow|block)$"),
    method: str | None = Query(default=None, regex="^[A-Z]{3,7}$"),
    source_ip: str | None = Query(default=None, max_length=64),
    path_contains: str | None = Query(default=None, max_length=200),
    request_id: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    """Paginated, filterable audit-log slice.

    Returns ``{rows, total, offset, limit, has_more}``. ``rows`` lists
    timestamp-descending records matching every supplied filter; ``total``
    is the unpaginated match count so the dashboard can render "N-M of K".
    Backwards-compat: callers that previously got a bare list now get a
    dict; the dashboard handles both shapes.
    """
    try:
        col = requests_collection()
        query: dict[str, Any] = {}
        if action:
            query["final_action"] = action
        if method:
            query["method"] = method.upper()
        if source_ip:
            query["source_ip"] = source_ip
        if request_id:
            query["request_id"] = request_id
        if path_contains:
            # Escape regex specials so user input is a literal substring.
            import re

            query["path"] = {"$regex": re.escape(path_contains), "$options": "i"}

        total = col.count_documents(query)
        cursor = col.find(query).sort("timestamp", -1).skip(offset).limit(limit)
        rows = [_serialize(doc) for doc in cursor]
        return {
            "rows": rows,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(rows) < total,
        }
    except PyMongoError as exc:
        logger.warning("logs: mongo error %s", exc)
        raise HTTPException(status_code=503, detail="storage unavailable") from exc


@router.get("/logs/{request_id}")
def get_log_detail(request_id: str) -> dict[str, Any]:
    """Single full audit record by request_id. Returns 404 if missing."""
    try:
        col = requests_collection()
        doc = col.find_one({"request_id": request_id})
        if not doc:
            raise HTTPException(status_code=404, detail="request_id not found")
        return _serialize(doc)
    except PyMongoError as exc:
        logger.warning("logs/detail: mongo error %s", exc)
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
        series: dict[str, list[dict[str, Any]]] = {"allow": [], "block": []}
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


# ---------------------------------------------------------------------------
# M8 + M9: mining + candidate-rule synthesis
# ---------------------------------------------------------------------------


class MineRequest(BaseModel):
    min_support: float = Field(default=0.05, ge=0.001, le=1.0)
    min_itemset_len: int = Field(default=2, ge=1, le=8)
    max_itemset_len: int = Field(default=4, ge=1, le=8)
    lookback_hours: int = Field(default=168, ge=1, le=24 * 60)
    max_transactions: int = Field(default=20000, ge=10, le=200000)
    only_blocked: bool = True
    emit_candidates: bool = True
    provider: str | None = None  # stub|openai|anthropic; defaults to LLM_PROVIDER env


@router.post("/mining/run")
def mining_run(req: MineRequest) -> dict[str, Any]:
    cfg = MinerConfig(
        min_support=req.min_support,
        min_itemset_len=req.min_itemset_len,
        max_itemset_len=req.max_itemset_len,
        lookback_hours=req.lookback_hours,
        max_transactions=req.max_transactions,
        only_blocked=req.only_blocked,
    )
    try:
        result = mine_patterns(requests_collection(), cfg)
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=f"storage error: {exc}") from exc
    if req.emit_candidates and result.get("patterns"):
        try:
            result["synthesis"] = generate_candidates(
                result["patterns"], provider=req.provider
            )
        except PyMongoError as exc:
            raise HTTPException(status_code=503, detail=f"storage error: {exc}") from exc
    return result


# ---------------------------------------------------------------------------
# M10: candidate rule queue (approve / reject / edit / expire / promote)
# ---------------------------------------------------------------------------


def _rule_to_payload(doc: dict[str, Any]) -> dict[str, Any]:
    return _serialize(doc)


@router.get("/rules/candidates")
def rules_candidates_list(
    status: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    if status and status not in RuleStatus.ALL:
        raise HTTPException(status_code=400, detail=f"unknown status {status!r}")
    try:
        rows = list_rules(status=status, limit=limit)
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="storage unavailable") from exc
    return {
        "rows": [_rule_to_payload(r) for r in rows],
        "total": len(rows),
        "statuses": RuleStatus.ALL,
    }


@router.get("/rules/candidates/{rule_id}")
def rules_candidates_get(rule_id: int) -> dict[str, Any]:
    doc = get_rule(rule_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="rule_id not found")
    return _rule_to_payload(doc)


class TransitionPayload(BaseModel):
    note: str | None = None


@router.post("/rules/candidates/{rule_id}/approve")
def rules_candidates_approve(
    rule_id: int, payload: TransitionPayload, request: Request
) -> dict[str, Any]:
    actor = _request_actor(request)
    try:
        doc = approve_rule(rule_id, actor=actor, note=payload.note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    promote = promote_approved()
    return {"rule": _rule_to_payload(get_rule(rule_id) or doc), "promote": promote}


@router.post("/rules/candidates/{rule_id}/reject")
def rules_candidates_reject(
    rule_id: int, payload: TransitionPayload, request: Request
) -> dict[str, Any]:
    actor = _request_actor(request)
    try:
        doc = reject_rule(rule_id, actor=actor, note=payload.note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _rule_to_payload(doc)


@router.post("/rules/candidates/{rule_id}/expire")
def rules_candidates_expire(
    rule_id: int, payload: TransitionPayload, request: Request
) -> dict[str, Any]:
    actor = _request_actor(request)
    try:
        doc = expire_rule(rule_id, actor=actor, note=payload.note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    sync = remove_expired()
    return {"rule": _rule_to_payload(get_rule(rule_id) or doc), "sync": sync}


class EditPayload(BaseModel):
    rule_text: str | None = None
    message: str | None = None
    notes: str | None = None


@router.put("/rules/candidates/{rule_id}")
def rules_candidates_edit(
    rule_id: int, payload: EditPayload, request: Request
) -> dict[str, Any]:
    actor = _request_actor(request)
    try:
        doc = edit_rule(
            rule_id,
            actor=actor,
            rule_text=payload.rule_text,
            message=payload.message,
            notes=payload.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _rule_to_payload(doc)


@router.delete("/rules/candidates/{rule_id}")
def rules_candidates_delete(rule_id: int) -> dict[str, Any]:
    if not delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="rule_id not found")
    sync = remove_expired()
    return {"deleted": rule_id, "sync": sync}


def _request_actor(request: Request) -> str:
    """Pull the username from require_auth's request.state.user."""
    user = getattr(request.state, "user", None)
    return str(user) if user else "unknown"


# ---------------------------------------------------------------------------
# M11 (partial): autoencoder drift watch
# ---------------------------------------------------------------------------


@router.get("/models/drift")
def models_drift(
    window_min: int = Query(default=60, ge=5, le=1440),
    baseline_min: int = Query(default=24 * 60, ge=60, le=14 * 24 * 60),
    z_threshold: float = Query(default=2.0, ge=0.5, le=10.0),
) -> dict[str, Any]:
    """Reconstruction-error drift: compare last `window_min` to baseline window.

    Baseline is the slice [now - baseline_min - window_min, now - window_min)
    so the two windows do not overlap. z = (window_mean - baseline_mean) /
    baseline_std. drift_detected when |z| >= z_threshold AND we have enough
    samples (>=30) in both windows -- below that the stats are noise.
    """
    try:
        from datetime import datetime, timedelta, timezone
        import math

        col = requests_collection()
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=window_min)
        baseline_end = window_start
        baseline_start = baseline_end - timedelta(minutes=baseline_min)

        def stats(start, end):
            cursor = col.find(
                {"timestamp": {"$gte": start, "$lt": end}},
                {"_id": 0, "ml_anomaly_score": 1},
            )
            xs = [
                float(d.get("ml_anomaly_score") or 0.0)
                for d in cursor
            ]
            n = len(xs)
            if n == 0:
                return {"n": 0, "mean": 0.0, "std": 0.0}
            mean = sum(xs) / n
            var = sum((x - mean) ** 2 for x in xs) / max(1, n - 1)
            return {"n": n, "mean": mean, "std": math.sqrt(var)}

        window = stats(window_start, now)
        baseline = stats(baseline_start, baseline_end)

        z = None
        drift_detected = False
        if baseline["n"] >= 30 and window["n"] >= 30 and baseline["std"] > 1e-9:
            z = (window["mean"] - baseline["mean"]) / baseline["std"]
            drift_detected = abs(z) >= z_threshold

        # Training baseline pulled from autoencoder.json -- a static reference
        # for the operator, separate from the rolling baseline computed above.
        ae_meta = get_store().status().get("autoencoder", {})

        return {
            "window_minutes": window_min,
            "baseline_minutes": baseline_min,
            "window": window,
            "baseline": baseline,
            "z_score": z,
            "z_threshold": z_threshold,
            "drift_detected": drift_detected,
            "training_threshold": ae_meta.get("threshold"),
            "training_version": ae_meta.get("version"),
        }
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=f"storage error: {exc}") from exc
