from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pymongo.errors import PyMongoError

from .db import requests_collection, rules_collection

logger = logging.getLogger("latentguard.ml.api")

router = APIRouter(prefix="/api", tags=["dashboard"])


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
