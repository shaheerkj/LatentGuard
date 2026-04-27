"""Pull benign-traffic Features straight out of the proxy's audit log.

Why this is separate from csic_loader:
  csic_loader.py parses raw HTTP request blocks from a text dump. This module
  goes the other direction -- it queries Mongo for rows the proxy has already
  characterised, so we get features that are *guaranteed* to match what the
  proxy will compute at inference time (no parser drift, no train/serve skew).

Use case:
  After running datasets/crawl_dvwa_benign.py to generate benign DVWA traffic,
  this loader pulls those rows back out (filtered by crawler User-Agent) and
  hands them to train_autoencoder / train_hdbscan as additional benign samples.
  This widens the training distribution beyond CSIC's narrow /tienda1/... shape
  so browsing arbitrary upstream paths no longer looks anomalous.
"""
from __future__ import annotations

import os
from typing import Iterable

from app.features import Features

DEFAULT_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DEFAULT_DB = os.environ.get("MONGO_DB", "latentguard")
DEFAULT_UA = "LatentGuard-Crawler/1.0"


def _row_to_features(row: dict) -> Features | None:
    """Audit row -> Features. Returns None if the row lacks a features dict."""
    f = row.get("features")
    if not isinstance(f, dict):
        return None
    try:
        return Features(
            length=int(f.get("length", 0)),
            entropy=float(f.get("entropy", 0.0)),
            token_count=int(f.get("token_count", 0)),
            special_ratio=float(f.get("special_ratio", 0.0)),
            digit_ratio=float(f.get("digit_ratio", 0.0)),
            uppercase_ratio=float(f.get("uppercase_ratio", 0.0)),
            method_is_post=bool(f.get("method_is_post", False)),
        )
    except (TypeError, ValueError):
        return None


def load_by_user_agent(
    user_agent: str = DEFAULT_UA,
    uri: str = DEFAULT_URI,
    db: str = DEFAULT_DB,
    limit: int | None = None,
) -> list[Features]:
    """Return Features for every audit row whose User-Agent matches.

    The audit-log header keys are lowercased by the proxy, so the filter goes
    against `headers.user-agent`. Pymongo accepts the dotted path verbatim.
    """
    from pymongo import MongoClient

    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    try:
        cursor = client[db]["requests"].find(
            {"headers.user-agent": user_agent},
            projection={"features": 1, "_id": 0},
        )
        if limit is not None:
            cursor = cursor.limit(limit)
        out: list[Features] = []
        for row in cursor:
            f = _row_to_features(row)
            if f is not None:
                out.append(f)
        return out
    finally:
        client.close()


def load_allowed_recent(
    uri: str = DEFAULT_URI,
    db: str = DEFAULT_DB,
    limit: int = 5000,
    exclude_user_agents: Iterable[str] = (),
) -> list[Features]:
    """Optional fallback: pull recent allow-decisions, excluding listed UAs.

    Useful for the M11 continuous-learning loop later -- once the model is
    well-calibrated, allow-decisions in the audit log are a free source of
    fresh benign samples for periodic retrains.
    """
    from pymongo import MongoClient

    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    try:
        query: dict = {"final_action": "allow"}
        excluded = list(exclude_user_agents)
        if excluded:
            query["headers.user-agent"] = {"$nin": excluded}
        cursor = (
            client[db]["requests"]
            .find(query, projection={"features": 1, "_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        out: list[Features] = []
        for row in cursor:
            f = _row_to_features(row)
            if f is not None:
                out.append(f)
        return out
    finally:
        client.close()
