"""Persist consensus config in Mongo so dashboard edits survive restarts.

Document layout (collection `ml_config`):
  { "_id": "consensus", "mode": "weighted", "weight_autoencoder": 40, ... }

Falls back to in-memory defaults when Mongo is unreachable so the scorer
doesn't refuse to make decisions during a brief storage outage.
"""
from __future__ import annotations

import logging
from dataclasses import asdict

from pymongo.errors import PyMongoError

from ..db import client_or_none
from .engine import ConsensusConfig, ConsensusMode

logger = logging.getLogger("latentguard.ml.consensus.store")

_COLLECTION = "ml_config"
_DOC_ID = "consensus"

_cache: ConsensusConfig | None = None


def _coll():
    c = client_or_none()
    if c is None:
        return None
    import os
    db_name = os.environ.get("MONGO_DB", "latentguard")
    return c[db_name][_COLLECTION]


def get_config() -> ConsensusConfig:
    global _cache
    if _cache is not None:
        return _cache
    coll = _coll()
    if coll is not None:
        try:
            doc = coll.find_one({"_id": _DOC_ID})
            if doc:
                _cache = _from_doc(doc)
                return _cache
        except PyMongoError as exc:
            logger.warning("consensus.get_config: mongo error %s", exc)
    _cache = ConsensusConfig()
    return _cache


def save_config(cfg: ConsensusConfig) -> ConsensusConfig:
    cfg.validate()
    coll = _coll()
    if coll is not None:
        try:
            doc = _to_doc(cfg)
            coll.update_one({"_id": _DOC_ID}, {"$set": doc}, upsert=True)
        except PyMongoError as exc:
            logger.warning("consensus.save_config: mongo error %s", exc)
            raise
    global _cache
    _cache = cfg
    return cfg


def _to_doc(cfg: ConsensusConfig) -> dict:
    d = asdict(cfg)
    d["mode"] = cfg.mode.value if isinstance(cfg.mode, ConsensusMode) else str(cfg.mode)
    return d


def _from_doc(doc: dict) -> ConsensusConfig:
    return ConsensusConfig(
        mode=ConsensusMode(doc.get("mode", "weighted")),
        weight_autoencoder=int(doc.get("weight_autoencoder", 40)),
        weight_hdbscan=int(doc.get("weight_hdbscan", 30)),
        weight_rule=int(doc.get("weight_rule", 30)),
        threshold=float(doc.get("threshold", 0.65)),
        per_model_threshold=float(doc.get("per_model_threshold", 0.5)),
    )
