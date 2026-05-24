"""M11 (full): model-promotion HITL gate.

Drift detection (`/api/models/drift`) fires when the AE anomaly-score
distribution shifts. Auto-retraining on drift without an operator
check is a poisoning risk -- an attacker who can shape the audit log
can push the training distribution. So drift triggers a CANDIDATE
retrain (writes to autoencoder.candidate.*) and an operator must
review the stats and approve before the live model is replaced.

Mirror of M10 (rule promotion) in spirit, scaled down for the
model-layer's tighter state:

    pending   -- candidate exists on disk, awaiting approval
    approved  -- never really visible (we promote immediately)
    live      -- candidate has been promoted; old model replaced
    rejected  -- candidate deleted, model unchanged
    failed    -- training subprocess crashed

State lives in the `model_candidates` Mongo collection. The
auto-drift trigger here is a thin background task; it just spawns
the same training subprocess the manual Retrain button uses, with
--candidate flagged.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pymongo import DESCENDING
from pymongo.errors import PyMongoError

from .db import get_db

logger = logging.getLogger("latentguard.ml.model_promotion")

ML_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = ML_DIR / "models"

LIVE_PATHS = {
    "model": MODELS_DIR / "autoencoder.keras",
    "scaler": MODELS_DIR / "autoencoder_scaler.pkl",
    "meta": MODELS_DIR / "autoencoder.json",
}
CANDIDATE_PATHS = {
    "model": MODELS_DIR / "autoencoder.candidate.keras",
    "scaler": MODELS_DIR / "autoencoder_scaler.candidate.pkl",
    "meta": MODELS_DIR / "autoencoder.candidate.json",
}


def _collection():
    return get_db()["model_candidates"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# State queries
# ---------------------------------------------------------------------------


def _read_meta(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def list_candidates(limit: int = 50) -> list[dict[str, Any]]:
    try:
        return list(_collection().find().sort("created_at", DESCENDING).limit(limit))
    except PyMongoError as exc:
        logger.warning("list_candidates: %s", exc)
        return []


def get_pending() -> dict[str, Any] | None:
    """Returns the most recent pending candidate, if any. Used by the
    drift trigger to avoid spawning a parallel retrain when one is
    already awaiting review.
    """
    try:
        return _collection().find_one(
            {"status": "pending"}, sort=[("created_at", DESCENDING)]
        )
    except PyMongoError as exc:
        logger.warning("get_pending: %s", exc)
        return None


def _record(status: str, source: str, extra: dict[str, Any] | None = None) -> str:
    doc: dict[str, Any] = {
        "status": status,
        "source": source,             # 'manual' | 'auto-drift'
        "created_at": _now(),
        "updated_at": _now(),
    }
    if extra:
        doc.update(extra)
    try:
        res = _collection().insert_one(doc)
        return str(res.inserted_id)
    except PyMongoError as exc:
        logger.warning("model_promotion._record: %s", exc)
        return ""


def _update(candidate_id: str, sets: dict[str, Any]) -> None:
    try:
        from bson import ObjectId
        sets.setdefault("updated_at", _now())
        _collection().update_one({"_id": ObjectId(candidate_id)}, {"$set": sets})
    except (PyMongoError, ValueError) as exc:
        logger.warning("model_promotion._update: %s", exc)


# ---------------------------------------------------------------------------
# Training trigger
# ---------------------------------------------------------------------------


def _run_training_blocking(candidate_id: str) -> None:
    """Synchronous training subprocess. Runs in a thread so it doesn't
    block the asyncio loop. Updates the candidate row with status +
    stats on success, failed-status + log path on failure.
    """
    log_path = MODELS_DIR / "autoencoder.candidate.log"
    cmd = [sys.executable, "-m", "training.train_autoencoder", "--candidate"]
    if os.environ.get("AUTO_RETRAIN_AUGMENT_MONGO", "true").lower() in ("1", "true", "yes"):
        cmd.append("--augment-mongo")
    logger.info("model_promotion: launching %s", " ".join(cmd))
    try:
        with log_path.open("wb") as fp:
            rc = subprocess.call(cmd, cwd=str(ML_DIR), stdout=fp, stderr=subprocess.STDOUT)
    except OSError as exc:
        _update(candidate_id, {"status": "failed", "error": str(exc)})
        return
    if rc != 0:
        _update(candidate_id, {
            "status": "failed",
            "exit_code": rc,
            "log_path": str(log_path),
        })
        return
    meta = _read_meta(CANDIDATE_PATHS["meta"])
    live_meta = _read_meta(LIVE_PATHS["meta"])
    _update(candidate_id, {
        "status": "pending",
        "stats": meta,
        "live_stats_at_creation": live_meta,
        "log_path": str(log_path),
    })


async def trigger_candidate_retrain(source: str = "manual") -> dict[str, Any]:
    """Spawn a candidate retrain, return the candidate doc immediately
    (status=training). The subprocess runs in a worker thread so the
    asyncio event loop stays free; on completion the row flips to
    pending (success) or failed (subprocess exit != 0).
    """
    existing = get_pending()
    if existing:
        return {"existing": True, "candidate": _serialize(existing)}
    candidate_id = _record("training", source)
    if not candidate_id:
        return {"error": "could not record candidate"}
    asyncio.get_event_loop().run_in_executor(
        None, _run_training_blocking, candidate_id
    )
    return {"started": True, "candidate_id": candidate_id, "source": source}


# ---------------------------------------------------------------------------
# Promote / reject
# ---------------------------------------------------------------------------


def promote(candidate_id: str, actor: str) -> dict[str, Any]:
    """Move candidate files to live paths atomically, then reload the
    in-memory model store. Mongo state flips to 'live'.
    """
    if not all(CANDIDATE_PATHS[k].exists() for k in CANDIDATE_PATHS):
        raise FileNotFoundError("candidate artifacts not on disk")
    # Replace each live file. shutil.move is atomic when src and dst
    # are on the same filesystem (which they always are inside the
    # container -- both live under /app/models).
    for k, dst in LIVE_PATHS.items():
        src = CANDIDATE_PATHS[k]
        if dst.exists():
            dst.unlink()
        shutil.move(str(src), str(dst))
    _update(candidate_id, {
        "status": "live",
        "promoted_at": _now(),
        "approved_by": actor,
    })
    # Reload the in-memory AE / HDBSCAN store so the next /score sees
    # the new weights without a service restart.
    try:
        from .models import get_store
        get_store().reload()
    except Exception as exc:
        logger.warning("model_promotion.promote: reload failed: %s", exc)
    return _serialize(_collection().find_one({"_id": _to_oid(candidate_id)}))


def reject(candidate_id: str, actor: str, note: str | None = None) -> dict[str, Any]:
    """Delete candidate files + mark rejected. The live model stays
    untouched."""
    for p in CANDIDATE_PATHS.values():
        if p.exists():
            try:
                p.unlink()
            except OSError as exc:
                logger.warning("model_promotion.reject: unlink %s: %s", p, exc)
    _update(candidate_id, {
        "status": "rejected",
        "rejected_at": _now(),
        "rejected_by": actor,
        "rejection_note": note,
    })
    return _serialize(_collection().find_one({"_id": _to_oid(candidate_id)}))


def _to_oid(s: str):
    from bson import ObjectId
    return ObjectId(s)


def _serialize(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if not doc:
        return None
    out = dict(doc)
    if "_id" in out:
        out["_id"] = str(out["_id"])
    for k in ("created_at", "updated_at", "promoted_at", "rejected_at"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    return out


def serialize_candidates(docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_serialize(d) for d in docs if d]


# ---------------------------------------------------------------------------
# Auto-trigger from drift watch
# ---------------------------------------------------------------------------

_drift_history: list[bool] = []
DRIFT_CONFIRM_COUNT = 3  # need K consecutive drift hits to trigger
DRIFT_CHECK_INTERVAL_S = int(os.environ.get("DRIFT_CHECK_INTERVAL_S", "900"))  # 15 min default


async def _drift_watcher() -> None:
    """Background task: every DRIFT_CHECK_INTERVAL_S, compute drift; if
    drift_detected for DRIFT_CONFIRM_COUNT consecutive checks AND no
    pending candidate exists, fire a candidate retrain. Disabled when
    AUTO_RETRAIN_ON_DRIFT != "true".
    """
    if os.environ.get("AUTO_RETRAIN_ON_DRIFT", "false").lower() not in ("1", "true", "yes"):
        logger.info("model_promotion: auto-retrain-on-drift disabled")
        return
    logger.info(
        "model_promotion: drift watcher armed (every %ds, %d consecutive hits to trigger)",
        DRIFT_CHECK_INTERVAL_S, DRIFT_CONFIRM_COUNT,
    )
    from .api import models_drift  # local import to avoid circular at module load
    while True:
        await asyncio.sleep(DRIFT_CHECK_INTERVAL_S)
        try:
            res = models_drift()  # default window/baseline
            detected = bool(res.get("drift_detected"))
        except Exception as exc:
            logger.warning("drift watcher: drift call failed: %s", exc)
            continue
        _drift_history.append(detected)
        if len(_drift_history) > DRIFT_CONFIRM_COUNT:
            _drift_history.pop(0)
        if all(_drift_history) and len(_drift_history) >= DRIFT_CONFIRM_COUNT:
            if get_pending() is not None:
                logger.info("drift watcher: pending candidate already exists, skipping")
                continue
            logger.warning(
                "drift watcher: %d consecutive drift detections; spawning candidate retrain",
                DRIFT_CONFIRM_COUNT,
            )
            await trigger_candidate_retrain(source="auto-drift")
            _drift_history.clear()


def start_in_background(loop: asyncio.AbstractEventLoop) -> None:
    loop.create_task(_drift_watcher())
