"""Candidate-rule persistence (M10 backing store).

Collection: rules_queue (already declared in db.py). Document shape:

  _id                 ObjectId
  rule_id             int     reserved ModSecurity ID in the 2000000+ band
  fingerprint         str     pattern fingerprint, used to dedupe across runs
  status              str     pending | approved | rejected | live | expired
  source              str     mining|manual
  provider            str     stub|openai|anthropic
  pattern             dict    M8 pattern that drove this rule (items + support)
  rule_text           str     ModSecurity rule directive(s)
  message             str     human-readable msg (also embedded in rule_text)
  tags                [str]   attack class tags, e.g. ["sqli", "lg/mined"]
  created_at          datetime
  updated_at          datetime
  approved_at         datetime | None
  approved_by         str | None
  promoted_at         datetime | None   when written to disk + reloaded
  notes               str               operator notes from the UI
  edit_history        [dict]            audit trail of edits / state changes

State machine (enforced in the helpers below):

  pending  ──approve──>  approved  ──promote──>  live  ──expire──>  expired
        \─reject──>  rejected
        \─edit (stays pending, rule_text overwritten, history pushed)

Once a rule is live, the only legal transitions are edit (re-promotes
with new text) or expire (removes from disk + triggers reload).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import PyMongoError

from ..db import rules_collection

logger = logging.getLogger("latentguard.ml.rulegen.store")


class RuleStatus:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    LIVE = "live"
    EXPIRED = "expired"

    ALL = (PENDING, APPROVED, REJECTED, LIVE, EXPIRED)

    # Allowed transitions. Keep this conservative -- the dashboard relies on
    # it to grey out impossible buttons.
    TRANSITIONS = {
        PENDING: {APPROVED, REJECTED},
        APPROVED: {LIVE, REJECTED, PENDING},
        LIVE: {EXPIRED, PENDING},
        REJECTED: {PENDING},
        EXPIRED: {PENDING},
    }


@dataclass
class CandidateRule:
    rule_id: int
    fingerprint: str
    rule_text: str
    message: str
    tags: list[str] = field(default_factory=list)
    pattern: dict[str, Any] = field(default_factory=dict)
    provider: str = "stub"
    source: str = "mining"
    status: str = RuleStatus.PENDING
    notes: str = ""

    def to_doc(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "rule_id": int(self.rule_id),
            "fingerprint": self.fingerprint,
            "rule_text": self.rule_text,
            "message": self.message,
            "tags": list(self.tags),
            "pattern": dict(self.pattern),
            "provider": self.provider,
            "source": self.source,
            "status": self.status,
            "notes": self.notes,
            "created_at": now,
            "updated_at": now,
            "approved_at": None,
            "approved_by": None,
            "promoted_at": None,
            "edit_history": [],
        }


def _ensure_indexes() -> None:
    try:
        col = rules_collection()
        col.create_index([("fingerprint", ASCENDING)], unique=True)
        col.create_index([("status", ASCENDING), ("updated_at", DESCENDING)])
        col.create_index([("rule_id", ASCENDING)], unique=True)
    except PyMongoError as exc:
        logger.warning("rules_queue: index create failed: %s", exc)


_INDEXES_READY = False


def _maybe_init() -> None:
    global _INDEXES_READY
    if not _INDEXES_READY:
        _ensure_indexes()
        _INDEXES_READY = True


# Rule-ID allocator -- LatentGuard reserves 2000000+ per the baseline file
# comment in proxy/rules/10-latentguard-baseline.conf.
RULE_ID_BASE = 2_000_000
RULE_ID_CEILING = 2_999_999


def _next_rule_id() -> int:
    _maybe_init()
    col = rules_collection()
    doc = (
        col.find({"rule_id": {"$gte": RULE_ID_BASE, "$lte": RULE_ID_CEILING}})
        .sort("rule_id", DESCENDING)
        .limit(1)
    )
    last = next(iter(doc), None)
    if last is None:
        return RULE_ID_BASE
    nxt = int(last["rule_id"]) + 1
    if nxt > RULE_ID_CEILING:
        raise RuntimeError(
            f"rule-id space exhausted ({RULE_ID_BASE}-{RULE_ID_CEILING}); "
            "expire old rules or widen the band"
        )
    return nxt


def upsert_candidate(
    *,
    fingerprint: str,
    rule_text: str,
    message: str,
    tags: list[str],
    pattern: dict[str, Any],
    provider: str = "stub",
    source: str = "mining",
) -> tuple[dict[str, Any], bool]:
    """Insert a new candidate, or refresh metadata on a duplicate fingerprint.

    Returns ``(doc, was_inserted)``. Duplicates are common across miner
    runs: the same itemset keeps surfacing while an attack is ongoing.
    Refresh support stats in-place rather than spamming the queue, and
    never overwrite the operator's edited rule_text -- their changes win.
    """
    _maybe_init()
    col = rules_collection()
    existing = col.find_one({"fingerprint": fingerprint})
    now = datetime.now(timezone.utc)
    if existing:
        update = {
            "$set": {
                "pattern": pattern,
                "updated_at": now,
                "message": message,
                "tags": list(tags),
            }
        }
        doc = col.find_one_and_update(
            {"fingerprint": fingerprint},
            update,
            return_document=ReturnDocument.AFTER,
        )
        return doc, False

    rid = _next_rule_id()
    cand = CandidateRule(
        rule_id=rid,
        fingerprint=fingerprint,
        rule_text=rule_text,
        message=message,
        tags=tags,
        pattern=pattern,
        provider=provider,
        source=source,
    )
    doc = cand.to_doc()
    col.insert_one(doc)
    return doc, True


def get_rule(rule_id: int) -> dict[str, Any] | None:
    _maybe_init()
    return rules_collection().find_one({"rule_id": int(rule_id)})


def list_rules(
    status: str | Iterable[str] | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    _maybe_init()
    query: dict[str, Any] = {}
    if status:
        if isinstance(status, str):
            query["status"] = status
        else:
            query["status"] = {"$in": list(status)}
    cursor = (
        rules_collection()
        .find(query)
        .sort([("status", ASCENDING), ("updated_at", DESCENDING)])
        .limit(limit)
    )
    return list(cursor)


def _transition(
    rule_id: int,
    target: str,
    actor: str | None,
    note: str | None,
    extra_set: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _maybe_init()
    col = rules_collection()
    current = col.find_one({"rule_id": int(rule_id)})
    if current is None:
        raise KeyError(f"rule_id {rule_id} not found")
    if target not in RuleStatus.ALL:
        raise ValueError(f"unknown target status {target!r}")
    src = current.get("status", RuleStatus.PENDING)
    if target not in RuleStatus.TRANSITIONS.get(src, set()) and src != target:
        raise ValueError(f"illegal transition {src} -> {target}")
    now = datetime.now(timezone.utc)
    history_entry = {
        "at": now,
        "from": src,
        "to": target,
        "actor": actor,
        "note": note,
    }
    sets: dict[str, Any] = {"status": target, "updated_at": now}
    if extra_set:
        sets.update(extra_set)
    if target == RuleStatus.APPROVED:
        sets["approved_at"] = now
        sets["approved_by"] = actor
    return col.find_one_and_update(
        {"rule_id": int(rule_id)},
        {"$set": sets, "$push": {"edit_history": history_entry}},
        return_document=ReturnDocument.AFTER,
    )


def approve_rule(rule_id: int, actor: str, note: str | None = None) -> dict[str, Any]:
    return _transition(rule_id, RuleStatus.APPROVED, actor, note)


def reject_rule(rule_id: int, actor: str, note: str | None = None) -> dict[str, Any]:
    return _transition(rule_id, RuleStatus.REJECTED, actor, note)


def expire_rule(rule_id: int, actor: str, note: str | None = None) -> dict[str, Any]:
    return _transition(rule_id, RuleStatus.EXPIRED, actor, note)


def edit_rule(
    rule_id: int,
    *,
    actor: str,
    rule_text: str | None = None,
    message: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Edits send the rule back to pending so it must be re-approved."""
    _maybe_init()
    col = rules_collection()
    current = col.find_one({"rule_id": int(rule_id)})
    if current is None:
        raise KeyError(f"rule_id {rule_id} not found")
    extra: dict[str, Any] = {}
    if rule_text is not None and rule_text.strip():
        extra["rule_text"] = rule_text
    if message is not None:
        extra["message"] = message
    if notes is not None:
        extra["notes"] = notes
    if not extra:
        return current
    # Edits always demote to pending so the change goes through approval again.
    return _transition(
        int(rule_id),
        RuleStatus.PENDING,
        actor,
        "edit",
        extra_set=extra,
    )


def delete_rule(rule_id: int) -> bool:
    _maybe_init()
    res = rules_collection().delete_one({"rule_id": int(rule_id)})
    return res.deleted_count > 0


def mark_promoted(rule_id: int) -> None:
    _maybe_init()
    rules_collection().update_one(
        {"rule_id": int(rule_id)},
        {"$set": {"promoted_at": datetime.now(timezone.utc)}},
    )
