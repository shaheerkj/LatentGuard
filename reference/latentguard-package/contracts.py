from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_request_id() -> str:
    return str(uuid.uuid4())


@dataclass
class RequestContext:
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: str
    source_ip: str
    timestamp: str = field(default_factory=utc_now_iso)
    request_id: str = field(default_factory=new_request_id)


@dataclass
class NormalizedRequest:
    canonical_path: str
    canonical_query: str
    canonical_body: str
    features: dict[str, float]


@dataclass
class RuleEvaluation:
    action: str  # allow | block | escalate
    score: float
    matched_rules: list[str]
    reasons: list[str]


@dataclass
class MLScore:
    anomaly_score: float
    outlier_score: float
    details: dict[str, Any]


@dataclass
class Decision:
    action: str  # allow | block | review
    score: float
    reasons: list[str]
    fallback_used: bool


@dataclass
class RuleDraft:
    rule_id: str
    pattern: str
    rule_text: str
    confidence: float
    status: str = "pending"  # pending | approved | rejected | deployed
    reviewer_notes: str = ""
