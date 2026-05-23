from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    timestamp: str
    version: str


class NormalizedFeatures(BaseModel):
    length: int = 0
    entropy: float = 0.0
    token_count: int = 0
    special_ratio: float = 0.0
    digit_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    method_is_post: bool = False
    # n-gram summary stats. Defaults to 0.0 so audit rows captured
    # against an old proxy build (pre-n-gram) deserialize cleanly --
    # the autoencoder treats zeros as "no n-gram signal" rather than
    # rejecting the request.
    ngram3_entropy: float = 0.0
    ngram3_unique_ratio: float = 0.0
    ngram4_entropy: float = 0.0
    ngram4_unique_ratio: float = 0.0


class ScoreRequest(BaseModel):
    request_id: str
    method: str
    path: str
    canonical_path: str | None = None
    canonical_query: str | None = None
    canonical_body: str | None = None
    features: NormalizedFeatures = Field(default_factory=NormalizedFeatures)
    rule_score: float | None = 0.0
    rule_matched: list[str] = Field(default_factory=list)


class ScoreResponse(BaseModel):
    action: Literal["allow", "block"]
    score: float
    anomaly_score: float
    outlier_score: float
    rule_score: float
    reasons: list[str]
    fallback_used: bool
