"""M6 Consensus engine: reduce (autoencoder, hdbscan, rule) into one verdict.

The verdict is BINARY -- allow or block -- because that is what real WAFs
emit at the edge. There is no human-in-the-loop band for individual
requests (that is intercept-proxy behaviour like Burp Suite Repeater, not
WAF behaviour). HITL in this project lives at the *rule* layer (M10):
when M9 drafts a SecRule from mined attack patterns, a human approves
that rule before it's merged into Coraza. Per-request approval would be
unworkable at line speed and isn't a feature any commercial WAF ships.
The original three-arm decision was a design carryover from the SRS
mockup; corrected 2026-05-22.

Three modes, taken from the SRS Presentation mockup:

  weighted - normalized weighted sum of the three [0,1] scores. Block when
             the combined score crosses the decision threshold; otherwise
             allow.
  majority - each model votes block/allow on its own per-model threshold.
             Majority (>=2/3) blocks.
  strict   - logical OR. ANY model crossing its per-model threshold blocks.
             Most conservative, useful when false negatives are costly.

Per-model weights are integers summing to 100. Decision threshold is in [0,1].
The mode and weights are operator-tunable from the dashboard (PUT /api/consensus/config).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ConsensusMode(str, Enum):
    WEIGHTED = "weighted"
    MAJORITY = "majority"
    STRICT = "strict"


@dataclass
class ConsensusConfig:
    mode: ConsensusMode = ConsensusMode.WEIGHTED
    weight_autoencoder: int = 40
    weight_hdbscan: int = 30
    weight_rule: int = 30
    threshold: float = 0.65
    per_model_threshold: float = 0.5  # used by majority + strict modes

    def validate(self) -> None:
        total = self.weight_autoencoder + self.weight_hdbscan + self.weight_rule
        if total != 100:
            raise ValueError(f"weights must sum to 100, got {total}")
        if not (0.0 <= self.threshold <= 1.0):
            raise ValueError(f"threshold must be in [0,1], got {self.threshold}")
        if not (0.0 <= self.per_model_threshold <= 1.0):
            raise ValueError(f"per_model_threshold must be in [0,1], got {self.per_model_threshold}")
        if self.mode not in {ConsensusMode.WEIGHTED, ConsensusMode.MAJORITY, ConsensusMode.STRICT}:
            raise ValueError(f"unknown mode {self.mode}")


@dataclass
class Decision:
    action: str  # allow / block (binary -- no per-request review band)
    score: float
    reasons: list[str] = field(default_factory=list)


def decide(ae_score: float, hdb_score: float, rule_score: float, cfg: ConsensusConfig) -> Decision:
    cfg.validate()
    ae = _clip(ae_score)
    hdb = _clip(hdb_score)
    ru = _clip(rule_score)

    if cfg.mode == ConsensusMode.STRICT:
        triggered = []
        if ae >= cfg.per_model_threshold:
            triggered.append(f"autoencoder {ae:.2f} >= {cfg.per_model_threshold:.2f}")
        if hdb >= cfg.per_model_threshold:
            triggered.append(f"hdbscan {hdb:.2f} >= {cfg.per_model_threshold:.2f}")
        if ru >= cfg.per_model_threshold:
            triggered.append(f"rule {ru:.2f} >= {cfg.per_model_threshold:.2f}")
        score = max(ae, hdb, ru)
        if triggered:
            return Decision(action="block", score=score, reasons=["strict mode"] + triggered)
        return Decision(action="allow", score=score, reasons=["strict mode: no model exceeded threshold"])

    if cfg.mode == ConsensusMode.MAJORITY:
        votes = sum(1 for s in (ae, hdb, ru) if s >= cfg.per_model_threshold)
        score = (ae + hdb + ru) / 3.0
        reasons = [
            f"majority mode: {votes}/3 votes",
            f"ae={ae:.2f}, hdb={hdb:.2f}, rule={ru:.2f}",
        ]
        if votes >= 2:
            return Decision(action="block", score=score, reasons=reasons)
        return Decision(action="allow", score=score, reasons=reasons)

    # weighted
    w_ae = cfg.weight_autoencoder / 100.0
    w_hdb = cfg.weight_hdbscan / 100.0
    w_ru = cfg.weight_rule / 100.0
    score = w_ae * ae + w_hdb * hdb + w_ru * ru
    reasons = [
        f"weighted mode: combined={score:.3f} (threshold={cfg.threshold:.2f})",
        f"ae={ae:.2f}*{w_ae:.2f}, hdb={hdb:.2f}*{w_hdb:.2f}, rule={ru:.2f}*{w_ru:.2f}",
    ]
    if score >= cfg.threshold:
        return Decision(action="block", score=score, reasons=reasons)
    return Decision(action="allow", score=score, reasons=reasons)


def _clip(x: float) -> float:
    if x is None:
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)
