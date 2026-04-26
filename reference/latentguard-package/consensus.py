from __future__ import annotations

from dataclasses import dataclass

from .contracts import Decision


@dataclass
class ConsensusConfig:
    weight_m4: float = 0.4
    weight_m5: float = 0.3
    weight_rules: float = 0.3
    block_threshold: float = 0.65
    review_threshold: float = 0.45

    def normalized(self) -> "ConsensusConfig":
        total = self.weight_m4 + self.weight_m5 + self.weight_rules
        if total <= 0:
            return ConsensusConfig()
        return ConsensusConfig(
            weight_m4=self.weight_m4 / total,
            weight_m5=self.weight_m5 / total,
            weight_rules=self.weight_rules / total,
            block_threshold=self.block_threshold,
            review_threshold=self.review_threshold,
        )


class ConsensusEngine:
    def __init__(self, config: ConsensusConfig | None = None) -> None:
        self.config = (config or ConsensusConfig()).normalized()

    def update_config(self, config: ConsensusConfig) -> None:
        self.config = config.normalized()

    def decide(self, rule_score: float, anomaly_score: float, outlier_score: float, reasons: list[str]) -> Decision:
        c = self.config
        score = (
            (anomaly_score * c.weight_m4)
            + (outlier_score * c.weight_m5)
            + (rule_score * c.weight_rules)
        )
        score = round(score, 4)

        if score >= c.block_threshold:
            action = "block"
        elif score >= c.review_threshold:
            action = "review"
        else:
            action = "allow"

        return Decision(action=action, score=score, reasons=reasons, fallback_used=False)
