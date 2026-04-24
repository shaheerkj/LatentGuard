from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .contracts import RequestContext
from .normalizer import RequestNormalizer
from .rule_engine import RuleEngine
from .ml import MLDetector
from .consensus import ConsensusConfig, ConsensusEngine
from .storage import AuditStore
from .rulegen import PatternMiner, RuleGenerator


class LatentGuardPipeline:
    def __init__(self, data_path: str = "./data") -> None:
        self.normalizer = RequestNormalizer()
        self.rules = RuleEngine()
        self.ml = MLDetector()
        self.consensus = ConsensusEngine(ConsensusConfig())
        self.store = AuditStore(data_path)
        self.pattern_miner = PatternMiner()
        self.rule_gen = RuleGenerator()
        self.safe_mode = False

    def set_consensus_config(self, payload: dict[str, Any]) -> dict[str, float]:
        cfg = ConsensusConfig(
            weight_m4=float(payload.get("weight_m4", self.consensus.config.weight_m4)),
            weight_m5=float(payload.get("weight_m5", self.consensus.config.weight_m5)),
            weight_rules=float(payload.get("weight_rules", self.consensus.config.weight_rules)),
            block_threshold=float(payload.get("block_threshold", self.consensus.config.block_threshold)),
            review_threshold=float(payload.get("review_threshold", self.consensus.config.review_threshold)),
        )
        self.consensus.update_config(cfg)
        c = self.consensus.config
        return {
            "weight_m4": c.weight_m4,
            "weight_m5": c.weight_m5,
            "weight_rules": c.weight_rules,
            "block_threshold": c.block_threshold,
            "review_threshold": c.review_threshold,
        }

    def process_request(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        req = RequestContext(
            method=request_payload.get("method", "GET"),
            path=request_payload.get("path", "/"),
            query=request_payload.get("query", ""),
            headers=request_payload.get("headers", {}),
            body=request_payload.get("body", ""),
            source_ip=request_payload.get("source_ip", "0.0.0.0"),
        )

        norm = self.normalizer.normalize(req)
        rule_eval = self.rules.evaluate(req, norm)

        fallback_used = False
        anomaly = 0.0
        outlier = 0.0
        ml_details: dict[str, Any] = {}

        reasons = list(rule_eval.reasons)

        if rule_eval.action == "block":
            decision = self.consensus.decide(rule_score=1.0, anomaly_score=0.0, outlier_score=0.0, reasons=reasons)
            decision.action = "block"
            decision.score = 1.0
        else:
            if self.safe_mode:
                fallback_used = True
                reasons.append("Safe mode active: ML bypassed")
                decision = self.consensus.decide(rule_score=rule_eval.score, anomaly_score=0.0, outlier_score=0.0, reasons=reasons)
            else:
                try:
                    ml_score = self.ml.score(norm)
                    anomaly = ml_score.anomaly_score
                    outlier = ml_score.outlier_score
                    ml_details = ml_score.details
                    reasons.append(f"M4 anomaly score={anomaly}")
                    reasons.append(f"M5 outlier score={outlier}")
                    decision = self.consensus.decide(rule_score=rule_eval.score, anomaly_score=anomaly, outlier_score=outlier, reasons=reasons)
                except Exception as exc:
                    fallback_used = True
                    self.safe_mode = True
                    reasons.append(f"ML failure: {exc}")
                    reasons.append("Fallback to rule-only mode")
                    decision = self.consensus.decide(rule_score=rule_eval.score, anomaly_score=0.0, outlier_score=0.0, reasons=reasons)

        decision.fallback_used = fallback_used

        should_forward = decision.action == "allow"

        result = {
            "request": asdict(req),
            "normalized": asdict(norm),
            "rule_evaluation": asdict(rule_eval),
            "ml": {
                "anomaly_score": anomaly,
                "outlier_score": outlier,
                "details": ml_details,
            },
            "decision": asdict(decision),
            "safe_mode": self.safe_mode,
            "forward_to_backend": should_forward,
        }

        self.store.append_log(result)
        return result

    def dashboard(self) -> dict[str, Any]:
        metrics = self.store.metrics()
        metrics["safe_mode"] = self.safe_mode
        metrics["consensus"] = {
            "weight_m4": self.consensus.config.weight_m4,
            "weight_m5": self.consensus.config.weight_m5,
            "weight_rules": self.consensus.config.weight_rules,
            "block_threshold": self.consensus.config.block_threshold,
            "review_threshold": self.consensus.config.review_threshold,
        }
        return metrics

    def generate_rules(self) -> dict[str, Any]:
        blocked = self.store.list_logs(limit=5000, action="block")
        patterns = self.pattern_miner.mine(blocked)
        drafts = self.rule_gen.generate(patterns)
        valid = [d for d in drafts if self.rule_gen.validate_modsec_rule(d.rule_text)]
        self.store.queue_rules(valid)
        return {
            "blocked_records_scanned": len(blocked),
            "patterns_found": len(patterns),
            "rules_queued": len(valid),
            "rules": [asdict(r) for r in valid],
        }
