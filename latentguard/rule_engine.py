from __future__ import annotations

import re

from .contracts import RequestContext, NormalizedRequest, RuleEvaluation


class RuleEngine:
    """MVP rule-based pre-filtering (baseline + custom + threat intel denylist)."""

    def __init__(
        self,
        deny_ips: set[str] | None = None,
        deny_domains: set[str] | None = None,
        custom_block_patterns: list[str] | None = None,
    ) -> None:
        self.deny_ips = deny_ips or set()
        self.deny_domains = {d.lower() for d in (deny_domains or set())}

        baseline = [
            r"(?i)union\s+select",
            r"(?i)or\s+1=1",
            r"(?i)<script",
            r"\.\./",
            r"(?i)cmd=",
            r"(?i)drop\s+table",
        ]
        custom = custom_block_patterns or []
        self.block_patterns = [re.compile(p) for p in [*baseline, *custom]]

        self.suspicious_patterns = [
            re.compile(r"(?i)select\s+.*from"),
            re.compile(r"(?i)benchmark\("),
            re.compile(r"(?i)sleep\("),
        ]

    def evaluate(self, req: RequestContext, norm: NormalizedRequest) -> RuleEvaluation:
        host = req.headers.get("Host", "").lower()

        if req.source_ip in self.deny_ips:
            return RuleEvaluation("block", 1.0, ["threatintel.ip"], ["Source IP in denylist"])

        if host and host in self.deny_domains:
            return RuleEvaluation("block", 1.0, ["threatintel.domain"], ["Host domain in denylist"])

        joined = f"{norm.canonical_path} {norm.canonical_query} {norm.canonical_body}".strip()

        for idx, pattern in enumerate(self.block_patterns, 1):
            if pattern.search(joined):
                return RuleEvaluation(
                    "block",
                    1.0,
                    [f"rule.block.{idx}"],
                    [f"Matched hard-block pattern: {pattern.pattern}"],
                )

        for idx, pattern in enumerate(self.suspicious_patterns, 1):
            if pattern.search(joined):
                return RuleEvaluation(
                    "escalate",
                    0.6,
                    [f"rule.suspicious.{idx}"],
                    [f"Matched suspicious pattern: {pattern.pattern}"],
                )

        return RuleEvaluation("allow", 0.0, [], ["No rule match"])
