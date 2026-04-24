from __future__ import annotations

import re
from collections import Counter
from hashlib import sha1

from .contracts import RuleDraft


class PatternMiner:
    def mine(self, blocked_logs: list[dict]) -> list[tuple[str, float]]:
        tokens: list[str] = []
        for row in blocked_logs:
            req = row.get("request", {})
            text = f"{req.get('path', '')} {req.get('query', '')} {req.get('body', '')}"
            for t in re.findall(r"[A-Za-z_]{3,}", text.lower()):
                tokens.append(t)

        if not tokens:
            return []

        c = Counter(tokens)
        total = sum(c.values())
        ranked = []
        for token, count in c.most_common(10):
            confidence = round(count / total, 4)
            if confidence >= 0.07:
                ranked.append((token, confidence))
        return ranked


class RuleGenerator:
    def generate(self, patterns: list[tuple[str, float]]) -> list[RuleDraft]:
        drafts: list[RuleDraft] = []
        for token, confidence in patterns:
            rid = sha1(f"{token}:{confidence}".encode("utf-8")).hexdigest()[:12]
            escaped = re.escape(token)
            rule_text = (
                f'SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx {escaped}" '
                f'"id:1{rid[:5]},phase:2,deny,status:403,msg:\'AI pattern: {token}\'"'
            )
            drafts.append(
                RuleDraft(
                    rule_id=rid,
                    pattern=token,
                    rule_text=rule_text,
                    confidence=confidence,
                )
            )
        return drafts

    def validate_modsec_rule(self, rule_text: str) -> bool:
        return rule_text.startswith("SecRule ") and "@rx" in rule_text and "id:" in rule_text
