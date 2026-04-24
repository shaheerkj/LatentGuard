from __future__ import annotations

import re
from collections import Counter
from hashlib import sha256

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
    @staticmethod
    def _modsec_numeric_id(rule_hex: str, seen_ids: set[int]) -> int:
        # Build ID from the full hash to reduce collision probability.
        base = 1_000_000_000 + (int(rule_hex, 16) % 1_000_000_000)
        candidate = base
        while candidate in seen_ids:
            candidate += 1
            if candidate > 1_999_999_999:
                candidate = 1_000_000_000
        seen_ids.add(candidate)
        return candidate

    def generate(self, patterns: list[tuple[str, float]]) -> list[RuleDraft]:
        drafts: list[RuleDraft] = []
        seen_ids: set[int] = set()
        for token, confidence in patterns:
            rid = sha256(f"{token}:{confidence}".encode("utf-8")).hexdigest()[:32]
            modsec_id = self._modsec_numeric_id(rid, seen_ids)
            escaped = re.escape(token)
            rule_text = (
                f'SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx {escaped}" '
                f'"id:{modsec_id},phase:2,deny,status:403,msg:\'AI pattern: {token}\'"'
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
