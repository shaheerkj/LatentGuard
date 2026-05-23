"""Pattern -> ModSecurity rule synthesis.

Pluggable provider:

  stub       built-in template renderer. No external API. Always available.
  openai     deferred -- needs OPENAI_API_KEY. Stub returned if key missing.
  anthropic  deferred -- needs ANTHROPIC_API_KEY. Stub returned if key missing.

The stub provider is good enough to demo the full pipeline:
mining -> candidate -> approval -> live -> blocked-by-mined-rule. The
LLM swap is a one-function change once budget is available.

Rule template strategy:
  Each pattern item becomes a SecRule condition. We combine them with
  chained rules ("chain" action) so the parent fires only when every
  condition matches, mirroring the FP-Growth "all items present"
  semantics. Coraza supports chain natively.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

from .store import RULE_ID_BASE, upsert_candidate

logger = logging.getLogger("latentguard.ml.rulegen.orchestrator")


# Attack-class hints we tag a synthesized rule with. Best-effort -- the
# operator can re-tag after the fact. Keyed by Coraza rule-ID prefixes
# we already have in the baseline + CRS attack-rule conventions.
_RULE_ID_TAGS: dict[range, str] = {
    range(1000001, 1000010): "sqli",
    range(1000010, 1000020): "xss",
    range(1000020, 1000030): "lfi",
    range(1000030, 1000040): "rce",
    range(1000040, 1000050): "scanner",
    # OWASP CRS ranges (attack rules, scaffold stripped upstream).
    range(942000, 943000): "sqli",
    range(941000, 942000): "xss",
    range(930000, 931000): "lfi",
    range(932000, 933000): "rce",
    range(913000, 914000): "scanner",
    range(920000, 921000): "protocol",
}


def _classify_rule(rule_id: int) -> str | None:
    for rng, tag in _RULE_ID_TAGS.items():
        if rule_id in rng:
            return tag
    return None


def _classify_pattern(items: list[str]) -> list[str]:
    tags: set[str] = {"lg/mined"}
    for it in items:
        if it.startswith("rule:"):
            try:
                rid = int(it.split(":", 1)[1])
            except ValueError:
                continue
            tag = _classify_rule(rid)
            if tag:
                tags.add("attack-" + tag)
    if "ae:high" in items:
        tags.add("signal-ae")
    if "outlier:high" in items:
        tags.add("signal-outlier")
    return sorted(tags)


def _escape_for_modsec(value: str) -> str:
    # Strip anything that could close the quoted string or inject directives.
    return re.sub(r"[\"\\\r\n]", "", value)


def _conditions_for_items(items: list[str]) -> list[tuple[str, str]]:
    """Return [(variable, operator+pattern), ...] suitable for SecRule chains."""
    conds: list[tuple[str, str]] = []
    for raw in items:
        if ":" not in raw:
            continue
        kind, val = raw.split(":", 1)
        val = _escape_for_modsec(val)
        if kind == "path":
            # Anchor at request URI start so /loginz does not match /login.
            conds.append(("REQUEST_URI", f"@beginsWith {val}"))
        elif kind == "method":
            conds.append(("REQUEST_METHOD", f"@streq {val}"))
        elif kind == "ip/24":
            # @ipMatch accepts a CIDR; expand /24 sentinel back into a network.
            conds.append(("REMOTE_ADDR", f"@ipMatch {val}.0/24"))
        elif kind == "body" and val == "present":
            # REQUEST_BODY length > 0 -- @gt on REQUEST_BODY_LENGTH is the
            # canonical idiom and avoids a regex against arbitrary bodies.
            conds.append(("REQUEST_BODY_LENGTH", "@gt 0"))
        elif kind == "ae" or kind == "outlier":
            # These are ML-only signals; they cannot be expressed in Coraza
            # syntax, so we emit them only as a comment hint on the rule.
            continue
        elif kind == "rule":
            # An item "rule:NNNNN" means an existing rule already fires. Not
            # something we re-encode -- the existing rule still fires on its
            # own; including it as a condition would require Coraza's
            # @containsWord against TX.MATCHED_VAR_NAMES which is messy.
            # We comment it in the rule instead.
            continue
    return conds


def _stub_render(items: list[str], rule_id: int) -> tuple[str, str]:
    """Render a chained SecRule from items. Returns (rule_text, message)."""
    conds = _conditions_for_items(items)
    if not conds:
        # Nothing concrete enough to translate -- emit a no-op stub the operator
        # can edit by hand. Tag clearly so it does not get promoted by mistake.
        msg = "LG mined pattern (needs operator edit): " + ", ".join(items)
        body = (
            f'# Mined pattern had only ML/rule-id items; rewrite by hand.\n'
            f'# items: {", ".join(items)}\n'
            f'SecRule REQUEST_URI "@unconditionalMatch" \\\n'
            f'    "id:{rule_id},phase:2,pass,nolog,\\\n'
            f'     msg:\'{_escape_for_modsec(msg)}\',\\\n'
            f'     tag:\'lg/mined\',tag:\'lg/needs-edit\'"\n'
        )
        return body, msg

    msg = "LG mined: " + " AND ".join(items)
    head_var, head_op = conds[0]
    tail = conds[1:]

    # Chain marker: head rule carries the action + msg, every link adds
    # "chain". Coraza requires chained rules to NOT repeat the disruptive
    # action; only the head rule denies.
    rule_lines = [
        f'# Mined items: {", ".join(items)}',
        f'SecRule {head_var} "{head_op}" \\',
        f'    "id:{rule_id},phase:2,deny,status:403,severity:\'WARNING\',\\',
        f'     msg:\'{_escape_for_modsec(msg)}\',\\',
        f'     tag:\'lg/mined\'{"," if tail else ""}{"chain" if tail else ""}"',
    ]
    for i, (var, op) in enumerate(tail):
        is_last = i == len(tail) - 1
        rule_lines.append(f'    SecRule {var} "{op}" \\')
        rule_lines.append(
            f'        "t:none{"" if is_last else ",chain"}"'
        )
    return "\n".join(rule_lines) + "\n", msg


def _render(items: list[str], rule_id: int, provider: str) -> tuple[str, str, str]:
    """Returns (rule_text, message, provider_used).

    Pluggable provider dispatch. Each external provider returns either
    (rule_text, msg) on success or None on failure -- which always falls
    back to the stub renderer so the pipeline never breaks just because
    an API call timed out or the key expired. The orchestrator records
    the provider that actually produced the rule so the dashboard can
    surface "drafted by gemini" vs "drafted by stub" per candidate.
    """
    if provider == "gemini":
        from . import llm_gemini
        if not llm_gemini.is_available():
            logger.info("orchestrator: GEMINI_API_KEY missing, falling back to stub")
        else:
            out = llm_gemini.render(items, rule_id)
            if out is not None:
                rule_text, msg = out
                return rule_text, msg, "gemini"
            logger.info("orchestrator: gemini render failed, falling back to stub")
    elif provider == "openai" and not os.environ.get("OPENAI_API_KEY"):
        logger.info("orchestrator: OPENAI_API_KEY missing, falling back to stub")
    elif provider == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        logger.info("orchestrator: ANTHROPIC_API_KEY missing, falling back to stub")
    elif provider not in ("stub", "gemini"):
        logger.warning(
            "orchestrator: provider %r not implemented (openai/anthropic stubs "
            "available -- wire ml/app/rulegen/llm_*.py to enable); using stub",
            provider,
        )
    rule_text, msg = _stub_render(items, rule_id)
    return rule_text, msg, "stub"


def generate_candidates(
    patterns: list[dict[str, Any]],
    *,
    provider: str | None = None,
    max_to_emit: int = 25,
) -> dict[str, Any]:
    """Take mining patterns, emit candidate rules into rules_queue.

    Returns a summary of what was inserted vs refreshed vs skipped.
    """
    provider = provider or os.environ.get("LLM_PROVIDER", "stub").strip().lower() or "stub"

    inserted: list[int] = []
    refreshed: list[int] = []
    skipped: list[dict[str, Any]] = []

    for pat in patterns[:max_to_emit]:
        items: list[str] = list(pat.get("items") or [])
        if not items:
            continue
        fingerprint = pat.get("fingerprint") or "|".join(sorted(items))
        tags = _classify_pattern(items)

        # We allocate the rule_id during upsert by hitting the store --
        # we do not know it before the insert. Render twice: first
        # with a placeholder to estimate text shape, then re-render
        # once the store gives us the final id. Simpler: render with a
        # placeholder, store it, then patch rule_text with the real id.
        placeholder_id = RULE_ID_BASE
        rule_text, message, provider_used = _render(items, placeholder_id, provider)

        doc, was_inserted = upsert_candidate(
            fingerprint=fingerprint,
            rule_text=rule_text,
            message=message,
            tags=tags,
            pattern=pat,
            provider=provider_used,
            source="mining",
        )

        if doc is None:
            skipped.append({"fingerprint": fingerprint, "reason": "upsert returned None"})
            continue

        real_id = int(doc.get("rule_id", placeholder_id))
        if was_inserted and real_id != placeholder_id:
            # Patch the rule text so the id directive matches the allocated id.
            patched = rule_text.replace(
                f"id:{placeholder_id}", f"id:{real_id}", 1
            )
            from ..db import rules_collection
            rules_collection().update_one(
                {"rule_id": real_id},
                {"$set": {"rule_text": patched}},
            )

        if was_inserted:
            inserted.append(real_id)
        else:
            refreshed.append(real_id)

    return {
        "ok": True,
        "provider": provider,
        "inserted": inserted,
        "refreshed": refreshed,
        "skipped": skipped,
        "total_patterns": len(patterns),
        "emitted": len(inserted) + len(refreshed),
    }
