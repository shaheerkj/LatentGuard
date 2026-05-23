"""Google Gemini provider for M9 rule synthesis.

Uses Gemini 1.5 Flash via the public REST API (no SDK pulled in --
httpx is already a dependency for the proxy /__reload call). The
free tier (15 req/min, 1,500 req/day, 1M tokens/min) is more than
enough for a demo and the keys are issued at aistudio.google.com.

Enable by setting LLM_PROVIDER=gemini and GEMINI_API_KEY=<your key>
in infra/docker-compose.yml. If either is missing the orchestrator
falls back to the stub renderer -- the pipeline still works end-to-end
without a key, just with less polished rule prose.

Prompt design: we hand the model the FP-Growth itemset plus the
constraints a candidate must satisfy (Coraza SecLang syntax, rule_id
band, msg + tag conventions). Output is parsed defensively: we accept
either a raw rule block or a fenced code block, strip both, and
sanity-check that the result starts with `SecRule` before returning.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger("latentguard.ml.rulegen.llm_gemini")

# Hard-coded to 1.5 Flash because it's the free-tier sweet spot. Override
# with GEMINI_MODEL if you have paid access and want 1.5 Pro / 2.0 Flash.
DEFAULT_MODEL = "gemini-1.5-flash-latest"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

_PROMPT = """You are a defensive web-application-firewall engineer.
Given a frequent attack-pattern itemset mined from the audit log,
produce a single ModSecurity / Coraza SecLang rule (with chained
sub-rules as needed) that would block matching requests.

PATTERN ITEMS (every item must influence the rule):
{items}

CONSTRAINTS:
- Use rule_id = {rule_id} exactly (do not invent another).
- phase:2, deny, status:403.
- Provide a short, accurate msg: starting with 'LG mined:'.
- Add tags: 'lg/mined' and 'lg/llm' plus one attack-class tag
  (attack-sqli, attack-xss, attack-lfi, attack-rce, attack-scanner,
  attack-protocol) if the items imply one.
- For chained predicates use the `chain` action; the HEAD rule is
  the only one with the disruptive action.
- For path items use `REQUEST_URI @beginsWith /value`.
- For method items use `REQUEST_METHOD @streq VALUE`.
- For ip/24 items use `REMOTE_ADDR @ipMatch CIDR/24`.
- For body:present use `REQUEST_BODY_LENGTH @gt 0`.
- For `rule:NNN` items (existing rule already fires) reference them
  ONLY in a leading comment, never in a SecRule (Coraza cannot chain
  off another rule's match by id portably).
- For ae:high / outlier:high items (ML signals) reference ONLY in a
  leading comment.

OUTPUT:
Return the rule directives only. No prose. No code fences. The first
non-comment line MUST start with `SecRule`.
"""


def _api_key() -> str | None:
    return (os.environ.get("GEMINI_API_KEY") or "").strip() or None


def is_available() -> bool:
    return _api_key() is not None


def _model_name() -> str:
    return (os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL).strip()


_FENCE_RE = re.compile(r"^```[a-z]*\s*\n?(.*?)\n?```$", re.DOTALL | re.IGNORECASE)


def _clean_output(text: str) -> str:
    text = (text or "").strip()
    m = _FENCE_RE.match(text)
    if m:
        text = m.group(1).strip()
    return text


def render(items: list[str], rule_id: int) -> tuple[str, str] | None:
    """Render via Gemini. Returns (rule_text, msg) on success, None on
    failure -- the orchestrator then falls back to the stub renderer.
    """
    key = _api_key()
    if key is None:
        return None
    url = f"{GEMINI_BASE}/{_model_name()}:generateContent?key={key}"
    prompt = _PROMPT.format(items=", ".join(items), rule_id=rule_id)
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,  # low temp -> more deterministic rule grammar
            "maxOutputTokens": 800,
        },
    }
    try:
        resp = httpx.post(url, json=payload, timeout=15.0)
    except httpx.HTTPError as exc:
        logger.warning("gemini: request failed: %s", exc)
        return None
    if resp.status_code != 200:
        logger.warning("gemini: HTTP %d: %s", resp.status_code, resp.text[:200])
        return None
    try:
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, ValueError) as exc:
        logger.warning("gemini: malformed response: %s", exc)
        return None

    rule_text = _clean_output(text)
    if not rule_text:
        logger.warning("gemini: empty rule text")
        return None
    if "SecRule" not in rule_text:
        logger.warning("gemini: output has no SecRule directive -- rejecting")
        return None
    # Force-correct the id if the model invented its own.
    if f"id:{rule_id}" not in rule_text:
        rule_text = re.sub(r"id:\d+", f"id:{rule_id}", rule_text, count=1)

    msg_match = re.search(r"msg:'([^']+)'", rule_text)
    msg = msg_match.group(1) if msg_match else f"LG mined: {', '.join(items)}"
    return rule_text + ("\n" if not rule_text.endswith("\n") else ""), msg
