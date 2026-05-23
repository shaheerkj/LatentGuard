"""M9: rule-synthesis orchestrator + M10 candidate-rule store.

The orchestrator takes patterns from M8 (mining) and produces draft
ModSecurity rules in a pluggable way:

  LLM_PROVIDER=stub     hand-templated rule (no API key needed)
  LLM_PROVIDER=openai   OpenAI chat completion (deferred -- needs key)
  LLM_PROVIDER=anthropic Anthropic Messages API (deferred -- needs key)

All providers return a draft rule plus metadata; the draft is stored
in the rules_queue collection as status=pending and a human approves
via the dashboard before promotion to the live Coraza ruleset.
"""
from .store import (
    CandidateRule,
    RuleStatus,
    approve_rule,
    delete_rule,
    edit_rule,
    expire_rule,
    get_rule,
    list_rules,
    reject_rule,
    upsert_candidate,
)
from .orchestrator import generate_candidates

__all__ = [
    "CandidateRule",
    "RuleStatus",
    "approve_rule",
    "delete_rule",
    "edit_rule",
    "expire_rule",
    "get_rule",
    "list_rules",
    "reject_rule",
    "upsert_candidate",
    "generate_candidates",
]
