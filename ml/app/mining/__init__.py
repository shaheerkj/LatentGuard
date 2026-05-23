"""M8: FP-Growth attack-pattern miner.

Reads the audit log, builds a transaction per blocked request out of
discrete "items" (path prefix, method, fired rule IDs, IP /24, signal
bands), and runs FP-Growth to surface itemsets that occur together
often enough to justify a hard-coded rule.

Output: candidate "patterns" the M9 rule-synthesis orchestrator
turns into ModSecurity rule drafts.
"""
from .miner import MinerConfig, Pattern, mine_patterns

__all__ = ["MinerConfig", "Pattern", "mine_patterns"]
