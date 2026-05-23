"""FP-Growth miner over the requests audit log.

Why FP-Growth specifically: the SRS calls out market-basket mining for
attack-pattern discovery. Apriori works but rescans the DB once per
candidate level; FP-Growth builds a prefix tree once and recurses,
which matters as the audit log grows. mlxtend provides a solid
implementation -- already in pyproject.toml.

Items (the "alphabet" we mine over) are deliberately kept small and
interpretable, because every pattern eventually has to round-trip
through a human-readable ModSecurity rule:

  path:/login              first path segment, lower-cased
  method:POST              HTTP verb
  rule:1000001             every Coraza rule ID that fired (attack rules only)
  ip/24:10.0.0             /24 of source IP, coarse enough to dodge noise
  ae:high                  autoencoder anomaly_score >= 0.75
  outlier:high             HDBSCAN outlier_score >= 0.75
  body:present             non-empty canonical_body (hints at POST payload attack)

The miner runs offline (on a /api/mining/run trigger) so latency
is not in the request hot path. mlxtend is imported lazily so the
FastAPI cold start does not pay for pandas.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

logger = logging.getLogger("latentguard.ml.mining")

# CRS scaffold ranges that the proxy already filters out of attack_matched.
# We re-apply the same logic here so a stray scaffold ID in the audit log
# (older records from before the filter landed) does not pollute mining.
_CRS_SCAFFOLD_RANGES = (
    (900000, 902000),
    (949000, 950000),
    (980000, 990000),
)


def _is_scaffold_rule(rule_id: int) -> bool:
    for lo, hi in _CRS_SCAFFOLD_RANGES:
        if lo <= rule_id < hi:
            return True
    if 900000 <= rule_id < 1000000 and rule_id % 1000 < 100:
        return True
    return False


@dataclass(frozen=True)
class MinerConfig:
    min_support: float = 0.05    # itemset must appear in >= 5% of transactions
    min_confidence: float = 0.6  # association-rule confidence floor
    min_itemset_len: int = 2
    max_itemset_len: int = 4
    lookback_hours: int = 24 * 7  # default window: last 7 days
    max_transactions: int = 20000 # safety cap so we never OOM on a runaway log
    only_blocked: bool = True     # mine confirmed attacks by default


@dataclass
class Pattern:
    items: list[str]
    support: float       # fraction of transactions containing the itemset
    support_count: int   # absolute count
    length: int          # len(items)
    sample_request_ids: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        # Stable identifier used to dedupe patterns across miner runs.
        return "|".join(sorted(self.items))

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": list(self.items),
            "support": self.support,
            "support_count": self.support_count,
            "length": self.length,
            "fingerprint": self.fingerprint(),
            "sample_request_ids": list(self.sample_request_ids),
        }


def _ip_slash24(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return None
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net.network_address).rsplit(".", 1)[0]
    except (ValueError, TypeError):
        return None


def _first_path_segment(path: str) -> str:
    if not path:
        return "/"
    segs = [s for s in path.split("/") if s]
    if not segs:
        return "/"
    return "/" + segs[0].lower()


def record_to_items(record: dict[str, Any]) -> list[str]:
    """Translate one audit doc into a list of items for the FP basket."""
    items: set[str] = set()

    path = record.get("path") or record.get("canonical_path") or ""
    items.add(f"path:{_first_path_segment(path)}")

    method = (record.get("method") or "").upper()
    if method:
        items.add(f"method:{method}")

    for rid in record.get("rule_hits") or []:
        try:
            rid_int = int(rid)
        except (TypeError, ValueError):
            continue
        if _is_scaffold_rule(rid_int):
            continue
        items.add(f"rule:{rid_int}")

    ip = record.get("source_ip") or ""
    s24 = _ip_slash24(ip)
    if s24:
        items.add(f"ip/24:{s24}")

    ae = float(record.get("ml_anomaly_score") or 0.0)
    if ae >= 0.75:
        items.add("ae:high")
    outlier = float(record.get("ml_outlier_score") or 0.0)
    if outlier >= 0.75:
        items.add("outlier:high")

    body = record.get("canonical_body") or ""
    if body:
        items.add("body:present")

    return sorted(items)


def _load_transactions(
    collection,
    cfg: MinerConfig,
) -> tuple[list[list[str]], list[str]]:
    query: dict[str, Any] = {}
    if cfg.only_blocked:
        query["final_action"] = "block"
    if cfg.lookback_hours > 0:
        since = datetime.now(timezone.utc) - timedelta(hours=cfg.lookback_hours)
        query["timestamp"] = {"$gte": since}

    projection = {
        "_id": 0,
        "request_id": 1,
        "path": 1,
        "canonical_path": 1,
        "method": 1,
        "rule_hits": 1,
        "source_ip": 1,
        "canonical_body": 1,
        "ml_anomaly_score": 1,
        "ml_outlier_score": 1,
    }

    cursor = (
        collection.find(query, projection)
        .sort("timestamp", -1)
        .limit(cfg.max_transactions)
    )

    transactions: list[list[str]] = []
    request_ids: list[str] = []
    for doc in cursor:
        items = record_to_items(doc)
        if not items:
            continue
        transactions.append(items)
        request_ids.append(str(doc.get("request_id", "")))
    return transactions, request_ids


def _samples_for_itemset(
    items: Iterable[str],
    transactions: list[list[str]],
    request_ids: list[str],
    limit: int = 3,
) -> list[str]:
    target = set(items)
    out: list[str] = []
    for tx, rid in zip(transactions, request_ids):
        if target.issubset(set(tx)) and rid:
            out.append(rid)
            if len(out) >= limit:
                break
    return out


def mine_patterns(collection, cfg: MinerConfig | None = None) -> dict[str, Any]:
    """Run FP-Growth over the audit log and return ranked patterns.

    Returns a dict with run metadata + patterns; the orchestrator (M9)
    consumes the same shape directly.
    """
    cfg = cfg or MinerConfig()
    started = time.time()

    transactions, request_ids = _load_transactions(collection, cfg)
    if not transactions:
        return {
            "ok": True,
            "transactions": 0,
            "patterns": [],
            "elapsed_ms": int((time.time() - started) * 1000),
            "config": cfg.__dict__,
        }

    # Lazy import: pandas/mlxtend pull in numpy + ~50MB of state. Don't
    # pay for them on a cold FastAPI process that may never mine.
    from mlxtend.frequent_patterns import fpgrowth
    from mlxtend.preprocessing import TransactionEncoder

    encoder = TransactionEncoder()
    array = encoder.fit_transform(transactions)
    import pandas as pd  # local import same reasoning as above

    df = pd.DataFrame(array, columns=encoder.columns_)
    frequent = fpgrowth(df, min_support=cfg.min_support, use_colnames=True)

    if frequent.empty:
        return {
            "ok": True,
            "transactions": len(transactions),
            "patterns": [],
            "elapsed_ms": int((time.time() - started) * 1000),
            "config": cfg.__dict__,
            "note": "no itemsets met min_support",
        }

    frequent["length"] = frequent["itemsets"].apply(len)
    frequent = frequent[
        (frequent["length"] >= cfg.min_itemset_len)
        & (frequent["length"] <= cfg.max_itemset_len)
    ]
    frequent = frequent.sort_values(
        by=["length", "support"], ascending=[False, False]
    )

    n_tx = len(transactions)
    patterns: list[Pattern] = []
    for _, row in frequent.iterrows():
        items = sorted(row["itemsets"])
        support = float(row["support"])
        pat = Pattern(
            items=items,
            support=support,
            support_count=int(round(support * n_tx)),
            length=int(row["length"]),
            sample_request_ids=_samples_for_itemset(items, transactions, request_ids),
        )
        patterns.append(pat)

    return {
        "ok": True,
        "transactions": n_tx,
        "patterns": [p.to_dict() for p in patterns],
        "elapsed_ms": int((time.time() - started) * 1000),
        "config": cfg.__dict__,
    }
