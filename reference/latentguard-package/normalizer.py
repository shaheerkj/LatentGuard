from __future__ import annotations

from urllib.parse import unquote_plus
from collections import Counter
from math import log2
import re

from .contracts import RequestContext, NormalizedRequest


_SPECIAL_RE = re.compile(r"[^a-zA-Z0-9\s]")
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    count = Counter(text)
    total = len(text)
    return -sum((c / total) * log2(c / total) for c in count.values())


class RequestNormalizer:
    def normalize(self, req: RequestContext) -> NormalizedRequest:
        canonical_path = unquote_plus(req.path).strip()
        canonical_query = unquote_plus(req.query).strip()
        canonical_body = unquote_plus(req.body).strip()

        combined = " ".join(filter(None, [canonical_path, canonical_query, canonical_body]))
        token_count = len(_TOKEN_RE.findall(combined))
        special_count = len(_SPECIAL_RE.findall(combined))
        length = float(len(combined))

        features = {
            "length": length,
            "entropy": _entropy(combined),
            "token_count": float(token_count),
            "special_ratio": (special_count / length) if length else 0.0,
            "digit_ratio": (sum(ch.isdigit() for ch in combined) / length) if length else 0.0,
            "uppercase_ratio": (sum(ch.isupper() for ch in combined) / length) if length else 0.0,
            "method_is_post": 1.0 if req.method.upper() == "POST" else 0.0,
        }

        return NormalizedRequest(
            canonical_path=canonical_path,
            canonical_query=canonical_query,
            canonical_body=canonical_body,
            features=features,
        )
