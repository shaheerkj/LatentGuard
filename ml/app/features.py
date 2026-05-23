"""Feature extraction parity with proxy/internal/normalizer/normalizer.go.

At runtime the Go proxy computes these features and sends them to /score, so
this module is **training-only**. It is required to avoid train/serve skew:
the autoencoder must see exactly the same feature distribution at training
time as it does at inference time.

Any change to the Go normalizer's `extractFeatures` must be mirrored here in
the same commit, and the parity test in tests/test_feature_parity.py must be
re-run to catch drift.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.parse import parse_qsl

FEATURE_NAMES: tuple[str, ...] = (
    "length",
    "entropy",
    "token_count",
    "special_ratio",
    "digit_ratio",
    "uppercase_ratio",
    "method_is_post",
    # Character n-gram statistics. 3- and 4-grams capture short adversarial
    # motifs that the single-character ratios miss -- e.g. "<sc" + "scri"
    # repeated in obfuscated XSS, or "1=1" + "='1'" in classic SQLi.
    # We use SUMMARY STATS over the n-gram distribution rather than a fixed
    # vocabulary so the feature dimension is bounded and there is no
    # train/serve vocabulary drift.
    "ngram3_entropy",       # Shannon entropy of the 3-gram distribution
    "ngram3_unique_ratio",  # unique 3-grams / total 3-grams (diversity)
    "ngram4_entropy",
    "ngram4_unique_ratio",
)


@dataclass(slots=True, frozen=True)
class Features:
    length: int = 0
    entropy: float = 0.0
    token_count: int = 0
    special_ratio: float = 0.0
    digit_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    method_is_post: bool = False
    ngram3_entropy: float = 0.0
    ngram3_unique_ratio: float = 0.0
    ngram4_entropy: float = 0.0
    ngram4_unique_ratio: float = 0.0

    def to_vector(self) -> list[float]:
        return [
            float(self.length),
            float(self.entropy),
            float(self.token_count),
            float(self.special_ratio),
            float(self.digit_ratio),
            float(self.uppercase_ratio),
            1.0 if self.method_is_post else 0.0,
            float(self.ngram3_entropy),
            float(self.ngram3_unique_ratio),
            float(self.ngram4_entropy),
            float(self.ngram4_unique_ratio),
        ]

    def to_dict(self) -> dict:
        return asdict(self)


def canonicalize_path(path: str) -> str:
    if not path:
        return "/"
    lower = path.lower()
    while "//" in lower:
        lower = lower.replace("//", "/")
    return lower


def canonicalize_query(raw_query: str) -> str:
    """Lowercase keys, sort by key, join multi-values with ','. Mirrors Go side."""
    if not raw_query:
        return ""
    pairs = parse_qsl(raw_query, keep_blank_values=True)
    grouped: dict[str, list[str]] = {}
    order: list[str] = []
    for k, v in pairs:
        lk = k.lower()
        if lk not in grouped:
            grouped[lk] = []
            order.append(lk)
        grouped[lk].append(v)
    order.sort()
    parts: list[str] = []
    for k in order:
        joined = ",".join(grouped[k]).lower()
        parts.append(f"{k}={joined}")
    return "&".join(parts)


def canonicalize_body(body: str | bytes | None) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return body.strip().lower()


def extract_features(text: str, method: str) -> Features:
    is_post = method.upper() == "POST"
    length = len(text)
    if length == 0:
        return Features(method_is_post=is_post)

    digits = uppers = specials = 0
    freq: dict[str, int] = {}
    token_count = 0
    in_token = False

    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
        if ch.isdigit():
            digits += 1
        elif ch.isupper():
            uppers += 1
        elif not (ch.isalpha() or ch.isdigit() or ch.isspace()):
            specials += 1

        if ch.isalpha() or ch.isdigit():
            if not in_token:
                token_count += 1
                in_token = True
        else:
            in_token = False

    ng3_h, ng3_uniq = _ngram_stats(text, 3)
    ng4_h, ng4_uniq = _ngram_stats(text, 4)
    return Features(
        length=length,
        entropy=_shannon_entropy(freq, length),
        token_count=token_count,
        special_ratio=_ratio(specials, length),
        digit_ratio=_ratio(digits, length),
        uppercase_ratio=_ratio(uppers, length),
        method_is_post=is_post,
        ngram3_entropy=ng3_h,
        ngram3_unique_ratio=ng3_uniq,
        ngram4_entropy=ng4_h,
        ngram4_unique_ratio=ng4_uniq,
    )


def features_from_request(method: str, path: str, raw_query: str, body: str | bytes | None) -> Features:
    cp = canonicalize_path(path)
    cq = canonicalize_query(raw_query)
    cb = canonicalize_body(body)
    combined = f"{cp} {cq} {cb}"
    return extract_features(combined, method)


def features_matrix(rows: Iterable[Features]):
    """Return an (n, 7) numpy array. Imported lazily so this module is import-cheap."""
    import numpy as np
    return np.array([r.to_vector() for r in rows], dtype="float32")


_PATH_QUERY_RE = re.compile(r"^([^?]*)(?:\?(.*))?$")


def split_target(target: str) -> tuple[str, str]:
    """Split a request-target like '/foo?a=1&b=2' into (path, raw_query)."""
    m = _PATH_QUERY_RE.match(target or "")
    if not m:
        return target or "/", ""
    return m.group(1) or "/", m.group(2) or ""


def _ngram_stats(text: str, n: int) -> tuple[float, float]:
    """Return (entropy, unique_ratio) over the character n-gram distribution.

    Both metrics are bounded so they scale across short and long payloads:
        entropy        -- 0 when one n-gram dominates, log2(unique) at max
        unique_ratio   -- 0..1, high for diverse/obfuscated payloads, low
                          for repetitive ones (benign URLs lean low)

    Empty strings or strings shorter than n collapse to (0, 0) so the
    feature contributes no signal in degenerate cases.
    """
    if len(text) < n:
        return 0.0, 0.0
    counts: dict[str, int] = {}
    total = 0
    for i in range(len(text) - n + 1):
        gram = text[i:i + n]
        counts[gram] = counts.get(gram, 0) + 1
        total += 1
    if total == 0:
        return 0.0, 0.0
    h = 0.0
    inv = 1.0 / total
    for c in counts.values():
        p = c * inv
        h -= p * math.log2(p)
    h = round(h * 10000) / 10000
    uniq = round((len(counts) / total) * 10000) / 10000
    return h, uniq


def _shannon_entropy(freq: dict[str, int], total: int) -> float:
    if total <= 0:
        return 0.0
    n = float(total)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return round(h * 10000) / 10000


def _ratio(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((part / total) * 10000) / 10000
