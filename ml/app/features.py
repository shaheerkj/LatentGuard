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

    def to_vector(self) -> list[float]:
        return [
            float(self.length),
            float(self.entropy),
            float(self.token_count),
            float(self.special_ratio),
            float(self.digit_ratio),
            float(self.uppercase_ratio),
            1.0 if self.method_is_post else 0.0,
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

    return Features(
        length=length,
        entropy=_shannon_entropy(freq, length),
        token_count=token_count,
        special_ratio=_ratio(specials, length),
        digit_ratio=_ratio(digits, length),
        uppercase_ratio=_ratio(uppers, length),
        method_is_post=is_post,
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
