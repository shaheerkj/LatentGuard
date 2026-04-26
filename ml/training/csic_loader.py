"""Parse CSIC 2010 raw HTTP request blocks into Features for training.

Mirrors datasets/replay_csic.py's parser, but the output here is the same
canonicalized 7-feature vector the proxy emits at runtime. Same canonicalize
+ extract_features pipeline, so train and serve see identical inputs.
"""
from __future__ import annotations

import re
import urllib.request
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from app.features import Features, features_from_request, split_target

_CSIC_BASE = (
    "https://raw.githubusercontent.com/msudol/"
    "Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010"
)
CSIC_NORMAL_URL = f"{_CSIC_BASE}/normalTrafficTraining.txt"
CSIC_ANOMALOUS_URL = f"{_CSIC_BASE}/anomalousTrafficTest.txt"

_REQUEST_LINE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/")


@dataclass(slots=True)
class HTTPSample:
    method: str
    target: str
    headers: dict[str, str]
    body: str


def download(url: str, dest: Path) -> None:
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "LatentGuard-train/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        dest.write_bytes(r.read())


def parse(path: Path) -> list[HTTPSample]:
    text = path.read_text(encoding="latin-1", errors="replace")
    blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
    samples: list[HTTPSample] = []
    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue
        m = _REQUEST_LINE.match(lines[0])
        if not m:
            continue
        method, target = m.group(1), m.group(2)
        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if not in_body:
                if line.strip() == "":
                    in_body = True
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
            else:
                body_lines.append(line)
        samples.append(HTTPSample(method=method, target=target, headers=headers, body="\n".join(body_lines)))
    return samples


def to_features(sample: HTTPSample) -> Features:
    # CSIC's request line stores the absolute-form URL (e.g.
    # "GET http://localhost:8080/tienda1/index.jsp?... HTTP/1.1"). The proxy
    # only ever sees the origin-form r.URL.Path at runtime, so we must strip
    # the scheme + host here -- otherwise every training row carries an extra
    # ~20 chars of "http://localhost:8080" prefix that inference never sees,
    # which silently shifts the entire feature distribution.
    target = sample.target
    if "://" in target:
        # drop scheme://host, keep the path-and-query suffix
        rest = target.split("://", 1)[1]
        slash = rest.find("/")
        target = rest[slash:] if slash >= 0 else "/"
    path, query = split_target(target)
    return features_from_request(sample.method, path, query, sample.body)


def load_split(local_path: Path, url: str, max_samples: int | None = None) -> list[Features]:
    download(url, local_path)
    samples = parse(local_path)
    if max_samples is not None:
        samples = samples[:max_samples]
    return [to_features(s) for s in samples]
