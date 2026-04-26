"""Replay CSIC 2010 HTTP traffic against the LatentGuard proxy.

Downloads the CSIC 2010 dataset on first run, parses both the benign and
attack splits, and replays them through the proxy. Reports block-rate per
split so you can quickly check rule efficacy.

Usage:
    python datasets/replay_csic.py --proxy http://localhost:8080 --limit 200
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import time
import urllib.request
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import http.client
from urllib.parse import urlparse

_CSIC_BASE = (
    "https://raw.githubusercontent.com/msudol/"
    "Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010"
)
CSIC_URL = f"{_CSIC_BASE}/normalTrafficTraining.txt"
CSIC_ATTACK_URL = f"{_CSIC_BASE}/anomalousTrafficTest.txt"

DATA_DIR = Path(__file__).resolve().parent / "raw"
BENIGN_FILE = DATA_DIR / "csic_normal.txt"
ATTACK_FILE = DATA_DIR / "csic_anomalous.txt"


@dataclass
class HTTPSample:
    method: str
    path: str
    headers: dict[str, str]
    body: str


def download(url: str, dest: Path) -> None:
    if dest.exists():
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  fetching {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "LatentGuard-CSIC-replay/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        dest.write_bytes(r.read())


def parse_csic(path: Path) -> list[HTTPSample]:
    """CSIC 2010 stores raw HTTP request blocks separated by blank lines."""
    text = path.read_text(encoding="latin-1", errors="replace")
    blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
    samples: list[HTTPSample] = []
    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue
        request_line = lines[0]
        m = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", request_line)
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

        samples.append(
            HTTPSample(method=method, path=target, headers=headers, body="\n".join(body_lines))
        )
    return samples


def replay(samples: Iterable[HTTPSample], proxy_url: str, limit: int) -> dict[str, int]:
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 80

    counts: Counter[int] = Counter()
    latencies: list[float] = []
    sent = 0

    for sample in samples:
        if sent >= limit:
            break
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            headers = {k: v for k, v in sample.headers.items() if k.lower() not in {"host", "content-length"}}
            headers["Host"] = f"{host}:{port}"
            body_bytes = sample.body.encode("utf-8", errors="replace") if sample.body else None
            if body_bytes:
                headers.setdefault("Content-Length", str(len(body_bytes)))
            t0 = time.perf_counter()
            conn.request(sample.method, sample.path, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            counts[resp.status] += 1
            latencies.append(elapsed)
            conn.close()
        except Exception as exc:
            counts[0] += 1
            print(f"  send error: {exc}", file=sys.stderr)
        sent += 1

    p95 = 0.0
    if latencies:
        latencies.sort()
        p95 = latencies[int(0.95 * (len(latencies) - 1))]

    return {
        "sent": sent,
        "blocked_403": counts.get(403, 0),
        "ok_2xx": sum(c for s, c in counts.items() if 200 <= s < 300),
        "errors": counts.get(0, 0),
        "p95_ms": round(p95, 2),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--proxy", default="http://localhost:8080")
    p.add_argument("--limit", type=int, default=200, help="requests per split")
    p.add_argument("--skip-download", action="store_true")
    args = p.parse_args()

    if not args.skip_download:
        print("Downloading CSIC 2010 splits (cached on disk after first run)...")
        download(CSIC_URL, BENIGN_FILE)
        download(CSIC_ATTACK_URL, ATTACK_FILE)

    print("\nParsing benign split...")
    benign = parse_csic(BENIGN_FILE)
    print(f"  parsed {len(benign)} benign samples")

    print("Parsing attack split...")
    attack = parse_csic(ATTACK_FILE)
    print(f"  parsed {len(attack)} attack samples")

    print(f"\nReplaying first {args.limit} of each split against {args.proxy} ...\n")

    print("-- BENIGN --")
    bres = replay(benign, args.proxy, args.limit)
    print(f"  {bres}")
    fpr = bres["blocked_403"] / max(bres["sent"], 1)
    print(f"  false positive rate: {fpr:.2%}")

    print("\n-- ATTACK --")
    ares = replay(attack, args.proxy, args.limit)
    print(f"  {ares}")
    tpr = ares["blocked_403"] / max(ares["sent"], 1)
    print(f"  detection rate: {tpr:.2%}")

    print(f"\nP95 latencies - benign: {bres['p95_ms']} ms, attack: {ares['p95_ms']} ms")
    print(f"NFR target: P95 <= 150 ms end-to-end")

    return 0


if __name__ == "__main__":
    sys.exit(main())
