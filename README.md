# LatentGuard MVP

This repository now includes an MVP implementation of the LatentGuard pipeline derived from the SRS.

## Implemented MVP capabilities

- Traffic inspection API endpoint (`POST /inspect`)
- Request normalization + feature extraction
- Rule-based filtering (baseline signatures + threat-intel denylist hooks)
- ML anomaly/outlier scoring (MVP heuristic surrogate)
- Consensus decision engine with configurable weights/thresholds
- Logging + explainability in JSONL audit store
- Basic dashboard/log/config endpoints
- Rule mining/generation/review queue endpoints
- Safe-mode fallback to rule-only operation when ML fails

## Run

```bash
python3 /home/runner/work/LatentGuard/LatentGuard/main.py
```

Server starts at `http://127.0.0.1:8080`.

## Test

```bash
cd /home/runner/work/LatentGuard/LatentGuard
python3 -m unittest discover -s /home/runner/work/LatentGuard/LatentGuard/tests -v
```
