# LatentGuard

This repository includes a working LatentGuard pipeline with a browser-based frontend console and API endpoints.

## Implemented capabilities

- Traffic inspection API endpoint (`POST /inspect`)
- Request normalization + feature extraction
- Rule-based filtering (baseline signatures + threat-intel denylist hooks)
- ML anomaly/outlier scoring (heuristic surrogate)
- Consensus decision engine with configurable weights/thresholds
- Logging + explainability in JSONL audit store
- Interactive web frontend at `/` for dashboard/log/config/rules/safe-mode management
- Rule mining/generation/review queue endpoints
- Safe-mode fallback to rule-only operation when ML fails

## Run

```bash
python3 main.py
```

Server starts at `http://127.0.0.1:8080`.

Open `http://127.0.0.1:8080/` in your browser to use the frontend console.

## Test

```bash
python3 -m unittest discover -s tests -v
```
