# ml/ — Python FastAPI ML service

Owns SRS modules **M4 (Autoencoder anomaly detection)**, **M5 (HDBSCAN
outlier validation)**, **M6 (Consensus engine)**, **M8 (FP-Growth pattern
mining)**, **M9 (Rule generation)**, and **M11 (Continuous learning)**.

## Endpoints (planned)

- `GET  /healthz` — liveness for Go proxy heartbeat.
- `POST /score`   — request scoring (M4 + M5 + M6 → action/score/reasons).
- `POST /mine`    — trigger FP-Growth over blocked logs (M8).
- `POST /rules/generate` — generate SecLang drafts from mined patterns (M9).
- `POST /train`   — retrain autoencoder on filtered benign traffic (M11).

## Layout

- `app/` — FastAPI app modules.
- `training/` — offline scripts (autoencoder training, HDBSCAN fit).
- `models/` — saved Keras + HDBSCAN artifacts (gitignored).

## Run (dev)

```
cd ml
uv sync   # or: pip install -e .
uvicorn app.main:app --reload --port 8000
```
