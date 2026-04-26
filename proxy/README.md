# proxy/ — Go reverse proxy with Coraza WAF

Owns SRS modules **M1 (Reverse Proxy Interceptor)**, **M2 (Request
Normalization)**, and **M3 (Rule-Based Pre-filter via Coraza/CRS)**.

## Layout

- `cmd/proxy/` — entrypoint.
- `internal/coraza/` — Coraza v3 engine setup, CRS loading, hot reload.
- `internal/normalizer/` — request canonicalization + feature extraction.
- `internal/client/` — HTTP client to the FastAPI ML service (`/score`).
- `internal/decision/` — final block/allow/forward logic.
- `internal/storage/` — MongoDB writer for audit logs.
- `rules/` — OWASP CRS plus AI-generated rules deployed via M9 + M10.

## Build

```
cd proxy
go build ./cmd/proxy
```

## Run (standalone, no compose)

```
PROXY_LISTEN=:8080 PROXY_UPSTREAM=http://localhost:8081 \
ML_URL=http://localhost:8000 MONGO_URI=mongodb://localhost:27017 \
./proxy
```
