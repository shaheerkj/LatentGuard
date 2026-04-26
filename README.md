# LatentGuard

Adaptive dual-layer Web Application Firewall combining **rule-based ModSecurity-compatible
filtering** with **AI-driven anomaly detection** and a **closed learning loop** that turns
blocked traffic into new SecLang rules under human review.

> COMSATS University Islamabad — Final Year Project (FYP-I + FYP-II), Spring 2026.

## Architecture (target)

```
Client ──► Go proxy (Coraza WAF) ──► protected app (DVWA in dev)
                │
                ├── POST /score ──► FastAPI ML service ──► Mongo
                │                    (autoencoder, HDBSCAN,
                │                     consensus, mining,
                │                     rule generation)
                │
                └── audit log writes ──► Mongo
                                          ▲
                                          │ reads
                                Static dashboard (Nginx)
```

## Repo layout

| Directory | Owns SRS modules | Notes |
| --- | --- | --- |
| `proxy/` | M1, M2, M3 | Go 1.21 + Coraza v3 |
| `ml/` | M4, M5, M6, M8, M9, M11 | Python 3.11 + FastAPI |
| `dashboard/` | M10 | Static HTML/JS, Chart.js |
| `storage/` | M7 | Mongo schemas + retention scripts |
| `infra/` | — | Docker Compose for local dev |
| `datasets/` | — | CSIC 2010 download/split scripts |
| `tests/` | — | per-component + e2e tests |
| `reference/` | — | Frozen Codex scaffold (do not import from) |

## Quick start

```bash
cd infra
docker compose up -d --build
```

| URL | What |
| --- | --- |
| `http://localhost:8080/` | DVWA, behind the LatentGuard proxy |
| `http://localhost:3000/` | Operator dashboard |
| `http://localhost:8000/healthz` | ML service liveness |

## Phase status

- [x] Phase 0 — repo skeleton, compose stack, Go + FastAPI bootstraps
- [ ] Phase 1 — M1/M2/M3 + dashboard (FYP-I, 30%)
- [ ] Phase 2 — M4/M5/M6 + safe-mode failover
- [ ] Phase 3 — M7/M8/M9/M10/M11 (closed learning loop)
- [ ] Phase 4 — Auth, RBAC, MFA, TLS, SIEM, hardening (FYP-II, 70%)

See `SRS Document.md` for the authoritative requirements.
