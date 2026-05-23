# LatentGuard

**Adaptive Dual-Layer Web Application Firewall** that combines a
rule engine (Coraza + OWASP CRS) with an unsupervised ML layer
(autoencoder + HDBSCAN + consensus) and a feedback loop that mines
its own audit log to propose new defensive rules for a human to
approve.

> COMSATS University Islamabad — Final Year Project (FYP-I + FYP-II),
> Spring 2026. Syed Shaheer Khalid.

```
client → Coraza WAF + threat intel → ML scoring → consensus → upstream
                          │                                        │
                          └─────► Mongo audit log ◄────────────────┘
                                          │
                                          ▼
                              FP-Growth mining (M8)
                                          │
                                          ▼
                              draft rules (M9)
                                          │
                                          ▼
                              operator approval (M10)
                                          │
                                          ▼
                              Coraza hot reload (lg-generated/)
```

## Module status — 10.5 / 11

| # | Module | Status |
|---|---|---|
| 1 | Reverse proxy + TLS | DONE |
| 2 | Normalisation + features | DONE |
| 3 | Rule engine + threat intel (Spamhaus DROP/EDROP, hot reload) | DONE |
| 4 | Autoencoder anomaly scoring | DONE |
| 5 | HDBSCAN cluster validation | DONE |
| 6 | Multi-signal consensus (tunable from dashboard) | DONE |
| 7 | Mongo audit log | DONE |
| 8 | FP-Growth attack-pattern miner | DONE |
| 9 | Rule synthesis orchestrator | DONE (stub renderer; LLM hookable in one function) |
| 10 | HITL rule approval + hot promotion | DONE |
| 11 | Drift watch (z-score) | PARTIAL (auto-retrain trigger deferred) |

## Measured performance

- **100%** detection on canonical OWASP Top 10 payloads (6/6)
- **83.5%** on a varied 127-shot red-team battery (19 attack classes)
- **0%** false positives on 12-flow benign Juice Shop traffic
- **22 ms p50** end-to-end latency with full ML pipeline enabled
- **1,630 CIDRs** loaded from Spamhaus, hot-refreshed every 12 h

Re-verify recipe in [`docs/verified-states.md`](docs/verified-states.md).

## Quick start

```bash
git clone <repo>
cd LatentGuard
docker compose -f infra/docker-compose.yml up -d --build
```

Wait ~30 s for the ML service to warm up TensorFlow.

| URL | Purpose |
|---|---|
| `http://localhost:3000/` | Operator dashboard |
| `http://localhost:8080/` | Protected upstream (Juice Shop), via the proxy |
| `https://localhost:8443/` | Same, over HTTPS (auto self-signed cert) |
| `http://localhost:8000/healthz` | ML service health (public) |

Default operator credentials: `shaheerkj / v59q1rg8EOfykTXUUp1b`.
Override `ADMIN_USER` / `ADMIN_PASSWORD_HASH` / `JWT_SECRET` in
`infra/docker-compose.yml` for any non-local deployment.

## Repo layout

| Directory | Contents |
|---|---|
| `proxy/` | Go 1.21 reverse proxy + Coraza v3 + threat-intel + auth |
| `ml/` | Python 3.11 FastAPI + autoencoder + HDBSCAN + consensus + mining + rulegen |
| `dashboard/` | Static HTML/CSS/JS, Chart.js, JWT-aware fetch wrapper |
| `infra/` | Docker Compose, named volumes, shared rules dir |
| `attacks/` | 141-payload red-team battery, 19 attack classes |
| `datasets/` | CSIC 2010 download/split + benign Juice Shop crawler |
| `documentation/` | **Start here** — outside-in docs for evaluators + viva questions |
| `docs/` | Inside-out contributor notes (gotchas, verified states, design notes) |
| `fyp-documents/` | Submission docs (SRS, SDS, mockups) |

## Documentation

- [`documentation/`](documentation/) — outside-in project docs.
  Architecture, modules, setup, results, design decisions, and a
  prepared question bank for the viva committee.
- [`docs/`](docs/) — contributor-facing notes: gotchas, verified
  snapshots, roadmap, defense notes.
- `CLAUDE.md` — orientation file for AI pair-programming sessions
  (hard rules, module status, where everything lives).

## Adding a different upstream web app

There are two scenarios. The simple one is a one-for-one swap (drop
Juice Shop, put your own app behind the WAF); the complex one is
running the WAF in front of *multiple* apps and routing by host or
path.

### Scenario 1 — replace the upstream with your own app

This is one env-var change. Three steps:

1. **Add your app as a service** in `infra/docker-compose.yml`
   (or remove `juiceshop` and replace with whatever container
   image you want). Make sure the new service joins the
   `latentguard` network so the proxy can reach it by container
   name:

   ```yaml
   myapp:
     image: ghcr.io/myorg/myapp:latest
     container_name: latentguard-myapp
     restart: unless-stopped
     expose:
       - "8000"          # only expose internally; never publish to host
     environment:
       # app-specific env
     networks:
       - latentguard
   ```

2. **Point the proxy at the new upstream** by editing the `proxy`
   service's `PROXY_UPSTREAM` env var:

   ```yaml
   proxy:
     environment:
       PROXY_UPSTREAM: "http://myapp:8000"
       # ... other env unchanged
   ```

3. **Rebuild and restart**:

   ```bash
   docker compose -f infra/docker-compose.yml up -d --build proxy
   ```

That's it — the WAF, ML scoring, audit log, dashboard, threat intel,
and mining loop all continue to work unchanged. They're upstream-agnostic.

**Retraining note.** The ML models were trained on Juice Shop traffic
patterns. They'll still work against a different upstream, but the
false-positive rate will be higher until you retrain on your app's
benign traffic. To retrain:

```bash
# 1. Stop ML so it doesn't score during the warm-up phase.
docker compose -f infra/docker-compose.yml stop ml

# 2. Write a benign crawler for your app (see datasets/juiceshop_crawl/
#    as a template). Point it at http://localhost:8080 so traffic
#    flows through the proxy and gets captured to Mongo.

# 3. Run the crawler. Aim for >2,000 distinct benign requests.

# 4. Restart ML and trigger retraining from the dashboard's
#    Anomaly Models tab (Retrain button on both AE and HDBSCAN cards).
docker compose -f infra/docker-compose.yml start ml
```

### Scenario 2 — protect multiple apps from one WAF instance

Today the proxy speaks to a *single* upstream URL. Supporting
multiple upstreams (e.g., `api.example.com` → service A,
`shop.example.com` → service B) requires a small code change because
`proxy/cmd/proxy/main.go` builds one `httputil.NewSingleHostReverseProxy`.

The shape of the change:

1. **Define a routing config.** Add `PROXY_UPSTREAMS_JSON` or a
   small YAML file describing host-or-path → upstream mappings:

   ```json
   {
     "routes": [
       { "host": "api.example.com",  "upstream": "http://api:8000"  },
       { "host": "shop.example.com", "upstream": "http://shop:8000" },
       { "path_prefix": "/admin",    "upstream": "http://admin:8000" }
     ],
     "default": "http://web:80"
   }
   ```

2. **Build a `map[string]*httputil.ReverseProxy`** keyed by host or
   path prefix on boot; replace the single `reverse` handler in
   `main.go` with a small dispatcher that picks the right one
   per request. The Coraza/ML/audit pipeline runs *before* the
   dispatch so every upstream gets the same protection.

3. **Tag audit rows with the matched upstream** so the dashboard's
   Request Log filter can split per-app traffic. One extra field on
   `AuditRecord` (`storage/mongo.go`) plus a filter on the
   `/api/logs` endpoint.

4. **Optional:** per-upstream Coraza rule files (e.g., looser rules
   for an admin path) by adding a per-route `rules_dir` field.

Estimated effort: a long afternoon if you've worked with Go's
`net/http` before. The single-upstream design today is a deliberate
FYP-scope choice, not a structural limitation — the Coraza, ML, and
mining layers don't care how many upstreams sit behind them.

## What's in the box

- Five-container Docker Compose stack (proxy, ml, dashboard, mongo,
  juiceshop) with one shared `lg-generated-rules` volume between
  proxy and ml for hot rule promotion.
- JWT auth (HS256 + bcrypt) shared between the ML service and the
  proxy via one secret. Dashboard signs in once, calls both backends.
- OWASP CRS v4.7.0 + custom baseline (IDs 1000000+) + threat-intel
  rule (ID 1500001) + reserved 2000000+ band for mined rules.
- Tunable consensus (weighted / majority / strict modes) configurable
  live from the dashboard, persisted to Mongo.
- Dashboard with five working tabs: KPIs, Anomaly Models, Consensus,
  Request Log (filter + paginate + drawer), Rules Queue (mine,
  approve, edit, expire, hot reload).
- 141-payload attack battery and 12-flow benign crawler for
  reproducible verification.

## Author

Syed Shaheer Khalid (`shaheerkjaffer@gmail.com`)

## License

Academic project — see `LICENSE` for terms. Not affiliated with
OWASP, Coraza, or Spamhaus; uses their open-source artifacts under
their respective licenses.
