# Architecture

## Five containers, one bridge network

```
                                      ┌──────────────────────┐
                                      │   dashboard (nginx)  │
                                      │   :3000 → static HTML│
                                      └──────────┬───────────┘
                                                 │ JWT bearer
                                                 │ in localStorage
                  ┌──────────────────────────────┼──────────────┐
                  │ HTTP/HTTPS                   │              │
                  ▼                              ▼              ▼
        ┌──────────────────┐         ┌────────────────┐ ┌──────────────┐
client →│  proxy (Go)      │────────▶│  ml (Python)   │ │  /__reload   │
        │  :8080  HTTP     │  POST   │  :8000 FastAPI │ │  endpoint    │
        │  :8443  HTTPS    │ /score  │                │ │              │
        │                  │         │  /api/auth/*   │ │  triggers    │
        │  Coraza v3 +     │         │  /api/metrics  │ │  Engine.     │
        │  OWASP CRS +     │         │  /api/logs     │ │  Reload()    │
        │  custom rules    │         │  /api/mining   │ │              │
        │  threat-intel    │         │  /api/rules/*  │ │              │
        │                  │         │  /api/models/* │ │              │
        └──┬─────────┬─────┘         └───────┬────────┘ └──────┬───────┘
           │         │                       │                 │
           │ proxy   │ audit                 │ persists        │
           │ to      │ insert                │ rules_queue +   │
           │         │                       │ requests +      │
           │         │                       │ ml_config       │
           ▼         ▼                       ▼                 │
   ┌─────────────┐ ┌──────────────────────────────┐            │
   │ juiceshop   │ │      mongo (:27017)          │            │
   │ :3000       │ │      database: latentguard   │            │
   │ Angular SPA │ │      collections:            │            │
   │ vulnerable  │ │        requests (audit log)  │            │
   │ by design   │ │        rules_queue (M10)     │            │
   │             │ │        ml_config (consensus) │            │
   └─────────────┘ └──────────────────────────────┘            │
                                                               │
                  ┌────────────────────────────────────────────┘
                  │  ml writes lg-<id>.conf to a named volume
                  │  shared with proxy at
                  │  /etc/coraza/rules/lg-generated/
                  │  then calls /__reload
                  ▼
        ┌────────────────────────────────┐
        │ docker volume: lg-generated    │
        │ shared between ml + proxy      │
        └────────────────────────────────┘
```

## Request flow (the hot path)

A single HTTP request from `client` to `juiceshop` traverses these
steps. The numbers are typical latency on the demo box.

| # | Step | Owner | Time |
|---|---|---|---|
| 1 | TCP/TLS accept | proxy | <1ms |
| 2 | Normalise URL + body (decode, lowercase, strip) | proxy | <1ms |
| 3 | Coraza ProcessRequestHeaders + ProcessRequestBody — runs CRS + custom rules + threat-intel CIDR check | proxy | 5-15ms |
| 4 | If Coraza interruption → block, skip ML | proxy | — |
| 5 | Extract features (length, entropy, tokens, special-ratio, etc.) | proxy | <1ms |
| 6 | POST `/score` to ML with features + canonicals | proxy | network |
| 7 | ML loads cached AE + HDBSCAN, computes anomaly_score + outlier_score | ml | 10-30ms |
| 8 | ML consensus engine combines rule_score + anomaly + outlier per the configured weights, compares to threshold | ml | <1ms |
| 9 | ML returns `{action, score, reasons, ...}` | ml | — |
| 10 | Proxy applies final action (allow → forward upstream / block → 403) | proxy | — |
| 11 | Proxy + ML both write to `requests` collection (proxy is authoritative; ML side may add features) | proxy | async |

**Total typical latency: 20-50 ms** measured on a 4-core dev laptop
(see [06-results.md](06-results.md)).

## Feedback flow (the slow path)

Triggered by the operator from the dashboard, not on every request.

```
  operator clicks "Run miner"
            │
            ▼
  POST /api/mining/run
            │
            ▼
  M8: FP-Growth over requests collection
  (last N hours, only blocked requests by default)
            │
            ▼
  itemsets ranked by support
            │
            ▼
  M9: orchestrator → ModSecurity rule drafts
  (stub renderer today; LLM API hookable)
            │
            ▼
  rules_queue.insert(status=pending)
            │
            ▼
  operator sees candidate on dashboard rules tab
            │
            ▼
  operator clicks Approve
            │
            ▼
  M10: state transition pending → approved → live
            │
            ▼
  promoter writes lg-<id>.conf to shared volume
            │
            ▼
  promoter POSTs proxy /__reload (signed JWT)
            │
            ▼
  Coraza Engine.Reload() picks up the new file
            │
            ▼
  next matching attack blocked by the mined rule
```

## Authentication architecture

Single shared HS256 secret (`JWT_SECRET` env var) used by both the ML
service and the Go proxy. Tokens issued by the ML service are accepted
by the proxy without round-tripping back. This means:

- The dashboard signs in **once** (against ML) and the same token
  authorises every operator call against either backend.
- The ML service can call its own helper `auth.issue_token("ml-service")`
  to mint a service token when it needs to call the proxy
  (e.g. `/__reload`).
- `/healthz` and `/__healthz` are deliberately unauthenticated for
  docker healthcheck use.

## Why this stack?

| Choice | Reason |
|---|---|
| Coraza (not real ModSecurity) | Go-native, no C extension headache, identical rule grammar, ships as a single static binary |
| OWASP CRS v4.7.0 | Industry-standard ruleset; using the latest stable release closes a major credibility gap vs commercial WAFs |
| FastAPI for ML | Async-friendly, automatic OpenAPI, fast cold start, type-checked endpoints |
| MongoDB | Schemaless audit records (different request shapes, growing list of features without migrations); aggregation pipeline handles the time-series view |
| HDBSCAN over k-means | No need to pre-specify k; handles noise points explicitly; density-based clustering matches the irregular shape of HTTP-request feature space |
| Autoencoder over simple distance | Compresses 7 features into a 4-dim bottleneck — reconstruction error catches subtle anomalies that Mahalanobis distance misses |
| FP-Growth over Apriori | Single-pass tree construction vs Apriori's exponential rescans; matters as the audit log grows |
| Docker Compose | Single-command bring-up for evaluators; everything is reproducible without K8s overhead |
