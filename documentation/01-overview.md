# Overview

## The problem

Web Application Firewalls (WAFs) come in two flavours and both have a
chronic weakness:

1. **Rule-based WAFs** (ModSecurity + CRS, Cloudflare, AWS WAF) are
   accurate on known attack signatures but blind to novel payloads.
   They require a human to write every new rule, and rule authors lag
   real-world threats by weeks.
2. **ML-based WAFs** detect anomalies in traffic but cannot *explain*
   why something was blocked, cannot be audited cleanly, and produce
   high false-positive rates that erode operator trust.

Existing commercial products pick one side or the other, with a
shallow nod to the other. Neither closes the loop between *detection*
and *defensive action*.

## What LatentGuard does differently

LatentGuard runs both layers in series on every request, then uses
what it learns to **propose new rules back to the operator**:

```
attack traffic → WAF rules + ML scorers → consensus verdict → audit log
                                                                 │
                                                                 ▼
                                              FP-Growth pattern mining
                                                                 │
                                                                 ▼
                                              draft ModSecurity rules
                                                                 │
                                                                 ▼
                                                operator approves
                                                                 │
                                                                 ▼
                                                live in Coraza (hot reload)
```

This is the "adaptive" in *Adaptive Dual-Layer Web Application
Firewall*. The system learns from what it has already seen, surfaces
attack-pattern itemsets to a human, and lets the human decide what
becomes a permanent rule. **No automated weight updates ship to
production without an operator click** — this is the Human-in-the-Loop
(HITL) gate.

## Scope

| In scope (built) | Out of scope (deliberately) |
|---|---|
| Reverse proxy + TLS termination | Cloud-native (K8s, Helm) deployment |
| Coraza WAF + OWASP CRS + custom rules | Multi-tenant RBAC, MFA, SSO |
| Spamhaus threat-intel feeds with hot reload | Federated learning across deployments |
| Autoencoder anomaly score | SHAP / LIME explainability (deferred) |
| HDBSCAN cluster outlier score | Automated retraining on drift |
| Tunable consensus engine | Real LLM rule synthesis (stub provided; LLM is one swap away) |
| MongoDB audit log | High-availability replication |
| FP-Growth attack-pattern miner | Distributed proxy fleet |
| Stub rule-synthesis orchestrator | Per-shape autoencoders (single global AE today) |
| Approval UI for candidate rules | n-gram features (still character-level) |
| Live Coraza hot reload on promote | |
| AE drift watch (z-score on rolling window) | |
| Single-admin JWT auth on every operator endpoint | |
| Dashboard for KPIs, audit log, models, rules | |

The "out of scope" column is intentional — these items appear in the
SRS / SDS as aspirational future work to round out academic chapters,
not as binding deliverables for the FYP submission.

## Who is this for?

- **Operators** of small-to-mid traffic web apps who want a WAF that
  adapts to their actual traffic without a full security team writing
  custom rules.
- **Researchers** studying HITL-feedback loops in security ML
  (the audit log + candidate-rule store is a clean datapoint for
  approval-rate / time-to-block / FPR-over-time studies).
- **Academic evaluators** assessing a final-year project that ties
  together five non-trivial subsystems (proxy, WAF, ML, mining,
  dashboard) into one running stack.

## Project status

10.5 of 11 SRS modules implemented and running. See
[03-modules.md](03-modules.md) for the per-module breakdown and
[06-results.md](06-results.md) for measured performance.
