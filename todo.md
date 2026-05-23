# LatentGuard — backlog

Tick a box only after the work is committed and (where applicable) live-verified.
Grouped by viva-impact / effort. Cross-references in `documentation/` and `docs/`.

---

## Top 5 — building now

- [ ] **#1 LLM in M9** (Gemini Flash free-tier wiring) — biggest demo-quality jump
- [ ] **#2 Sandbox-test a candidate rule before promotion** (FR5.5) — show which past requests would match the proposed rule before approving
- [x] **#3 MFA + account lockout + brute-force alert** (SEC-1 / SEC-4 / SEC-10 bundle) — commit after this one
- [x] **#4 Loss-curve viz during retraining** (FR7.4) — commit after this one
- [x] **#5 Decision override + reason audit** (FR4.5) — commit `6a2ae89`

---

## High-impact, unbuilt (next priority)

- [ ] **Automatic failover to ModSecurity-only mode** (REL-2) — UX surface for the existing safe-mode flag
- [ ] **Model accuracy panel** — running precision / recall / F1 + drop alert (FR-MON-1)
- [ ] **CEF / Syslog export of audit events** (SI-6)
- [ ] **OpenAPI / Swagger polish on `/docs`** — descriptions + examples
- [ ] **Auto-retrain on drift** (M11-full) — close the loop with a model-promotion HITL gate

---

## Medium-impact

- [ ] **SHAP / LIME explainability** in audit drawer (6.2.4)
- [ ] **MISP / AlienVault OTX / X-Force threat-intel feeds** beyond Spamhaus (6.2.6)
- [ ] **Auto-FP correction workflow** — operator flags FP → next benign training set (6.2.9)
- [ ] **Rule-effectiveness scoring** — per-rule TP/FP count over lifetime
- [ ] **WebSocket / HTTP/2 / gRPC inspection** (6.2.8)

---

## Compliance / chapter-padding (skip unless asked)

- [ ] AES-256 at rest (SEC-9) — Mongo encryption config
- [ ] Password policy + recovery + remember-me (FR1.1 / 1.3 / 1.4)
- [ ] LDAP / OAuth / SSO (SI-2.1 / 2.2) — needs an identity provider
- [ ] PCI-DSS / HIPAA / GDPR auto-reports (6.2.10)
- [ ] CSV / JSON log export (FR6.5)
- [ ] Keyboard shortcuts + tooltips + WCAG AA (USE-6 / 7 / 8)

---

## Deployment & ops

- [ ] Kubernetes Helm chart (4.3)
- [ ] HPA on the ML pod (6.2.3)
- [ ] Multi-tenancy (6.2.3)
- [ ] Prometheus + Grafana export (4.3)
- [ ] Encrypted DB backups + retention enforcement (3.4.2)

---

## ML research-grade (high reward, high risk)

- [ ] VAE / Transformer over HTTP requests (6.2.1)
- [ ] Federated learning prototype across two demo instances (6.2.5)
- [ ] GPU acceleration + INT8 quantisation (6.2.7)

---

## Done (cumulative)

- [x] M1 Reverse proxy + TLS (auto self-signed)
- [x] M2 Normalisation + 7-feature extractor
- [x] M3 Coraza WAF + OWASP CRS v4.7.0 + baseline rules + Spamhaus threat-intel with 12 h hot-reload
- [x] M4 Autoencoder anomaly scoring
- [x] M5 HDBSCAN cluster validation
- [x] M6 Multi-signal consensus (tunable; binary verdict; no per-request review band)
- [x] M7 Mongo audit log + 90-day TTL retention
- [x] M8 FP-Growth attack-pattern miner
- [x] M9 Rule-synthesis orchestrator (stub renderer; LLM hooks pluggable)
- [x] M10 HITL candidate-rule approval + hot promotion to Coraza
- [x] M11 Drift watch (partial — z-score endpoint + topbar pill)
- [x] JWT (HS256 + bcrypt) auth shared between ML + proxy
- [x] RBAC: 4 roles (admin / security-operator / ml-engineer / auditor) + Users tab + role-aware UI hiding + audit actor_role
- [x] Char n-gram features (3- and 4-grams) with Go ↔ Python parity test
- [x] Dashboard (KPIs, models, consensus, request log + drawer + copy-as-curl, rules, users)
- [x] 5-container docker-compose stack
- [x] 141-payload attack battery × 19 classes
- [x] Comprehensive documentation + viva question prep
- [x] OWASP CRS v4.7.0 pinned + VERSION marker
- [x] Copy-as-curl button on audit-log detail drawer
