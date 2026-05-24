# LatentGuard — backlog

Tick a box only after the work is committed and (where applicable) live-verified.
Grouped by viva-impact / effort. Cross-references in `documentation/` and `docs/`.

---

## Top 5 — building now

- [x] **#1 LLM in M9** (Gemini Flash free-tier wiring) — commit after this one. To use: get a free key at https://aistudio.google.com/app/apikey, set `GEMINI_API_KEY` in compose, flip `LLM_PROVIDER` to `gemini`, restart `ml`. Falls back to stub when key missing.
- [x] **#2 Sandbox-test a candidate rule before promotion** (FR5.5) — commit after this one
- [x] **#3 MFA + account lockout + brute-force alert** (SEC-1 / SEC-4 / SEC-10 bundle) — commit after this one
- [x] **#4 Loss-curve viz during retraining** (FR7.4) — commit after this one
- [x] **#5 Decision override + reason audit** (FR4.5) — commit `6a2ae89`

---

## High-impact, unbuilt (next priority)

- [x] **Automatic failover to ModSecurity-only mode** (REL-2) — operator force-toggle + global banner
- [x] **Model accuracy panel** — running precision / recall / F1 + drop alert (FR-MON-1)
- [x] **CEF / Syslog export of audit events** (SI-6)
- [x] **OpenAPI / Swagger polish on `/docs`** — descriptions + tag groups + role-gating notes
- [x] **Auto-retrain on drift** (M11-full) — closed the loop with a model-promotion HITL gate

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

## Research-paper roadmap

Two paths to a paper out of this codebase, with effort + venue notes.

### Path A — systems paper (the closed loop IS the contribution)

Frame: **"LatentGuard: An Adaptive Dual-Layer WAF with Operator-Gated Pattern Mining for Continuous Rule Synthesis"**.
~80% built; the gap is rigorous evaluation.

- [ ] **A1. Comparative TPR/FPR over time.** Inject fresh attack classes weekly; measure how fast the mining loop produces rules that catch them vs a static-rule baseline (CRS alone).
- [ ] **A2. Operator labour metric.** Fraction of mined candidates approved, time-from-attack-onset-to-rule-live.
- [ ] **A3. Multi-app generalisation.** Run the stack against 2-3 upstreams (Juice Shop, DVWA, WebGoat); show the mining loop adapts without retraining the core engine.
- [ ] **A4. Adversarial pressure test.** Generate evasion payloads (LLM-driven mutation + standard obfuscation); show recall holds.
- [ ] **A5. Comparison vs commercial WAFs.** Same battery against ModSecurity-alone, AWS WAF (managed rules), Cloudflare free tier. Honest results table.

Venue: ACSAC, RAID, DSN systems track, DIMVA. Effort ~2-3 weeks. Risk: low (system already exists).

### Path B — ML-novelty paper. Pick ONE.

- [ ] **B1. Per-shape contrastive autoencoder ⭐ recommended.** Supervised contrastive loss (benign pulled together, known attacks pushed apart) + one AE per (method, path-prefix) tuple with shape routing. Genuinely under-explored for WAF. ~2 weeks.
- [ ] **B2. HTTP-BERT — masked language modelling on canonical requests ⭐⭐ highest ceiling.** Small Transformer encoder (4 layers, ~5M params) trained MLM-style on benign HTTP; anomaly = perplexity. Top-tier paper potential. ~3-4 weeks, GPU recommended.
- [ ] **B3. Active learning + adversarial robustness.** Queue uncertain-band requests (consensus ~0.4-0.6) for HITL; fine-tune classifier head on operator labels. FGSM + LLM-mutated payloads for adversarial eval. Workshop / lower-tier conference. ~1.5 weeks.
- [ ] **B4. Interpretable bottleneck via sparsity + concept attribution.** L1 sparsity on the 4-dim bottleneck; post-hoc correlate each dim with input features to label them. Explainability workshop. ~1 week.
- [ ] **B5. Federated learning prototype.** Two LatentGuard instances FedAvg-ing AE weights via a coordinator; show convergence + no audit-log sharing. Very high novelty, high risk. ~3+ weeks. Recommend as future-work paragraph in Path A instead.

### Recommended pick

**A + B1 combined.** Systems paper backed by per-shape contrastive AE as the ML contribution. Strongest defensible story. ~3-4 weeks total.

Implementation order if A+B1 is greenlit:
- [ ] adversarial-eval harness (LLM/obfuscation mutator + recall-delta script)  — 2 days
- [ ] per-shape AE infrastructure in `models.py` (shape clustering + router + per-shape thresholds + global fallback) — 3 days
- [ ] contrastive-loss training option in `train_autoencoder.py` (--contrastive flag; collect labelled attack set from battery + audit overrides) — 2 days
- [ ] `bench/` eval automation (bring stack up, fire attacks across a simulated month, dump CSV/JSON/matplotlib plots) — 3 days
- [ ] baseline runs against ModSecurity-only + CRS-only configs — 2 days

Total ~12 working days for an experimental section worth writing up.

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
