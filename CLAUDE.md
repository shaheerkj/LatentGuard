# LatentGuard — Claude orientation

This file is auto-loaded every Claude Code session. Keep it short. Anything
that runs past ~120 lines goes into `docs/` with a one-line pointer below.

---

## Hard rules (read first, always apply)

- **NEVER `git push` without an explicit user instruction.** Even on feature
  branches, even after a clean local commit, even after a previously approved
  push — that approval was scoped to that one push, not future ones. Wait for
  the user to type "push" (or equivalent). Local commits are fine; remote
  sharing is the user's call every time.
- **NEVER include `Co-Authored-By: Claude` or any other Claude / Anthropic
  attribution line** in commits, PRs, or generated artefacts. This is an
  academic FYP — AI co-authorship would invalidate the submission. Strip the
  default Claude Code footer if it tries to add one.
- **Commits are authored as `Syed Shaheer Khalid <shaheerkjaffer@gmail.com>`.**
- **Verify before declaring done.** "It compiles" ≠ "it works". Hit the live
  stack with curl / the attack battery, check the audit log.
- **The SRS / SDS in `fyp-documents/` are NOT a binding TODO list.** They
  document the *aspirational* full system, including features written to
  fill academic chapters (six layers, MFA, RBAC, K8s, federated learning,
  SHAP/LIME, etc.). Some of those will be built, some won't, some have
  already deliberately diverged (e.g. binary verdict instead of
  allow/review/challenge — see gotcha #27). **Before implementing any
  feature you spot in the SRS/SDS, ASK the user whether they actually want
  it built.** "The SDS says X" is *not* sufficient justification on its
  own. The user re-stated this on 2026-05-22.
- **`main` is hands-off after PR #3 (merge commit `4ca4dcb`, 2026-05-24).**
  It now carries the FYP-II 70 % snapshot. New work continues on `fyp-II`;
  the user calls the next PR-to-main moment. When that PR happens, use
  `git merge --no-ff` (no squash, no rebase) — preserves per-commit history.
- **Ask before risky actions:** force push, branch deletion, dropping
  containers with named volumes, anything that touches `main`.

---

## What this project is (one paragraph)

**LatentGuard** is an Adaptive Dual-Layer Web Application Firewall —
COMSATS FYP by Syed Shaheer Khalid. A Go reverse proxy runs Coraza
(ModSecurity) with OWASP CRS v4.7.0 + baseline rules + Spamhaus threat-intel
feeds, then forwards to a Python ML service for autoencoder + HDBSCAN +
consensus scoring, then writes everything to Mongo for audit + ML training.
Read `docs/architecture.md` for the full picture.

---

## Module status (11 / 11 + extras)

| # | Module | Status |
|---|---|---|
| 1 | Reverse proxy + TLS | DONE |
| 2 | Normalisation + features (11 features incl. 3-/4-gram entropy + unique ratio) | DONE |
| 3 | Rule engine + threat-intel (Spamhaus, hot-reload) | DONE |
| 4 | Autoencoder | DONE |
| 5 | HDBSCAN cluster validation | DONE |
| 6 | Multi-signal consensus (binary verdict; no per-request review) | DONE |
| 7 | Audit log / Mongo (+ 90-day TTL) | DONE |
| 8 | FP-Growth attack-pattern miner — `ml/app/mining/` | DONE |
| 9 | Rule synthesis orchestrator — `ml/app/rulegen/orchestrator.py` (stub + Gemini provider wired; OpenAI/Anthropic stubs) | DONE |
| 10 | HITL rule approval + promotion — Rules tab + `/api/rules/candidates/*` + proxy `/__reload` | DONE |
| 11 | Continuous learning / drift watch + HITL **model**-promotion gate — `ml/app/model_promotion.py` + `/api/models/candidates/*` | DONE |

**Beyond the 11 SRS modules (this session):**
- Auth: JWT (HS256+bcrypt) shared between ML + proxy
- **RBAC**: 4 roles (admin / security-operator / ml-engineer / auditor), users collection, `require_role` dependency, proxy `MiddlewareRoles`, role-aware dashboard (greyed-out cards + READ ONLY badge per role)
- **MFA**: TOTP via pyotp, self-service enrollment, login flow with 412 second-stage
- **Account lockout** (SEC-4): 5 fails → 15 min; **Brute-force IP watch** (SEC-10): >10 fails / 5 min triggers alert
- **Decision override** + audit (FR4.5) on Request Log drawer
- **Model accuracy** panel (FR-MON-1): P/R/F1/FPR from operator overrides
- **CEF/Syslog export** (SI-6): background tail of audit log → CEF over UDP/file
- **Sandbox-test** (FR5.5): preview which past requests a candidate rule would match
- **Live training-loss chart** (FR7.4) during retrain
- **Safe-mode banner** (REL-2): operator can force on; global red banner across every tab
- **OpenAPI polish**: tag groups, summaries, role notes at `/docs` and `/redoc`
- **Dashboard topbar v2**: one rollup health pill + popover (was 6 pills); compact user chip
- **Char n-gram features** (3- and 4-grams) with Go ↔ Python parity test

Current branch: **`fyp-II`** (off `main`). Branch conventions and the
submission-snapshot `fyp-1` branch are explained in `docs/preferences.md`.

`todo.md` at repo root tracks the SRS/SDS backlog with tickboxes
including a "Research-paper roadmap" section at the bottom.

---

## Where everything is

**Working docs (`docs/`):**
- `docs/architecture.md` — full module table, data flow, repo layout, source
  documents (SRS, SDS, mockups).
- `docs/gotchas.md` — 42 landmines, each with the *why*. Tagged
  `[PROXY] [ML] [INFRA] [UI] [DATA] [DESIGN]` so you can grep by area.
- `docs/verified-states.md` — historical snapshots with re-verify recipes.
  Latest entry at the top is the live truth.
- `docs/roadmap.md` — FYP-II phase plan (A done, B/C/D ahead), binding
  mockup constraints, honest gaps to soften in the report.
- `docs/preferences.md` — branch conventions, commit style, working style
  notes from prior sessions. Hard rules above are the short version.
- `docs/defense-notes.md` — viva framing + deferred AI improvements that
  would unlock real ML contribution (n-grams, CRS anomaly_score, per-shape
  AE, contrastive loss).

**FYP submission documents (`fyp-documents/`):**
- `fyp-documents/fyp-I (Software Requirement Specification)/SRS Document.md`
  — canonical SRS in markdown. Match this when implementing.
- `fyp-documents/fyp-I (Software Design Specification) - 30%/LatentGuard - FYP-I SDS - 30% implementation.md`
  — canonical SDS in markdown (Chapter 3 design + architecture, 717 lines).
  Converted from the .docx via `.claude/docx2md.py` on 2026-05-22.
- Same folders carry the corresponding `.docx` and `.pptx` versions. The
  PPTX mockups are **binding** for UI work.
- `fyp-documents/fyp-0/` — earliest scoping docs (superseded but kept).

When working on a subsystem, the fast path is:
`grep '\[PROXY\]' docs/gotchas.md` (or `[ML]`, `[INFRA]`, etc.) then read
the architecture file for that area. When implementing a feature, also
search the SRS / SDS markdown to confirm the spec.

---

## Recent changes (last few commits, newest first)

Maintain this manually when you commit — it's the fastest answer to
"what happened last session?".

- `751772e` — dashboard: topbar v2 (one rollup health pill + popover; user chip
  with role badge + signout icon); role-strip under topbar; greyed-out cards
  with READ ONLY badge for roles that can't mutate the contents.
- `0429824` — high-5 / M11 full: auto-retrain on drift + HITL **model**
  promotion gate. `train_autoencoder.py --candidate` writes to
  `.candidate.*` files; `ml/app/model_promotion.py` handles the state
  machine (`training → pending → live` / `rejected` / `failed`); drift
  watcher background task auto-fires retrains when
  `AUTO_RETRAIN_ON_DRIFT=true`.
- `7d8890d` — high-4: OpenAPI / Swagger polish on `/docs` + `/redoc`.
- `592d967` — high-3: SIEM export in CEF over syslog UDP + file
  (`ml/app/siem.py`); env: `SYSLOG_HOST`/`SIEM_LOG_PATH`.
- `6c6ee9c` — high-2: model accuracy panel from operator overrides
  (`/api/models/accuracy`, FR-MON-1).
- `8560dfe` — high-1: operator-controllable safe-mode + global red
  banner (REL-2); `SafeMode.SetForced` survives the heartbeat.
- `e7e2378` — #1: Gemini Flash provider for M9
  (`ml/app/rulegen/llm_gemini.py`); falls back to stub when
  `GEMINI_API_KEY` missing. (User has no key yet; running in stub mode.)
- `ad2bf1a` — #2: sandbox-test (FR5.5) — `/api/rules/candidates/{id}/preview`
  replays the candidate's pattern items against recent audit rows; UI
  shows "would NEWLY block" rows in green.
- `a8a13a3` — #4: live training-loss chart (FR7.4) on the Anomaly Models
  tab; trainer writes `models/autoencoder.progress.jsonl`.
- `9ff3845` — #3: MFA (TOTP, pyotp) + 5-fail account lockout (SEC-4) +
  brute-force IP alerts (SEC-10).
- `6a2ae89` — #5: decision override + reason audit (FR4.5) on the
  Request Log drawer.
- `d0b5db8` — char n-gram features (3 + 4 grams); feature vector
  7 → 11; Go ↔ Python parity test in
  `proxy/internal/normalizer/normalizer_test.go`. Stale models pad/trunc
  with a one-time warning until retrain.
- `8782d2c` — RBAC: 4 roles + `users` collection + Users tab
  + `require_role` FastAPI dep + proxy `MiddlewareRoles` + audit
  `actor(role)` strings.
- `efe52c7` — quick wins: 90-day TTL on `requests` (`AUDIT_RETENTION_DAYS`),
  pin OWASP CRS v4.7.0 via `proxy/rules/90-crs/VERSION` + Dockerfile
  comment, copy-as-curl button on the audit-log drawer.
- `12722b6` — Phase B landing on `fyp-II`: M8 FP-Growth miner,
  M9 stub orchestrator, M10 approval UI + promoter + `/__reload`,
  M11-partial drift watch.
- `5a9843d` — operator-panel auth: ML JWT (bcrypt + HS256), shared
  secret with proxy; dashboard login page + token-aware fetch wrapper.

PR #3 merged `fyp-II` into `main` after `5a9843d` (merge commit
`4ca4dcb`, 2026-05-24). Everything above this line lives on `fyp-II`
and is unpushed at time of writing. Pre-merge commit history lives
in `git log main` if needed.

---

## Maintaining this file

Keep CLAUDE.md slim. When something needs durable documentation:

| Change | Goes in |
|---|---|
| New gotcha (a non-obvious landmine) | `docs/gotchas.md` (next number, tag the area) |
| Module flips status, or a new verified state with FPR/TPR/latency | `docs/verified-states.md` (top of file) |
| Roadmap reshuffle, new constraint from supervisor | `docs/roadmap.md` |
| User states a new convention or preference | `docs/preferences.md` (and mirror to hard rules above if non-negotiable) |
| Big change to data flow or new container | `docs/architecture.md` |
| Recent commit on the branch | "Recent changes" section above (last ~8 entries) |

Don't expand any section of this file past ~25 lines. If you need more room,
that means the content belongs in `docs/`.
