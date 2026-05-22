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
- **FYP-II work stays off `main`.** It protects the submitted 30 % snapshot.
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

## Module status (7 / 11 done)

| # | Module | Status |
|---|---|---|
| 1 | Reverse proxy + TLS | DONE |
| 2 | Normalisation + features | DONE |
| 3 | Rule engine + threat-intel | DONE (this session) |
| 4 | Autoencoder | DONE |
| 5 | HDBSCAN cluster validation | DONE |
| 6 | Multi-signal consensus | DONE (binary verdict, no review band) |
| 7 | Audit log / Mongo | DONE |
| 8 | FP-Growth attack-pattern miner | not started — FYP-II Phase B |
| 9 | LLM rule synthesis | not started — FYP-II Phase B |
| 10 | HITL rule approval (NOT per-request) | not started — FYP-II Phase C |
| 11 | Continuous learning / drift watch | not started — FYP-II Phase D |

Current branch: **`fyp-II`** (off `main`). Branch conventions and the
submission-snapshot `fyp-1` branch are explained in `docs/preferences.md`.

---

## Where everything is

- `docs/architecture.md` — full module table, data flow, repo layout, source
  documents (SRS, mockups).
- `docs/gotchas.md` — 28 landmines, each with the *why*. Tagged
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

When working on a subsystem, the fast path is:
`grep '\[PROXY\]' docs/gotchas.md` (or `[ML]`, `[INFRA]`, etc.) then read
the architecture file for that area.

---

## Recent changes (last few commits, newest first)

Maintain this manually when you commit — it's the fastest answer to
"what happened last session?".

- `45b735a` — remove per-request `review` verdict; WAFs are binary at the
  edge. HITL belongs at the *rule* layer (M10), not on individual requests.
- `f496a5d` — UI: bigger fonts + projector-friendly layout; split Threat
  Intel into two cards (Blocklist status / Intel sources).
- `719c77e` — UI: dashboard visual refresh (KPI icons, layered surfaces, TI
  card rework).
- `5fb2959` — fix(dashboard): drawer-backdrop covered the whole page on load.
- `bec6c00` — dashboard: browsable audit log with filters, pagination,
  detail drawer.
- `e2614b9` — dashboard: live threat-intel card + CORS on proxy status
  endpoints.
- `0dc29f6` — M3 / FE-2: threat-intel blocklist (Spamhaus DROP+EDROP) with
  hot reload via `coraza.Engine.Reload()`.
- `5330630` — attacks: 141-payload red-team battery across 19 classes.
- `1be93f5` — fyp-II: swap DVWA upstream for OWASP Juice Shop.

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
