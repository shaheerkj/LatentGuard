# LatentGuard — Documentation

This folder is the **outside-in** view of the project: written for a
reader (supervisor, evaluator, future you) who has never seen the
codebase before. The `docs/` folder at the repo root is the
**inside-out** view — internal working notes, gotchas, and verified
snapshots used by contributors. Read this folder first, then drop into
`docs/` only when you need to dig.

## What is LatentGuard?

An **Adaptive Dual-Layer Web Application Firewall** that combines a
deterministic rule engine (Coraza + OWASP CRS) with an unsupervised
machine-learning layer (autoencoder + HDBSCAN) and a feedback loop that
**mines its own audit log** to propose new defensive rules. A human
operator approves the candidate rules from a dashboard; approved rules
are hot-reloaded into the live WAF.

**One-line elevator pitch:** A WAF that learns from what it sees and
asks a human to confirm what to do about it.

## Read in this order

1. [01-overview.md](01-overview.md) — problem statement, scope, what
   *this* WAF does that off-the-shelf WAFs don't.
2. [02-architecture.md](02-architecture.md) — components, request flow,
   data flow, every container and what it does.
3. [03-modules.md](03-modules.md) — every one of the 11 SRS modules,
   what it does, where to find it.
4. [04-setup.md](04-setup.md) — how to bring the whole stack up
   locally and sign in.
5. [05-usage.md](05-usage.md) — dashboard tour, how to run an attack
   demo end-to-end.
6. [06-results.md](06-results.md) — measured TPR/FPR, latency, threat
   intel coverage.
7. [07-design-decisions.md](07-design-decisions.md) — non-obvious
   choices and the reasoning behind them.

## Defense / committee preparation

The [questions/](questions/) sub-folder collects the questions a
panel is most likely to ask, organised by theme, each with a
prepared answer. Read these the night before the viva.

## Tools used

| Layer | Technology |
|---|---|
| Reverse proxy / WAF engine | Go, Coraza v3, OWASP CRS v4.7.0 |
| ML service | Python 3.11, FastAPI, TensorFlow, HDBSCAN, mlxtend |
| Storage | MongoDB 6 |
| Upstream demo app | OWASP Juice Shop |
| Dashboard | Vanilla HTML/CSS/JS, Chart.js |
| Orchestration | Docker Compose (5 containers) |
| Auth | JWT (HS256) + bcrypt |
| Threat intel | Spamhaus DROP + EDROP feeds |
