# LatentGuard Project Assessment — 2026-09-01

## Purpose and scope

This file is meant to be a grounded project assessment for the current repository state, not a speculative summary of what a branch might contain. I reviewed the live repo and the branch history before writing this:

- `README.md`
- `docs/architecture.md`
- `docs/verified-states.md`
- `docs/preferences.md`
- `ml/app/rulegen/orchestrator.py`
- `proxy/internal/auth/auth.go`
- `dashboard/js/auth.js`
- `git log` / `git diff` between `main` and `fyp-II`

## Executive summary

The current checked-out branch is `main`, and the repo is in a credible, merged state for an FYP submission. The earlier assessment in this folder overstated the branch gap by treating `fyp-II` as if `main` were stale and unmerged. That is not the current reality.

What the repository state actually shows:

- `main` is the live trunk and includes the merge of the `fyp-II` work (`Merge pull request #3 from shaheerkj/fyp-II` at `4ca4dcb`).
- `fyp-II` still exists as a branch with additional later changes, but it is not “the only real branch” nor is `main` a stale, older snapshot.
- The project is best described as a working, integrated prototype with a clear FYP scope: core WAF + ML + audit + mining + rule approval flow is present, but some later-stage enhancements are framed as branch-specific or deferred rather than universal repo truth.

## Current status: honest read of the codebase

### 1. Core project goal is believable and implemented

The project matches the description in `README.md` and `docs/architecture.md`:

- Go reverse proxy + Coraza + OWASP CRS + threat-intel
- Python ML service for anomaly scoring
- Mongo audit log and explainability
- FP-Growth mining to generate candidate rules
- dashboard-based approval/reload flow

This is not a toy scaffold; it has real integration points across proxy, ML, dashboard, Mongo, and rule distribution.

### 2. Module status should be read conservatively

The repo itself documents a status of `10.5 / 11` modules in `README.md`, and in the code the M11 drift-watch work is a partial implementation rather than a fully automated continuous-learning loop.

The most defensible assessment is:

| Module | Status | Evidence |
|---|---|---|
| M1–M3 | ✅ Done | Proxy, Coraza, threat-intel, rule loading, normalizer |
| M4–M6 | ✅ Done | Autoencoder/HDBSCAN/consensus logic and config |
| M7 | ✅ Done | Mongo audit logging and explainability |
| M8 | ✅ Done | `ml/app/mining/miner.py` present and wired into candidate generation |
| M9 | ⚠️ Partial / stub-based | `ml/app/rulegen/orchestrator.py` explicitly falls back to stub rendering when no real LLM provider is configured |
| M10 | ✅ Done | Candidate rule approval and promotion flow exists |
| M11 | ⚠️ Partial | Drift detection exists; auto-retrain trigger is not presented as complete in the repo docs |

This is more accurate than claiming that the repo has a fully implemented live Gemini or fully automatic retraining loop across the whole project.

### 3. Security and auth are present, but not portrayed as a miracle stack

The repo contains explicit JWT authentication for dashboard and admin endpoints:

- `proxy/internal/auth/auth.go`
- `dashboard/js/auth.js`
- `ml/app/auth.py`
- `ml/app/auth_router.py`

This is a meaningful operational improvement and a real production concern. But the repo still reads like an FYP system that is feature-complete enough to demo and reason about, not as a polished enterprise-grade product with every advanced control claimed in some speculative summary.

### 4. The branch history matters, and the earlier assessment got that wrong

The actual branch evidence is straightforward:

- `main` HEAD: `7ee8e03`
- `fyp-II` HEAD: `8116aa4`
- merge base: `937dc72`
- `main` contains `Merge pull request #3 from shaheerkj/fyp-II`

This means the repository should not be assessed as “main was frozen while fyp-II overtook it.” The branch relation is more nuanced:

- `main` is the canonical trunk after the merge.
- `fyp-II` is a side branch with additional later work.
- `main` is not simply older or less complete than `fyp-II` in the current repo snapshot.

## Quality assessment

### Strengths

- Clear architecture and domain fit.
- Real integration across multiple services rather than a mock demo.
- Auditability is good: scoring decisions and reasons are stored and partly explainable.
- The project shows a credible progression from rule-based filtering to ML-assisted mitigation.
- The documentation is surprisingly mature relative to a student project.

### Gaps / caveats

- Several “full” claims should be treated carefully unless re-verified in the current branch.
- M9 is implemented as a stub-based orchestrator by default; real provider integration is not universal repo reality.
- M11 is a drift-detection foundation, not a fully automated learning loop.
- Branch-specific claims should be tied to the actual branch, not assumed to apply to all branches equally.

## Recommendation

For a realistic assessment of this repository as it currently sits on `main`:

1. Treat the project as a strong FYP prototype with a credible end-to-end architecture and full submission-grade narrative.
2. Treat the advanced or branch-specific enhancements as optional, candidate improvements rather than confirmed repo-wide state.
3. Use `main` as the canonical baseline and `fyp-II` as a feature-branch comparison point, not as “the branch that supersedes the repo.”

### Bottom line

The project is good, coherent, and credible, but the earlier assessment was too absolute in how it framed branch positions and feature completeness. The repo is not “stale main vs advanced fyp-II” in a simplistic sense; it is a merged trunk with additional branch-specific changes that should be treated carefully and verified before being described as universal project status.
