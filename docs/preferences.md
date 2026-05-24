# Working preferences + branch conventions

The non-negotiable rules live in CLAUDE.md (top of the file). This is the
fuller explanation.

## Branches

- **`main`** — live trunk. **Now carries the full FYP-II 70 % snapshot**
  after PR #3 (merge commit `4ca4dcb`, 2026-05-24) brought `fyp-II` up
  to `937dc72` in. **`main` is hands-off again** — no direct work
  lands here. New work continues on `fyp-II`; future stable cuts will
  be merged in via PR. Never push to `origin/main` without explicit
  user approval.

- **`fyp-II`** (created 2026-05-22, off `main`) — **the FYP-II working
  branch**. After the 2026-05-24 merge to main, this is the
  active-development branch and is N commits AHEAD of `origin/main`.
  All new feature work lands here. The user controls when the next
  PR-merge to `main` happens.

- **`fyp-1`** (created 2026-04-30, commit `b219548`, on `origin`) —
  **the 30 % submission snapshot**. Same code as `main` but with
  `ML_DISABLED=true` set in `infra/docker-compose.yml` so the Phase A ML
  layer is gated off. This is the branch the supervisor evaluates; it
  cleanly demonstrates M1+M2+M3+M7 without the in-progress autoencoder
  mis-classifying benign DVWA traffic. Don't merge `fyp-1` back into
  `main` — they are deliberately divergent on the `ML_DISABLED` line and
  the diff *is* the demarcation between the 30 % scope and FYP-II Phase A
  work. To switch demo modes: `git checkout fyp-1` (rule-only) vs
  `git checkout main` (full ML).

- **`feature/fyp-i`** — historical; bundled the original FYP-I baseline +
  Phase A work; merged into `main` on 2026-04-26 then retired. Local-only
  stale branch — safe to delete when convenient.

## Commits

- **Authored as `Syed Shaheer Khalid <shaheerkjaffer@gmail.com>`. NEVER
  include `Co-Authored-By: Claude` or any other Claude / Anthropic
  attribution line** in commit messages, PR descriptions, or generated
  artefacts. This is an academic FYP — co-authorship by an AI would
  invalidate the submission. The user has been explicit about this and
  re-stated it on 2026-05-22. Do not add it under any circumstance, even
  when the default Claude Code commit footer would include it.

- **NEVER `git push` without an explicit user instruction.** Even on
  feature branches like `fyp-II`, even after a clean local commit, even
  when the user has previously approved a push — that approval was for
  that one push, not future ones. Wait for the user to type the word
  "push" (or equivalent). Re-stated on 2026-05-22 after a previous-session
  over-step. Local commits are fine; remote sharing is the user's call
  every time.

- Commit messages: subject + bullet body explaining *why* and *what
  verified*.

## Working style (from prior sessions)

- **Verify before declaring done.** "It compiles" ≠ "it works". Run the
  live stack, hit it with curl / replay, check the audit log. The user
  has corrected this twice.

- **SRS / SDS are aspirational documentation, not a TODO list.** Files
  under `fyp-documents/` describe the *full envisioned system* — including
  features written purely to populate academic chapters (full RBAC, MFA,
  K8s/HPA, federated learning, SHAP/LIME explainability, multi-tenancy,
  etc.). Some of these will get built, some won't, and some have already
  deliberately diverged (e.g. binary verdict instead of three-arm — see
  gotcha #27). Before implementing anything spotted in the SRS/SDS,
  **ask the user first**. "The SDS says X" is not sufficient justification
  on its own. Re-stated 2026-05-22 after the user's explicit instruction.

- **Terse responses.** Skip restating the prompt and trailing "Summary:"
  sections.

- **Ask before risky actions** (force push, branch deletion, dropping
  containers with named volumes, anything that touches `main`).

- **`main` is hands-off; only merge to it via an explicit PR the user
  asks for.** After PR #3 (2026-05-24) it carries the FYP-II 70 %
  snapshot. New work continues on `fyp-II`; the user calls the next
  PR-to-main moment.

- **Use a merge commit (no fast-forward, no squash) when merging
  `fyp-II` → `main`.** Squash destroys per-commit history; rebase
  rewrites every hash and orphans `origin/fyp-II`. `git merge --no-ff`
  preserves the full branch shape and gives a single revertible anchor
  commit on `main`. (Established as a hard rule on 2026-05-24 when the
  user asked which option was safest.)

- **Do not mock the ML/database in integration tests** — the value is
  end-to-end behaviour.
