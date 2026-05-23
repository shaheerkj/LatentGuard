# Working preferences + branch conventions

The non-negotiable rules live in CLAUDE.md (top of the file). This is the
fuller explanation.

## Branches

- **`main`** — live trunk. Carries the full Phase A ML pipeline
  (M4+M5+M6+HTTPS+dashboard rework) with the DVWA upstream. Frozen for
  FYP-II — no new work lands here directly. Never push to `origin/main`
  without explicit user approval.

- **`fyp-II`** (created 2026-05-22, off `main`) — **the FYP-II working
  branch**. Swaps DVWA → OWASP Juice Shop, adds
  `datasets/crawl_juiceshop_benign.py`, retrains the AE/HDBSCAN on Juice
  Shop benign traffic, ships threat-intel feeds + UI refresh + binary
  verdict. Same WAF code as `main` for the parts that didn't change. All
  Phase A/B/C/D work for FYP-II lands here (or in `feature/fyp-ii-*` topic
  branches off this) and gets merged back into `fyp-II` once verified.
  Don't merge back to `main` until FYP-II is delivered.

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

- **FYP-II must stay off `main`** until the user says otherwise —
  protects the 30 % submission.

- **Do not mock the ML/database in integration tests** — the value is
  end-to-end behaviour.
