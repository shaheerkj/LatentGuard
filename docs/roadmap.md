# FYP-II roadmap

Working branch: `fyp-II` (off `main`). 7 of 11 SRS modules done as of
2026-05-22. Four left: M8, M9, M10, M11 — all FYP-II Phase B/C/D backbone.

## Phase plan

| Phase | SRS Modules | Backend | Dashboard |
|---|---|---|---|
| ~~A~~ | ~~M3 (FE-2 finish)~~ | **DONE 2026-05-22 on fyp-II.** Spamhaus DROP+EDROP fetched on boot + every 12h via `internal/threatintel`, atomic data-file rewrite, `coraza.Engine.Reload()` hot-swaps the WAF. Status at `GET /__threatintel`. Rule 1500001 phase:1. | ✓ "Threat intel" status card shipped (Blocklist status + Intel sources, two cards in split layout). |
| **B** | M8 + M9 | FP-Growth miner over `latentguard.requests` confirmed-block subset → LLM rule synthesis via Groq / OpenRouter free-tier API → SecLang draft. Inputs come from the 21 known leak classes documented by the red-team battery. | "Proposed Rules" table on the Rules tab (currently a placeholder). |
| **C** | M10 | HITL approve/reject/edit API; versioned rule store; hot-reload into Coraza without restart. **Foundation already shipped**: `coraza.Engine.Reload()` exists, used by threat-intel; M10 just reuses that path with an approve/reject UI on rule diffs. HITL is on **rules**, not individual requests (see gotchas #27). | Approve/Reject UX with approver audit trail. |
| **D** | Auth + M11 | JWT auth + RBAC (admin / auditor / ml-engineer); scheduled drift-watch → retrain trigger. | Login screen; Training Pipeline screen (mockup M7). |

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
