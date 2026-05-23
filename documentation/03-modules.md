# The 11 modules

Mapped directly to the SRS module list. Each entry says **what**,
**where in code**, and **how to verify**.

## M1 — Reverse proxy + TLS termination

**What:** Inspects every HTTP/HTTPS request before forwarding to the
upstream app. Generates a self-signed cert on boot for HTTPS (or
loads a real cert from env-supplied paths).

**Where:** `proxy/cmd/proxy/main.go`, `proxy/internal/tlsutil/`

**Verify:** `curl -v https://localhost:8443/` returns Juice Shop HTML
after a TLS handshake.

## M2 — Normalisation and feature extraction

**What:** Decodes URL/body, lowercases, strips redundant whitespace,
then extracts seven numeric features per request: length, Shannon
entropy, token count, special-char ratio, digit ratio, uppercase
ratio, and a method-is-POST flag.

**Where:** `proxy/internal/normalizer/`, `proxy/internal/pipeline/`,
`ml/app/features.py`

**Verify:** Click any blocked request in the dashboard's Request Log
→ Detail drawer shows the seven feature values.

## M3 — Rule engine + threat-intel feeds

**What:** Coraza v3 loads OWASP CRS v4.7.0 + our custom baseline rules
(IDs 1000000-1099999) + a threat-intel rule (ID 1500001) that
`@ipMatchFromFile`s a list of Spamhaus DROP+EDROP CIDRs. A background
goroutine refreshes the CIDR list every 12 h and triggers
`Engine.Reload()` so updates take effect without restart.

**Where:** `proxy/internal/coraza/`, `proxy/internal/threatintel/`,
`proxy/rules/`

**Verify:** `GET /__threatintel` (authed) shows `entry_count ≥ 1500`
and `last_error: ""`.

## M4 — Autoencoder anomaly scoring

**What:** Dense feed-forward autoencoder, 7→[8→4→8]→7. Trained on
clean traffic (CSIC + Juice Shop crawler). At inference,
reconstruction error normalised to [0, 1] is the anomaly score.
Higher = more anomalous.

**Where:** `ml/app/models.py`, `ml/training/train_autoencoder.py`,
artifacts under `ml/models/`

**Verify:** `GET /api/models/status` shows `autoencoder.loaded: true`,
threshold, p50/p95/p99 reconstruction errors, training sample count.

## M5 — HDBSCAN cluster validation

**What:** HDBSCAN runs on the autoencoder's bottleneck embedding
(4-dim). At inference, `approximate_predict` returns cluster label and
membership strength; strength ∈ [0, 1] is inverted to give an outlier
score. Noise-class points are bumped to 0.75 minimum.

**Where:** `ml/app/models.py`, `ml/training/train_hdbscan.py`

**Verify:** `GET /api/models/status` shows `hdbscan.loaded: true`,
cluster count, noise ratio.

## M6 — Multi-signal consensus

**What:** Combines rule_score (from Coraza severity), anomaly_score
(M4), outlier_score (M5) using one of three modes — `weighted`,
`majority`, `strict` — and a threshold. Persists configuration to
Mongo; the operator tunes live from the Consensus tab. **Verdict is
binary (allow / block) — no per-request "review" band**, because a
WAF that punts decisions back to humans on every uncertain request is
useless on stage.

**Where:** `ml/app/consensus/`, dashboard Consensus tab

**Verify:** Change weights on the Consensus tab → Save → fire a
borderline attack → the chosen mode's logic is reflected in the
`reasons` array on the resulting audit row.

## M7 — Audit log

**What:** Every decision (allow + block) is appended to
`requests` in Mongo with full request canonicals, features, every
rule that fired, ML scores, final action, and latency. Indexes
support the dashboard's filters: `timestamp` desc, `request_id`
unique, `(final_action, timestamp)` and `(source_ip, timestamp)`.

**Where:** `proxy/internal/storage/mongo.go`,
dashboard Request Log tab

**Verify:** Fire one request → it appears in the log tab within 5s
(dashboard tick interval).

## M8 — FP-Growth attack-pattern miner *(this phase)*

**What:** On operator trigger, scans recent blocked requests in
`requests` and runs FP-Growth over a small alphabet of items:
path-prefix, method, fired rule IDs, source /24, signal bands
(`ae:high`, `outlier:high`), `body:present`. Returns ranked itemsets
with support count and sample request_ids.

**Where:** `ml/app/mining/miner.py`

**Verify:** Fire a series of similar attacks → Rules tab → Run
miner with `min_support=0.05` → output shows the itemset(s) that
describe the attack series.

## M9 — Rule synthesis orchestrator *(this phase, stub)*

**What:** Takes itemsets from M8 and renders them as chained
`SecRule` blocks (Coraza syntax). Pluggable provider:
- `stub` (default) — template renderer; no external API
- `openai` / `anthropic` / `gemini` / `groq` — hooks present, fall
  back to stub when no API key is set

The stub renderer is enough to demo the full mining-to-blocking
loop. Swapping in a real LLM is a one-function change.

**Where:** `ml/app/rulegen/orchestrator.py`

**Verify:** After a mining run, Rules tab shows new candidates with
non-empty `rule_text` and `provider: "stub"`.

## M10 — HITL rule approval + promotion *(this phase)*

**What:** State machine for candidate rules (`pending → approved →
live → expired` and `→ rejected`). Operator approves/rejects/edits
from a dashboard tab. On approve: rule transitions to `live`, the
promoter rewrites `/etc/coraza/rules/lg-generated/lg-<id>.conf` from
the current set of live rules, then POSTs the proxy's
`/__reload` endpoint (signed with a JWT from the shared secret).
Coraza's `Engine.Reload()` picks up the new files without
restart. Edits demote to `pending` so the change goes through
approval again. Full edit history is kept per rule.

**Where:** `ml/app/rulegen/store.py`, `ml/app/rulegen/promoter.py`,
dashboard Rules tab, `proxy/cmd/proxy/main.go` `/__reload` handler

**Verify:** Approve a candidate → file appears in the proxy
container under `/etc/coraza/rules/lg-generated/` → the attack the
rule was built from now returns 403 (M3 layer caught it).

## M11 — Drift watch *(this phase, partial)*

**What:** `/api/models/drift` computes z-score of mean AE
anomaly_score over the last `window_min` minutes vs a baseline
window. `drift_detected` flag flips true when |z| ≥ 2.0 and both
windows have ≥30 samples. Dashboard topbar pill turns red when
drift fires. **What's missing:** the auto-retrain trigger; today
the operator must click Retrain manually after seeing the pill.

**Where:** `ml/app/api.py` `models_drift` endpoint, dashboard topbar

**Verify:** `GET /api/models/drift` returns a `z_score` value after
~30 requests have accumulated in both windows.
