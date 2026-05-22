# FYP defense framing + deferred AI improvements

Captured 2026-04-27, refined 2026-05-22 — not blocking the 30 % submission,
but reread before viva and before any FYP-II ML work.

## How to defend the scope

The honest framing is **systems contribution, not model contribution**. The
novelty isn't the autoencoder (any anomaly detector would do); it's the
*pipeline*: dual-layer consensus with configurable Weighted/Majority/Strict
modes, audit log driving retraining, HITL feedback loop at the RULE layer
(not per-request — see gotcha #27), safe-mode failover, hot reload, end-to-end
TLS. Don't claim ML supremacy; claim *adaptive WAF architecture with
explicit, tunable trust between rules and ML*.

### What's defensible as-is

- 5-container stack with real OWASP CRS v4.7.0, real ML scoring, real Mongo
  audit, real dashboard, real threat-intel feeds (Spamhaus).
- 0 % FPR on real browsing AND CSIC benign — achieved by iterating the
  *training-data pipeline*, not by tuning the model. The pipeline is what
  makes the model honest.
- TLS termination, audit integrity (`fallback_used` semantics), safe-mode
  failover, hot reload, threat-intel hot-swap — production-grade plumbing
  many FYPs don't reach.
- Configurable consensus engine + per-model weight UI matches the SRS
  mockup spec exactly. Sliders are wired end-to-end (PUT persists to
  Mongo, engine re-reads per scoring call).
- 141-payload red-team battery (19 attack classes) ships with the repo.
  83.5 % blocked, gaps documented and used as input for FYP-II Phase B.

### What's hard to defend (don't volunteer in viva, but be ready)

- Current ~27 % CSIC TPR is roughly the rule-only baseline. ML adds
  ~zero detection lift on CSIC by itself **because the model is now fit to
  Juice Shop, not CSIC**. Phrase any TPR claim as "system catches X % via
  either layer" rather than "ML catches X %". This is a feature, not a
  bug — domain-tuned anomaly detection is honest about its scope.
- "Adaptive" is partial — retrains are manual today; M11 (continuous
  learning) makes it true.
- 7 numeric features can't see attack *content* — that's why CRS does the
  heavy lifting and ML mostly de-confirms / catches statistical outliers.
- P95 latency 170 ms vs 150 ms NFR — Keras predict overhead. Documented
  gap, future work points at ONNX/tflite conversion.

## Subtle AI-layer changes worth doing later

Listed by leverage-per-effort. None are blocking; revisit when starting
FYP-II Phase B (M8/M9).

1. **Char n-grams as additional features** *(small effort, large payoff)*.
   Hash byte 3-grams into a 32- or 64-dim sparse bucket and concat to the
   current 7. Same AE architecture, wider input. Likely lifts CSIC TPR from
   ~27 % → 50–60 % because attacks like `UNION SELECT`, `<script>`, `../../`
   have telltale n-gram signatures the current numeric features can't see.
   Defensible as "content-aware features".

2. **Read CRS `anomaly_score` directly** *(tiny effort)*. Coraza accumulates
   a per-request `tx.Variables().TX().Get("anomaly_score")` (weighted sum
   of matched detection-rule severities). Currently discarded; we
   reconstruct severity from `MatchedRules()` which loses information.
   Feed it straight into consensus.

3. **Per-shape AE specialization** *(medium effort)*. Separate models for
   `GET-no-args`, `GET-with-query`, `POST-form`, `POST-json`. Each only
   sees its own distribution → fewer OOD trip-wires (the bug we kept
   hitting where each new Juice Shop flow needed a retrain). Router lives
   in `pipeline.go`.

4. **Contrastive term in AE loss** *(small effort)*. Same network, but add
   a hinge loss pushing Coraza-blocked rows away from the benign manifold.
   Currently AE only learns to reconstruct benign — adding negative anchors
   from the audit log sharpens the latent space.

**Highest leverage if revisited later: (1) + (2) together.** They'd let the
report defend "27 % TPR → 60 %+, FPR still ~0 %" as a real ML contribution,
not just plumbing.
