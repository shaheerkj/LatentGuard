# Design decisions

Reasoning behind the choices that aren't obvious from the code. Each
of these has a specific *why* — if a panelist asks "why did you do
it this way?", these are the answers.

## Binary verdict at the edge — no per-request "review" band

**Decision:** The consensus engine returns `allow` or `block`. There
is no third "review / hold for human approval" verdict.

**Why:** A WAF that defers individual requests back to an operator
is not a WAF — it is a proxy with a queue. No production WAF
operates this way. HITL (human-in-the-loop) belongs at the *rule*
layer, where a human reviews and approves *patterns of behaviour*
(M10), not at the per-request layer where humans cannot keep up with
real-time traffic. An earlier version of LatentGuard had the
"review" verdict; it was removed after the FYP-I supervisor pointed
out the same flaw, hard.

## Dual layer in series, not parallel

**Decision:** Coraza runs first. If Coraza issues a disruptive
interruption (block), the ML scorer is skipped entirely.

**Why:**
- **Latency.** Skipping ML on confirmed-malicious traffic shaves
  20+ ms off the block path, which matters at scale.
- **Cost.** ML inference is more expensive than rule evaluation; no
  reason to spend it confirming what the rules already caught.
- **Auditability.** A single attack rarely needs two independent
  reasons to be blocked. The audit log is cleaner with one
  primary cause.

## Coraza (Go-native) instead of real ModSecurity (C)

**Decision:** Embed Coraza v3 in the Go proxy.

**Why:** Real ModSecurity is a C library that requires Apache /
Nginx / OpenResty integration. Coraza is a Go-native reimplementation
of the same rule grammar with the same CRS compatibility. We get
identical detection semantics without the C-extension build
complexity, and the proxy ships as a single ~30 MB static binary.

## Reserve rule-ID bands

**Decision:**
- 900000-999999: OWASP CRS
- 1000000-1099999: LatentGuard baseline (hand-written)
- 1500000-1599999: threat-intel rules
- 2000000-2999999: mined / synthesized rules (M9)

**Why:** Coraza errors hard on duplicate IDs. Reserving disjoint
bands makes ID conflicts impossible by construction. The dashboard's
mined-rule list never shows a candidate with ID < 2000000 — easy to
visually distinguish from hand-written rules.

## FP-Growth, not Apriori

**Decision:** Use `mlxtend.frequent_patterns.fpgrowth` for M8.

**Why:** Apriori re-scans the dataset once per candidate level —
exponential I/O as the audit log grows. FP-Growth builds a single
prefix tree and recurses, two passes total. Performance gap is
negligible on the demo (~6 K rows) but matters as the project
scales to weeks of traffic.

## Lazy import of mlxtend / pandas / tensorflow

**Decision:** Heavy imports are deferred until first use.

**Why:** A FastAPI cold start that imports TensorFlow takes ~30
seconds. Most processes never need it (the dashboard tab someone
opens at 3 AM doesn't need ML). Lazy loading keeps cold starts under
2 seconds for everything except the first ML call.

## Single JWT secret shared between ML and proxy

**Decision:** Both backends verify HS256 tokens signed with the same
shared secret.

**Why:** The dashboard signs in once and uses one token everywhere.
The alternative — separate secrets and a token exchange — adds a
network round-trip per request and a refresh-token state machine
that buys nothing for a single-admin demo. The trade-off is that
both backends must agree on the secret (compose enforces this) and
the ML service can mint tokens that the proxy accepts (used for
service-to-service `/__reload` calls).

## Approval gate at the rule layer, not the model layer

**Decision:** The autoencoder and HDBSCAN are retrained
**automatically** when the operator clicks Retrain or when training
data is augmented. There is **no** model-weight approval gate.

**Why:** Model weights are not human-interpretable; approving them
would be theatre. What the operator *can* meaningfully approve is a
candidate ModSecurity rule generated from observed patterns, because
that rule's text is readable English+regex and the operator can
predict what it will and won't match.

## Mongo as source of truth, disk files as projection

**Decision:** Live rule files (`/etc/coraza/rules/lg-generated/*.conf`)
are rewritten end-to-end on every promote/expire from the current
`rules_queue` state.

**Why:** Per-file diffs are easy to get wrong (concurrent updates,
partial writes, race with the reloader). Rewriting from a single
authoritative source guarantees that disk matches Mongo even after
a partial failure. Cost is negligible — handful of files.

## OWASP Juice Shop instead of DVWA

**Decision:** The upstream demo app is Juice Shop, not DVWA.

**Why:** DVWA's purple PHP-era UI and prominent "Damn Vulnerable Web
Application" branding made the FYP-I demo look like a classroom lab,
which undermined credibility on stage. Juice Shop is a modern Angular
SPA (OWASP Flagship project) that *looks* like a real production app
while still being deliberately vulnerable, so the WAF is seen
protecting something believable.

## No per-shape autoencoder

**Decision:** One global autoencoder over all request shapes.

**Why and trade-off:** A per-shape AE (one model per
`(method, path-prefix)` tuple) would catch shape-specific anomalies
better — a body field that's always 32-char hex is anomalous as
plain text *only in that shape*. Today the global AE pools all
shapes, which dilutes the signal. Documented in
`docs/defense-notes.md` as a real ML upgrade for future work.

## No retraining-on-drift

**Decision:** Drift detection exists; auto-retrain on drift does
not.

**Why:** The retrain trigger is one cron call away — the omission
is intentional scope-control, not a technical block. Auto-retrain
without a guard against poisoning (an attacker who can flood your
audit log with adversarial-but-benign-looking traffic can degrade
your AE) is a security regression. M10's approval gate is the
right shape for the rule layer; the model layer deserves an
analogous gate which is real engineering work, not a checkbox.
