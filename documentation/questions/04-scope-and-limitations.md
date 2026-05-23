# Questions — scope and limitations

The honest-gaps file. Most "where is X?" questions come from the
panel reading the SRS / SDS and comparing to the running system.
Have these answers ready and confident.

### Q. The SRS describes six layers — where are they all?

The SRS layering is an academic-chapter framing of what runs as
five containers. Reverse proxy + WAF = layers 1+2; ML service = layer
3; consensus = layer 4; mining + rule generation + HITL = layers 5+6;
audit storage cuts across them. Every layer's responsibilities are
implemented — they just don't each get a dedicated container, which
would be operational overhead for no functional gain.

### Q. The SDS mentions RBAC, MFA, and SSO. None implemented?

Single-admin JWT auth is implemented; multi-role RBAC, MFA, and SSO
are not. The SRS/SDS contain these as aspirational sections that
fill academic chapters. For a *demo* FYP, single-admin is the right
scope — adding RBAC would require a user management UI, a role
assignment workflow, and per-endpoint policy that buys nothing on a
single-evaluator demo. The auth code is structured so that adding
roles is a per-endpoint dependency change, not a refactor.

### Q. The SDS shows Kubernetes deployment. Not done?

Docker Compose is the deployment target for the FYP demo.
Kubernetes is the right answer for production at scale; it's the
wrong answer for a single-evaluator demo box. The Compose file
maps cleanly to a Helm chart, but writing one is multi-week work
that doesn't improve detection.

### Q. The SDS mentions federated learning. Not built?

Federated learning across multiple deployments needs multiple
deployments — we have one. The pattern is genuinely useful in the
real world (sharing learnings across customers without sharing
traffic) but academically irrelevant for a one-customer demo.
Documented as future work.

### Q. What about SHAP / LIME explainability?

Not implemented. The autoencoder uses 7 interpretable features and
the consensus engine's reasons are returned in plain text per
decision — that's "soft" explainability that satisfies the
"why was this blocked?" question on a per-request basis. Formal
SHAP attributions would be a nice viva-tab demo but don't change
operator decisions, since the rule layer already gives them
explicit rule IDs to act on.

### Q. The SRS shows attack classes like XXE and SSRF. Coverage?

Both are covered via OWASP CRS (rules in the 920000 and 930000
ranges). Not in our custom baseline because CRS already does the
heavy lifting. If asked to demo, fire an XXE payload against
`/rest/products/search` — CRS catches it.

### Q. The SRS implies you'd build your own ruleset from scratch.

Building a ruleset *from scratch* would reproduce CRS poorly. We
took the engineering-rational path: use CRS as the baseline (10k+
mature rules), layer our custom rules at IDs 1000000+ to cover gaps
visible in our demo's traffic, and reserve IDs 2000000+ for
mined/synthesized rules — which IS where original research happens.
The originality is in the **feedback loop**, not in reimplementing
ModSecurity.

### Q. M9 is a stub — that's a limitation, isn't it?

Yes and no. The orchestrator architecture is real: pluggable
provider, fingerprint dedup, rule-ID allocator, hot-reload pipeline.
The stub renderer produces working ModSecurity rules that hot-load
and block their target patterns. Swapping in a real LLM (Gemini,
Groq, OpenAI) is one function — `_render()` in
`ml/app/rulegen/orchestrator.py` — and the rest of the pipeline
keeps working unchanged. We could not justify spending FYP budget
on API credits for a feature that the stub demonstrates end-to-end.

### Q. M11 is partial — what's missing?

Drift detection is fully implemented; auto-retraining on drift is
not. Adding it is a 20-line change (call the existing retrain
subprocess when drift_detected fires). We left it out *on purpose*
because auto-retrain without a poisoning guard is a security
regression — an attacker shaping the audit log can shift training
distribution. The right fix is a HITL gate analogous to M10, which
is real engineering, not a checkbox.

### Q. Test coverage?

End-to-end integration tests via `attacks/run_attacks.py` (141
payloads, 19 attack classes, plus 12 benign-flow checks) — these
prove the entire stack catches what it should and doesn't catch
what it shouldn't. Unit-test coverage is thin and we know it —
deliberately, because for a security system, unit-tested
components that integrate badly are worse than integration-tested
components with thinner unit coverage.

### Q. What about IPv6?

The proxy handles IPv6 connections (Go's `net/http` is dual-stack
by default). The miner's `/24` aggregation is IPv4-only; for IPv6
the appropriate aggregation would be `/64`, but IPv6 attacker
traffic is rare enough on the demo that we haven't generalised
the function. One conditional in `ml/app/mining/miner.py:_ip_slash24`.

### Q. Body size limits?

Coraza's `SecRequestBodyLimit` defaults apply; we haven't tuned
them. For payload-heavy attacks (huge JSON XXE bombs etc.) Coraza
will truncate at the configured limit and inspect what it has, which
is the safe default. Not exposed in the dashboard but
configurable via the `00-setup.conf` directives file.

### Q. WebSocket support?

Coraza inspects the upgrade handshake but not the post-upgrade
frames. WebSocket-borne attacks are a known gap; out of scope for
the FYP because Juice Shop's WebSocket surface is minimal and
demonstrating WS-WAF would require a different upstream app.

### Q. HTTP/3 / QUIC?

Not supported. The Go `net/http` stack doesn't natively serve
HTTP/3 without `quic-go`, which would be a bigger upgrade than the
FYP scope justifies. HTTP/1.1 and HTTP/2 cover the test corpus.

### Q. If you had three more months, what would you build?

Three things in priority order:
1. Wire a real LLM (Gemini free tier) into M9 so candidate rule
   quality jumps from template-quality to LLM-quality.
2. Add character-level n-gram features (3-4 grams) to the
   autoencoder. Documented in `docs/defense-notes.md` as the
   single biggest ML upgrade per engineering hour.
3. Build the model-promotion HITL gate (M11-full) so auto-retrain
   on drift becomes safe to ship.

Everything else is polish.
