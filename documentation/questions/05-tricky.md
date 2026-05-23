# Questions — curveballs and gotcha questions

The "I'm going to try to rattle you" questions. Answer calmly,
acknowledge the point if it's valid, defend the choice if it isn't.

### Q. Isn't this just ModSecurity with a pretty dashboard?

No. ModSecurity terminates at the rule-engine layer — humans write
the rules, period. LatentGuard adds an unsupervised ML layer that
votes on every decision, an audit-driven pattern miner that
surfaces attack shapes from the log, and a HITL gate that converts
those patterns into permanent rules via human approval. The
ModSecurity portion (via Coraza) is one of seven subsystems, not
the whole project.

### Q. The autoencoder is tiny. Couldn't I get the same result with a one-line distance check?

You'd get *some* of the result — Mahalanobis distance from a fitted
multivariate Gaussian would flag anything far from the training
distribution. What you'd lose: the autoencoder's non-linear
projection captures interactions between features that a Gaussian
can't (e.g., "high entropy is normal for POST bodies but anomalous
in URLs"). HDBSCAN running on the AE bottleneck would also become
meaningless because there'd be no learned latent space to cluster.
The size is right for the data; it isn't impressive because the
problem doesn't require an impressive model.

### Q. You're using OWASP CRS. So you didn't write the rules.

Most of them, no. We wrote ~50 baseline rules at IDs 1000000+ to
cover gaps visible in our demo's traffic. The originality of this
FYP isn't in writing yet another rule library — it's in the
feedback loop that *generates new rules* from observed traffic.
Pretending we reimplemented CRS would be dishonest and pointless;
shipping a working system that uses CRS as a foundation is good
engineering.

### Q. The miner output looks templated. Is the "AI" in this project actually AI?

The mining is unsupervised ML (FP-Growth on the audit log) and the
scoring is unsupervised deep learning (autoencoder + HDBSCAN). The
rule renderer is a template today because the LLM hook isn't wired
yet — the architecture supports swapping in Gemini / Groq /
Claude / GPT-4o as a one-function change, and we'd do that with an
API key. The mining and scoring are AI; the renderer is the
plug-point.

### Q. What if I send a payload that looks exactly like normal traffic?

Then both layers might miss it on the first request. That's the
honest answer. What happens *next* matters: every request goes into
the audit log, the miner runs over the recent log on operator
trigger, and patterns that recur — even if subtle — surface as
candidate rules. The system is designed to learn over time, not to
be omniscient on first contact.

### Q. Show me a request that bypasses your WAF.

Most heavily-obfuscated XSS payloads in the test battery bypass
both layers (~17% of the red-team set). Example: deeply nested
JSON with base64-encoded `<script>` tags inside a stringified
field. We document this honestly in `documentation/06-results.md`.
The mining loop is the answer — once such a bypass succeeds and
gets logged, the pattern surfaces and the operator can write a
custom rule against the encoding.

### Q. Why didn't you label some traffic and train a supervised classifier?

Labeling at scale is expensive and the labels are wrong by the time
you ship — adversaries adapt faster than label sets. Unsupervised
methods don't need labels and don't go stale the same way. We do
use weak supervision: the `only_blocked=True` miner default
implicitly treats consensus-blocked requests as positives, but no
human labels were collected.

### Q. The dashboard refreshes every 5 seconds. That's wasteful.

It is. WebSocket push from the proxy would be the correct
architecture for production. For a single-operator demo at <1 req/s
the polling cost is negligible and adds no new dependency. Real
production at thousands of req/s would need the push model.

### Q. What if Mongo goes down?

Audit logging fails gracefully (logged, never blocks the hot
path), `/api/metrics` returns 503, dashboard tiles show empty.
Detection itself doesn't depend on Mongo — Coraza and ML scoring
run from in-memory state. The proxy stays up. Recovery: restart
Mongo, the proxy reconnects on next request.

### Q. What about insider threat?

Out of scope. Single-admin model assumes the operator is trusted.
Real production would need audit-of-the-audit (who-approved-what
trail), RBAC, and tamper-evident logging. The state-machine in
`rules_queue` does keep an `edit_history` per rule which is the
first step.

### Q. Performance under DDoS?

The proxy itself isn't a DDoS mitigation layer; that should sit
upstream (CDN, load balancer with rate limiting). At the proxy
layer we have a hard `ReadHeaderTimeout: 5s` to bound slowloris,
but no per-source rate limiting in the WAF itself. Adding it
would be a 100-line middleware in front of the Coraza handler.

### Q. Why is the demo upstream OWASP Juice Shop and not a real app?

Two reasons. Demonstrating a WAF needs a vulnerable upstream;
production apps don't have known vulnerabilities that we can fire
attacks at on stage. And Juice Shop is OWASP Flagship — using it
signals to evaluators that the demo isn't artificially staged
("look, my WAF blocks my own deliberately bad code") but tested
against the canonical vulnerable-app benchmark.

### Q. You changed the default password from admin/admin halfway through development. Why?

Because the screenshot of the login page showed `admin/admin` as
a hint to anyone watching, including someone shoulder-surfing
during the viva. Default credentials in a screenshot is a security
own-goal. Rotated to `shaheerkj / <20-char random alnum>`; the
password lives outside the repo, only the bcrypt hash is committed.

### Q. The SDS / SRS describe X. Why doesn't your project do X?

(General answer to the "where is X?" family of questions.) The
SDS and SRS are aspirational specifications. The CLAUDE.md hard
rule on this codebase, set by me explicitly, is:
*"Before implementing any feature you spot in the SRS/SDS, ASK the
user whether they actually want it built."* Many SDS features fill
academic chapters; not all map to viva-demoable functionality. We
prioritised features that strengthen the *demo*: working ML, working
mining, working HITL approval, working hot-reload. Documentation
features without a demo path are deferred honestly.

### Q. If I gave you this project as a job, would you ship it to production?

Not as-is. Pre-production hardening would need: real TLS certs,
RBAC + audit-of-the-audit, rate limiting, Mongo replica set + TTL
indexes, a real LLM provider with rate-limit handling, per-shape
autoencoders, model-promotion HITL gate, comprehensive unit tests,
SIEM integration. **As a research demonstrator of the adaptive
feedback loop architecture, yes — that part works and is the
contribution.**
