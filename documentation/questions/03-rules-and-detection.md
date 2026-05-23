# Questions — rules, detection, and security

### Q. What attacks can you block today?

The OWASP Top 10 shapes — SQL injection (classic, stacked, blind),
XSS (reflected, stored, DOM, event-handler), path traversal, command
injection, scanner User-Agents, SSRF probes, LDAP injection, XXE,
deserialisation markers, host-header injection — plus IP-based
blocks via threat-intel. CRS v4.7.0 covers most; our custom baseline
rules at ID 1000000+ extend coverage on the demo's most-tested
shapes.

### Q. What's your false positive rate?

0% on a 12-flow benign Juice Shop battery (login, register, browse,
search, add-to-basket, etc.). On the synthetic test set this is a
clean number; in production a real WAF would see a higher FPR until
the consensus engine is tuned to the deployment's traffic
distribution.

### Q. How do you handle encrypted traffic?

The proxy terminates TLS on `:8443` and inspects plaintext. For a
backend that requires TLS to upstream too, the proxy re-encrypts
on the outbound leg (Go's `httputil.NewSingleHostReverseProxy`
handles this transparently). End-to-end encryption between client
and upstream isn't a WAF feature — inspection requires termination.

### Q. Can attackers bypass by encoding?

We normalise before inspection: URL-decode, lowercase, strip
redundant whitespace. The `canonical_*` fields in the audit log
show what Coraza and the ML service actually saw. CRS includes
double-decoding and Unicode normalisation transformations on its
rules. Coverage gaps exist — heavily-obfuscated payloads in the
red-team battery account for most of the 17% miss rate.

### Q. What's your defence against rule-engine bypasses?

Defense in depth — the ML layer is precisely there to catch what
rules miss. An attacker who crafts a payload that slips past CRS
still has to look like "normal traffic" to the autoencoder. The
consensus engine's `weighted` mode blocks when *either* signal
fires strongly enough, not requiring both.

### Q. How are rules updated?

Three sources, three mechanisms:
- **CRS rules** — baked into the proxy image, updated by rebuilding
  with a new CRS version pinned in the Dockerfile.
- **Threat-intel CIDRs** — fetched from Spamhaus every 12 h, written
  to `threatintel.data`, hot-reloaded via `Engine.Reload()`.
- **Mined rules (M9)** — written to `/etc/coraza/rules/lg-generated/`
  on operator approval, hot-reloaded via the same mechanism.

No restart required for either kind of update.

### Q. What's the trust model for the M9 stub rules?

Stub rules are *templates* — they translate FP-Growth itemsets into
chained `SecRule` blocks with conservative defaults (`deny`,
`status:403`, `severity:WARNING`). The operator reviews the full
rule text before approval, so trust ultimately rests on the human,
not the renderer. When a real LLM is wired in, the same trust
model applies — operator approval is mandatory.

### Q. What stops the operator from approving a bad rule?

Nothing in the system. The operator is the authority. What the
system does provide: full rule text shown in the edit modal before
approval, the pattern itemset that drove the rule, the support
count, sample request IDs to spot-check. After approval, expiring
the rule is one click and a hot-reload.

### Q. How do you prevent the mining loop from amplifying false positives?

Two ways. The miner defaults to `only_blocked=True` — it mines from
the audit subset that's already been classified as malicious by
consensus, so a benign request can't seed a candidate rule. And
M10 requires explicit human approval before any mined pattern
becomes a live rule. The loop is human-gated, not autonomous.

### Q. What happens if an attacker can poison your audit log?

They can't write to it directly — the audit log is server-side
state behind the proxy. They *can* shape what gets written by
making requests, but every request that lands in the log was
already evaluated by both layers. The worst-case attack is
crafting many borderline-malicious requests that get blocked but
also look like legitimate traffic, hoping the miner surfaces
benign patterns. The M10 operator approval gate breaks that loop.

### Q. Why JWT and not session cookies?

Stateless — backends don't share session state, which would force
either a Redis sticky-session layer or central session storage.
JWT lets both the ML service and the proxy verify the same token
independently. Token state lives in browser localStorage; the
backends carry zero session state.

### Q. Token lifetime?

12 hours by default (`JWT_TTL_HOURS` env var). Long enough that an
operator doesn't get logged out mid-shift, short enough that a
leaked token expires within a working day. Shorter TTL + refresh
tokens would be the next iteration if multi-operator support
landed.

### Q. What about CSRF / XSS on the dashboard itself?

The dashboard is served from a different origin than the backends
(`:3000` vs `:8000`/`:8080`), so CORS gates every backend call —
preflight + token in `Authorization` header, never a cookie, so
CSRF isn't possible. XSS on the dashboard would require an
attacker-controlled HTML payload reaching the dashboard's
`innerHTML` — every dynamic string passes through `escapeHtml()`
in `dashboard/js/app.js`.

### Q. Threat intel — Spamhaus only, why not commercial feeds?

Spamhaus DROP/EDROP are free, no API key, no rate limit, well-known
and trusted. Commercial feeds (FireHOL, AbuseIPDB, etc.) would
extend coverage but require keys + budget. The feed list is a
single env var (`THREATINTEL_URL`) — adding a commercial source is
a one-line change for any deployment with the budget.
