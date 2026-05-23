# Questions — architecture and system design

### Q. Walk us through the architecture in 60 seconds.

Five containers on a single Docker network. Client traffic hits a
Go reverse proxy, which runs Coraza WAF (with OWASP CRS plus our
custom rules) on every request. If Coraza doesn't block, the proxy
calls the Python ML service over HTTP, which returns an
allow/block verdict from an autoencoder + HDBSCAN + consensus
engine. Allowed traffic forwards to the upstream app (OWASP Juice
Shop). Every decision is logged to MongoDB. An operator dashboard
reads from MongoDB and ML for live status, and from a candidate-rules
queue that's populated by an FP-Growth miner over the audit log.

### Q. Why two layers (rules + ML) instead of one?

Rules are accurate on known signatures but blind to novel payloads;
ML catches anomalies but can't explain itself and false-positives
heavily on natural traffic variance. Each layer compensates for the
other's weakness. The consensus engine combines their outputs so
neither is solely authoritative.

### Q. Why is the order rules → ML and not ML → rules?

Two reasons. **Latency**: if Coraza catches the attack, we save the
20+ ms ML round-trip; ML is the more expensive layer.
**Auditability**: a single primary cause per blocked request keeps
the audit log clean.

### Q. Why Coraza instead of real ModSecurity?

Coraza is a Go-native reimplementation of ModSecurity's rule grammar
with full CRS compatibility. We get identical detection without
needing C extensions, an OpenResty/Apache wrapper, or per-platform
build complexity. The proxy ships as a single static binary.

### Q. Why MongoDB and not Postgres / Elasticsearch?

Audit records are schemaless — different request shapes carry
different fields, and the feature dictionary grows over time without
migrations. Mongo's BSON handles this naturally; Postgres would
force a `jsonb` column that loses query ergonomics. Elasticsearch
would be ideal for log search but adds operational weight (cluster,
heap tuning) that's overkill for a single-node demo.

### Q. Why FastAPI?

Async-friendly so the `/score` endpoint can handle hundreds of
concurrent requests; automatic OpenAPI docs at `/docs`; native
Pydantic validation matches our type-checked schema layer; cold
start under 2 seconds (with lazy ML imports).

### Q. How does the proxy authenticate to the ML service?

For the `/score` hot path it doesn't — both run on a private docker
network with no exposed ports for ML other than `:8000` for the
dashboard. For service-to-service calls in the other direction (ML
calling proxy's `/__reload`), the ML service mints a JWT signed
with the shared `JWT_SECRET` and includes a `sub: "ml-service"`
claim that's grep-friendly in proxy logs.

### Q. What happens if the ML service goes down?

The proxy has a heartbeat goroutine that pings ML every 5 seconds.
On failure it flips a `safe_mode` flag; subsequent requests skip
the ML call and the consensus engine's rule_score alone decides.
This is documented in `docs/architecture.md` and visible on the
dashboard's topbar "ML" pill.

### Q. What about the dashboard going down?

Irrelevant — the dashboard is read-only nginx serving static HTML
that talks to the backends via JS. Killing the dashboard container
doesn't affect detection at all. Operators can still curl the
endpoints directly.

### Q. How is the system deployed in production?

Today it isn't — the deployment target is `docker-compose` on a
single host. A real production deployment would put proxy replicas
behind a Layer 4 load balancer, the ML service behind a Layer 7 LB,
and Mongo on a replica set. Helm charts are out of scope for the
FYP submission.

### Q. How do you handle TLS?

The proxy terminates TLS on `:8443` so it can inspect plaintext
before forwarding upstream. On boot it auto-generates a self-signed
cert (24 h validity, localhost SAN) if `PROXY_TLS_CERT` /
`PROXY_TLS_KEY` env vars aren't set, otherwise loads a real cert
from those paths.

### Q. What protocols do you support?

HTTP/1.1 and HTTP/2 over both cleartext and TLS, on `:8080` and
`:8443` respectively. WebSocket upgrade passes through unchanged
(Coraza inspects the upgrade handshake but not the post-upgrade
frames — that's a known limitation).

### Q. How does the threat-intel feed get refreshed without restart?

Background goroutine in the proxy fetches Spamhaus DROP+EDROP every
12 hours, writes a new `threatintel.data` file atomically (temp +
rename), then calls `Engine.Reload()` which rebuilds the Coraza WAF
instance behind an RWMutex. In-flight requests hold the read lock
and finish on the old WAF; new requests see the new one. Same
machinery is used for M10 mined-rule promotion.
