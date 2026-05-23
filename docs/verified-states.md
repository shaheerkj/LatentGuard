# Verified states

Snapshots taken live, not aspirational. Each section is a checkpoint that
should reproduce if you follow the re-verify recipe. Listed newest first.

---

## Current head — fyp-II (2026-05-22, post review-removal + UI refresh)

Status of the dashboard + behaviour after this session's commits.

**Stack:** 5 containers (`latentguard-{mongo,juiceshop,ml,proxy,dashboard}`),
Coraza loads CRS v4.7.0 + baseline + 20-threat-intel.conf cleanly. ML model
loaded with Juice-Shop-augmented weights.

**Behaviour:**
- 6/6 attack classes still 403 through the proxy (SQLi, XSS, traversal,
  RCE, scanner UA, SQLi-in-JSON-login). Verified by `attacks/run_attacks.py`.
- 141-payload red-team battery: 106/127 expected-blocks caught → 83.5 % TPR.
- 12/12 benign Juice Shop flows pass (200/201) including login + register.
- Threat-intel: 1,630 CIDRs from Spamhaus DROP+EDROP loaded into rule
  `1500001`; `GET /__threatintel` returns live JSON status.
- Verdict is binary: no "review" emitted by the consensus engine on new
  requests. ~16 historical "review" rows still sit in Mongo from before the
  removal (rendered muted-grey on the dashboard).

**Dashboard:**
- KPI tiles: 4 (Total / Blocked / Block rate / P95 latency) with bigger
  fonts and per-tile accent icons, sized for projector readability.
- Two-card Threat Intel row (Blocklist status + Intel sources).
- Request Log view with filters (action, method, source IP, path-contains),
  pagination, click-row → full-detail drawer.
- Consensus tab is **real**, not placeholder — `PUT /api/consensus/config`
  persists to Mongo `ml_config` and is read per scoring decision.

**Re-verify:**
```bash
git checkout fyp-II
docker compose -f infra/docker-compose.yml up -d --build
sleep 15
python attacks/run_attacks.py --proxy http://127.0.0.1:8080 --sleep-ms 3
# expect summary line: ~83% detection rate, GRAND ~106/127
curl -s http://127.0.0.1:8080/__threatintel | python -m json.tool
# expect enabled=true, entry_count >= 1500, last_error empty
```

---

## fyp-II Juice Shop swap (2026-05-22, initial)

The DVWA upstream looked like a textbook lab on stage — purple PHP-era UI,
prominent "Damn Vulnerable Web App" branding — which undermined the
credibility of the FYP at the panel. `fyp-II` swaps the upstream to
**OWASP Juice Shop** (modern Angular SPA e-commerce, OWASP Flagship project)
so the supervisor sees a production-looking app being protected. The WAF
code is unchanged; only `infra/docker-compose.yml` and the training-data
pipeline differ from `main`.

**Stack diff vs `main`:**
- `infra/docker-compose.yml`: `dvwa` service → `juiceshop`
  (image `bkimminich/juice-shop:latest`, `expose: 3000`, `NODE_ENV=unsafe`);
  proxy `PROXY_UPSTREAM=http://juiceshop:3000`.
- New crawler `datasets/crawl_juiceshop_benign.py` — REST/JSON instead of
  HTML-form, JWT auth, ~3000 weighted requests, ~100 throwaway registrations
  (see gotcha #21).
- DVWA crawler scripts deleted on this branch (no upstream to crawl).

**Verified:**
- Coraza loads CRS v4.7.0 + baseline cleanly. 6/6 attack classes still
  403 through Juice Shop. 12/12 benign Juice Shop flows pass.
- CSIC 2010 replay (200 each): **FPR 0.00 %**, **TPR 27 %** — TPR is
  rule-only-equivalent because the ML model is now fit to Juice Shop,
  not CSIC; expected tradeoff for domain-tuned anomaly detection. Frame in
  report as *the system protects whatever it's deployed against, not
  whatever has the loudest published corpus*.
- P95 latency: benign 163 ms, attack 177 ms (~30 ms Keras overhead).

**Bootstrap order — critical sequence, getting it wrong wastes hours
(see gotcha #22):**

```bash
git checkout fyp-II
cd infra && docker compose up -d --build
# wait ~15s
docker stop latentguard-ml                  # force proxy into safe-mode
docker exec latentguard-mongo mongosh --quiet latentguard --eval 'db.requests.deleteMany({})'
python ../datasets/crawl_juiceshop_benign.py --proxy http://127.0.0.1:8080 --target 3000 --sleep-ms 2
docker start latentguard-ml && sleep 15
docker exec latentguard-ml python -m training.train_autoencoder --epochs 50 --augment-mongo --max 3000 --threshold-pct 99.5
docker exec latentguard-ml python -m training.train_hdbscan --augment-mongo --max 3000
docker restart latentguard-ml && sleep 18
# expect: attack curls return 403, benign POST login/register return 200/201
```

The `--max 3000` cap is essential (gotcha #20). Without it, CSIC's 36k
benign rows drown the 3.7k crawler rows and the AE collapses onto CSIC's
`/tienda1/...` distribution, blocking `/` on real browser hits.

---

## Threat-intel feeds shipped (2026-05-22, fyp-II)

Module 3 / FE-2 done. Boot pulled 1630 CIDRs from Spamhaus DROP + EDROP and
wrote `/etc/coraza/rules/threatintel.data` (25 735 bytes).
`coraza.Engine.Reload()` fired atomically right after — proxy didn't restart.
Rule 1500001 (`SecRule REMOTE_ADDR "@ipMatchFromFile threatintel.data" deny`)
loaded in phase:1.

Verified by injecting `172.18.0.1/32` (the docker bridge gateway IP, what
the proxy sees as a request from the host) into the data file and
restarting with `THREATINTEL_ENABLED=false` to preserve the edit:
- `curl http://127.0.0.1:8080/` → **HTTP 403**
- Audit row: `rule_hits: [1500001], final_action: "block", source_ip: "172.18.0.1"`

After restoring `THREATINTEL_ENABLED=true`, the 141-payload red-team
battery still scores 106/127 (83.5 %) — IP-based pre-filter is strictly
additive, not regressive.

**Live demo recipe:**
```bash
docker exec latentguard-proxy head -5 /etc/coraza/rules/threatintel.data
# Or force a known address by appending and restarting with TI fetch off:
docker exec latentguard-proxy sh -c 'echo "172.18.0.1/32" > /etc/coraza/rules/threatintel.data'
docker rm -f latentguard-proxy
MSYS_NO_PATHCONV=1 docker run -d --name latentguard-proxy --network infra_latentguard \
  -p 8080:8080 -p 8443:8443 \
  -e PROXY_UPSTREAM=http://juiceshop:3000 -e ML_URL=http://ml:8000 \
  -e MONGO_URI=mongodb://mongo:27017 -e MONGO_DB=latentguard \
  -e CORAZA_RULES_DIR=/etc/coraza/rules -e THREATINTEL_ENABLED=false \
  infra-proxy
sleep 12; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/  # expect 403
docker rm -f latentguard-proxy && docker compose up -d proxy             # restore
```

---

## Distribution-broadening pass (2026-04-27, main)

The Phase A model (CSIC-only training) gave 39.5 % CSIC TPR on paper but
mis-classified *every* real browser request to `/`, `/login.php`, etc. as
anomalous — CSIC paths all start with `/tienda1/...` (length 40+), so
anything shorter looked OOD and the AE saturated. Three fixes shipped
together:

1. **Generated DVWA benign traffic** via the (now-retired) DVWA crawler.
2. **`ml/training/mongo_loader.py`** pulls audit-log rows back as `Features`
   and the trainers gained `--augment-mongo` to mix them in.
3. **Fixed `rule_score` in `proxy/internal/coraza/coraza.go` + `pipeline.go`**
   (gotchas #12, #13).

**Verified state (2026-04-27, threshold 0.65):**
- Browser hits to `/`, `/login.php`, `/index.php`, `/favicon.ico`,
  `/robots.txt`, `/about.php`: all 200/302.
- 5/5 attack curls still 403.
- CSIC 2010 replay (200 each): **0.0 % FPR** (was 1.0 %),
  **25 % TPR** (was 39.5 %).

The TPR drop is honest, not regression. The previous 39.5 % was inflated by
the AE saturating on essentially all OOD traffic — including many CSIC
attacks, but also all real browsing. The current 25 % is what the model
genuinely contributes on top of Coraza's content-based detection. Frame
this in the report as *trading inflated TPR for usable FPR* rather than as
a TPR regression.

---

## FYP-II Phase A original (2026-04-26, branch `feature/fyp-ii-ml`)

After M4 autoencoder + M5 HDBSCAN + M6 consensus + dashboard rework went
live:

- 5 containers up, ML loads `autoencoder.keras` + `hdbscan.pkl` at boot,
  warmup predict runs in `@app.on_event("startup")` so the first real
  request doesn't pay the keras JIT cost.
- 6 / 6 attack classes blocked end-to-end.
- CSIC 2010 replay (200 each split): **Benign FPR: 1.0 %**, **Attack TPR:
  39.5 %** (vs 22 % rule-only in FYP-I — ML layer added +17.5 pts).
- **P95 latency 196 ms** end-to-end (over 150 ms NFR target — overshoot is
  keras predict per request; documented gap, acceptable for prototype).
- Consensus engine returned `block` only when weighted score ≥ 0.65;
  otherwise `review` (passthrough + log) or `allow`.
  **Note: `review` was removed in the 2026-05-22 binary-verdict change
  (gotcha #27). Today the engine emits allow or block only.**

---

## FYP-I 30 % submission snapshot (2026-04-30, branch `fyp-1`, commit `b219548`)

Branch built specifically for the 30 % submission demo. Same code as `main`
but with `ML_DISABLED=true` so the ML layer is bypassed and the supervisor
evaluates only M1+M2+M3+M7.

- 5 containers up; proxy logs `ML_DISABLED=true -- bypassing
  autoencoder/HDBSCAN/consensus; verdicts come from Coraza alone (FYP-I 30%
  scope)` at boot.
- Heartbeat goroutine **not** started.
- Benign smoke (4/4): GET `/`, `/login.php`, `/index.php`, `/favicon.ico`
  → 302/200/302/200.
- Attack smoke (5/5): SQLi, XSS, traversal, RCE, scanner UA → 403 from
  Coraza.
- Audit-log semantics: `ml_action=""`, `ml_score=0`, `fallback_used=false`,
  reason `"ML disabled (FYP-I scope: M1+M2+M3+M7)"`. `fallback_used` stays
  *false* — intentional scope gating, not a real ML outage (gotcha #18).

**Re-verify on `fyp-1`:**
```bash
git checkout fyp-1
docker compose -f infra/docker-compose.yml up -d --build
sleep 8
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/                       # expect 302
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/?q=%27%20OR%201=1--"  # expect 403
docker logs latentguard-proxy 2>&1 | grep ML_DISABLED                                 # expect kill-switch banner
```

---

## FYP-I original (commit `265294d`)

Captured live before Phase A ML went in.

- 5 containers up: `latentguard-{mongo,dvwa,ml,proxy,dashboard}`.
- Coraza loads CRS v4.7.0 + baseline rules cleanly.
- 6 / 6 attack classes blocked end-to-end.
- CSIC 2010 replay (200 each split): **0 % FPR**, **22 % rule-only TPR**
  (ML in safe-mode stub at this point).
- Latency: **server-side P95 30 ms**, **client-side P95 55 ms**. NFR target
  ≤ 150 ms — comfortably met.
- Audit log integrity verified — `fallback_used: true` only on real ML
  safe-mode failover.

### TLS termination (Module 1 / FE-2) added 2026-04-26

Proxy listens on **both** `:8080` (HTTP) and `:8443` (HTTPS) — same handler,
same Coraza+ML+audit pipeline. Cert loading lives in
`proxy/internal/tlsutil/selfsign.go`:
- If `PROXY_TLS_CERT` and `PROXY_TLS_KEY` env vars point at existing files,
  they're loaded as the operator-supplied cert.
- Otherwise an ephemeral self-signed cert is generated at boot (24h
  validity, CN=localhost, SANs for `localhost` + `127.0.0.1` + `::1`).

Verified: `curl -sk https://localhost:8443/__healthz` → 200; SQLi/XSS over
HTTPS → 403. TLS 1.2 minimum enforced.

For the panel demo: open `https://localhost:8443/`, accept the self-signed
cert warning, and you're going through Coraza + ML over TLS. Replay scripts
continue to use HTTP on 8080 (faster, no cert handling needed).
