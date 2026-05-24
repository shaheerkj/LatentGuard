# Gotchas — already fixed, do not re-break

Each entry is a landmine someone (usually past-Claude) stepped on. Every
fix includes the *why* so you can judge edge cases instead of pattern-matching.

Tags: `[PROXY]` Go proxy / Coraza · `[ML]` Python ML service / training ·
`[INFRA]` docker / build / OS · `[UI]` dashboard · `[DATA]` datasets / corpus ·
`[DESIGN]` architectural decisions

Numbering is preserved from the historical CLAUDE.md so cross-references
(e.g. "see gotcha #18") still resolve. Add new gotchas at the end.

---

1. **`[PROXY]` Coraza `SecDefaultAction` can only be set once per phase.**
   OWASP CRS sets it in `REQUEST-901-INITIALIZATION.conf`. Our `00-setup.conf`
   deliberately omits it; baseline rules carry their own explicit
   `deny,status:403`. Re-adding `SecDefaultAction` to setup will break startup.

2. **`[PROXY]` CRS `.data` files use paths relative to the rule file.** Load
   rules with `cfg.WithDirectivesFromFile(f)` — **not** `WithDirectives(string(body))`,
   which loses the base directory and breaks `@pmFromFile` lookups.

3. **`[PROXY]` `decision.FromCorazaOnly` requires an explicit `fallback bool`
   parameter.** The earlier hardcoded `FallbackUsed: true` corrupted audit
   semantics — `fallback_used` must mean *real ML outage*, not *ML deliberately
   skipped because Coraza already blocked*. Don't regress this signature.

4. **`[DATA]` CSIC dataset URL.** archive.org wayback URLs 404. Use
   `https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010/`.

5. **`[INFRA]` Windows console encoding.** Default cp1252 — never print unicode
   like `≤`, `→`, em-dash in scripts that run via `python script.py` on
   Windows. Use ASCII (`<=`, `->`, `--`).

6. **`[INFRA]` PPTX images for the Read tool.** `unzip` extracts to `/tmp/...`
   (git-bash path) which the Read tool can't open on Windows. Copy to
   `.claude/pptx-extract/media/` (gitignored, Windows-accessible).

7. **`[DATA]` CSIC request-line stores ABSOLUTE URLs**, not origin-form. Lines
   look like `GET http://localhost:8080/tienda1/index.jsp?... HTTP/1.1`.
   Naive parsers will treat `http://localhost:8080/...` as the path and
   produce features ~20 chars longer than the proxy ever sees at runtime —
   silent train/serve skew that pushes FPR to >90 %. `ml/training/csic_loader.to_features`
   strips `scheme://host` before splitting target. Mirror this in any future loader.

8. **`[ML]` Don't clip standardized features at training/inference.** First
   Phase A pass used `StandardScaler` then `RobustScaler` with `np.clip(xs, -3, 3)`.
   CSIC's tiny IQR on `entropy` / `digit_ratio` (~0.01-0.08) inflated z-scores
   so any benign drift saturated multiple dims to ±3 — combinations the
   autoencoder never saw in training (training only saturates single dims at
   a time), so recon error blew up by 800x. **Use `MinMaxScaler` with no
   clipping** (`ml/training/train_autoencoder.py`, `ml/app/models.py`); it
   bounds the feature space gracefully and the model handles slight
   out-of-range values.

9. **`[INFRA]` ML container caches training code at build time.**
   `infra/docker-compose.yml` mounts only `models/` and `csic_raw/` as
   volumes — `app/` and `training/` are baked into the image via `COPY` in
   `ml/Dockerfile`. After editing trainer/model code, you **must**
   `docker compose build ml && docker compose up -d ml` before retraining or
   the container will run stale code. `docker compose restart` alone is not
   enough.

10. **`[PROXY]` Pipeline must not impose its own ML-call timeout.** `MLClient`
    already enforces `ML_TIMEOUT_MS` (1000 ms in compose). Earlier
    `pipeline.go` wrapped the call in a 300 ms `context.WithTimeout`, which
    double-budgeted: every keras-warm path tripped the 300 ms budget, flipped
    safe mode, and stayed in fallback for the rest of the run. Use
    `context.WithCancel` only — let the HTTP client own the timeout.

11. **`[ML]` CSIC alone is not enough training data — the AE saturates on
    anything shorter than `/tienda1/...`.** First time a real browser hits
    `/` (length 3) or `/favicon.ico`, AE recon error explodes (~4000×
    threshold) and consensus blocks. Fix: train with `--augment-mongo` after
    running a crawler (today `datasets/crawl_juiceshop_benign.py`) so the
    audit log has weighted real-app benign traffic. The crawler intentionally
    over-weights short paths because they're the long tail. Re-run the
    crawler and retrain whenever the upstream app changes (new routes = new
    path shapes the model must learn).

12. **`[PROXY]` `rule_score` must use `AttackMaxSeverity`, never
    `MaxSeverity`.** CRS' `MatchedRules()` includes init (900xxx-901xxx),
    per-category setup (9xxxxx where ID%1000 < 100), anomaly evaluation
    (949xxx), and correlation (980xxx) rules that fire on *every* request.
    Counting them inflates `rule_score` to ~0.8 on benign traffic and the
    consensus engine blocks accordingly. `coraza.go` builds an
    `AttackMatchedRuleIDs` slice with these scaffold IDs filtered out via
    `isCRSScaffoldRuleID`, and `pipeline.go` uses `AttackMaxSeverity` for the
    score. Pipeline also forces `ruleScore = 0` when
    `len(AttackMatchedRuleIDs) == 0` (belt-and-suspenders against any
    unset-severity rule that slips the filter).

13. **`[PROXY]` Syslog severity is inverted in scoring.** `rule.Severity()`
    returns syslog levels: 0=Emergency (most severe), 7=Debug (least severe).
    The original `severityToFloat(sev) = sev/5.0` treated NOTICE (5) as 1.0
    (most severe!) and CRITICAL (2) as 0.4. Now: `1.0 - sev/7.0`, with
    `sev <= 0 → 1.0` and `sev >= 7 → 0.0`. Same fix in
    `decision.go::severityToScore` for the safe-mode fallback path.

14. **`[DATA]` Crawlers must do *real* login POSTs, not templated ones.**
    First DVWA crawler version had `("/login.php", "...&user_token={}",
    [["{token}"]])` — the literal string `{token}` got substituted, so
    training data carried `user_token={token}` (length 75, digit_ratio 0).
    Real browser logins post `user_token=<32-char hex>` (length 95+,
    digit_ratio 0.25), which the AE then treats as OOD and the consensus
    engine blocks. Both the (now-retired) DVWA crawler and the current
    `crawl_juiceshop_benign.py` do a real GET-then-POST flow with harvested
    tokens / JWT. After upstream-app changes that introduce new POST shapes
    (CSRF tokens, file uploads, etc.), re-crawl and retrain.

15. **`[DATA]` Every form is its own OOD shape.** Each form on the upstream
    (login, register, search, basket, feedback, ...) submits a unique field
    set. The crawler must hit every form-POST endpoint with realistic safe
    values to seed the AE — otherwise users clicking through the app trip
    OOD blocks one by one. For DVWA this lived in `datasets/prime_dvwa_full.py`
    (retired on fyp-II); for Juice Shop the same coverage lives directly
    inside `crawl_juiceshop_benign.py`'s phase 4 loop.

16. **`[DATA]` DVWA sets multiple `Set-Cookie` headers per response
    (`security=`, `PHPSESSID=`).** A `dict((k.lower(), v) for k, v in
    r.getheaders())` collapses them and only the last wins, which silently
    breaks session continuity in any crawler that uses that pattern. Use
    `[v for k, v in r.getheaders() if k.lower() == "set-cookie"]` to keep
    the list, then merge into a Cookie jar.

17. **`[ML]` Consensus threshold = 0.75 (was 0.65).** The original 0.65
    default tipped on benign POSTs once `rule_score=0.43` (CRS Host-header
    check leak) plus moderate AE/HDB scores summed to ~0.7. The fix is
    twofold: (a) widen training distribution as documented in #14/#15,
    (b) raise the threshold so genuine benign requests have margin. Real
    attacks score 0.94+, so 0.75 doesn't weaken detection. Update via
    `PUT /api/consensus/config`; persisted in Mongo `ml_config`.

18. **`[DESIGN]` `ML_DISABLED` is *not* the same as safe-mode — keep the
    audit semantics distinct.** Both routes the request through
    `decision.FromCorazaOnly`, but they answer different questions in the
    audit log:
    - **Safe mode** (`safe.Get() == true`): real ML outage, heartbeat
      tripped → `fallback_used=true`, reason `"ML in safe mode"`. This is a
      degraded-service signal the operator should investigate.
    - **`ML_DISABLED=true`** (env var, set on `fyp-1` branch): intentional
      scope gating for the 30 % submission → `fallback_used=false`, reason
      `"ML disabled (FYP-I scope: M1+M2+M3+M7)"`. The system is operating
      *exactly as configured*; nothing to investigate.

    The kill-switch is wired in `proxy/cmd/proxy/main.go` (reads env, also
    skips heartbeat goroutine) and `proxy/internal/pipeline/pipeline.go`
    (extra `case mlDisabled:` arm in the verdict switch, *before* the
    safe-mode case so the more specific signal wins). Don't collapse these
    into one path — `fallback_used` is what the dashboard's "ML reliability"
    panel keys off, and conflating intentional gating with outages would
    corrupt that metric.

19. **`[DATA]` Windows Python `http.client` to `localhost` is ~10 s/req
    slower than to `127.0.0.1`.** Windows resolves `localhost` to `::1`
    first, the proxy isn't bound to IPv6, the connect attempt waits the full
    timeout, then falls back to IPv4. 10 000 ms vs 17 ms per request,
    measured. All loopback crawlers and the CSIC replay must use `127.0.0.1`
    explicitly (`crawl_juiceshop_benign.py::_conn` rewrites
    `localhost` → `127.0.0.1` and keeps the original in the Host header;
    pass `--proxy http://127.0.0.1:8080` to `replay_csic.py`). Only matters
    on Windows hosts; Linux glibc is fine because of `nss-files`/`/etc/hosts`
    direct lookup.

20. **`[ML]` CSIC drowns the crawler in mixed-corpus training — cap with
    `--max`.** With CSIC at 36k rows and the Juice Shop crawler at ~3.7k,
    the AE minimises loss against CSIC's `/tienda1/...` distribution and
    ignores Juice Shop's `/`, `/api/Products`, etc. The model then blocks
    benign `/` on a real browser hit (recon error 0.11 vs threshold 0.04,
    AE saturates at 1.0). Fix: `--max 3000` on both `train_autoencoder` and
    `train_hdbscan` so CSIC ≈ crawler size, then bump `--threshold-pct 99.5`
    for a little extra margin. This generalises to any future upstream
    swap: always cap CSIC to the size of the freshest in-distribution
    corpus.

21. **`[DATA]` Crawler must seed many register-POST samples, not just N-pool
    registrations.** The first Juice Shop crawler did 8 `/api/Users/` POSTs
    (one per pool user) and the AE never fit the JSON register-body shape —
    a fresh signup post-train returned 403. Fix:
    `crawl_juiceshop_benign.py` schedules `THROWAWAY_REGISTER_COUNT=100`
    extra registrations spaced through phase 4 with unique emails
    (`lgone000_<millis>@lg-bench.test`, …). Same principle applies to any
    low-frequency POST shape: if a real user might do it occasionally, the
    crawler must do it ≥50 times.

22. **`[DATA]` `fyp-II` bootstrap requires ML to be DOWN during the seed
    crawl.** Cold-start chicken-and-egg: the un-juice-shop-trained ML
    blocks the very POSTs we need to capture as benign. Stop
    `latentguard-ml` before crawling so the proxy heartbeat trips safe-mode,
    requests fall through to Coraza-only, the audit log captures features
    for *every* request (block decision is irrelevant — features are written
    pre-decision), then start ML and retrain on the captured rows. Don't
    try to crawl with ML up "to save time" — you'll get a corrupt training
    set full of mid-train scores. See the bootstrap sequence in
    `docs/verified-states.md` (Juice Shop section).

23. **`[PROXY]` `@ipMatchFromFile` caches the data file on first load — you
    MUST `engine.Reload()` after rewriting it.** Coraza parses the file
    once when the rule loads; later edits on disk are ignored until the
    WAF is rebuilt. `proxy/internal/coraza/coraza.go` exposes
    `Engine.Reload()` (rebuilds WAF from the original `rulesDir`, swaps
    under an RWMutex) and `internal/threatintel.Manager.runOnce` calls it
    after every atomic file write. Without this, the boot fetch would
    populate the file but the running rule would still see the empty
    placeholder.

24. **`[PROXY]` The `threatintel.data` file MUST exist before
    `coraza.New()` runs.** `@ipMatchFromFile` errors out if the referenced
    file is missing, which would crash boot on a fresh clone where the
    fetcher has never run. `main.go` calls
    `threatintel.EnsurePlaceholder(cfg.tiDataPath)` *before*
    `coraza.New(cfg.rulesDir)` so the file always exists (comment-only
    placeholder if nothing else). Don't reorder these.

25. **`[INFRA]` Coraza paths-via-env on Windows: always set
    `MSYS_NO_PATHCONV=1` for `docker run -e CORAZA_RULES_DIR=...`.**
    Git-Bash rewrites the literal `/etc/coraza/rules` to
    `C:/Program Files/Git/etc/coraza/rules` when passing it through
    `docker run -e`, then the proxy tries to `mkdir C:/...` inside an
    Alpine container and panics. `docker compose up` doesn't trigger this
    because compose reads env values from YAML, not from the shell. Bites
    only one-off `docker run` overrides — the threat-intel live test
    recipe in `docs/verified-states.md` is the canonical use case.

26. **`[INFRA]` Dockerfile must `COPY --chown=latentguard:latentguard
    rules /etc/coraza/rules`.** The proxy runs as uid 1000, the threat-intel
    fetcher writes `threatintel.data` at runtime. Without the `--chown`,
    the rules dir is root-owned and the rename-into-place fails with EACCES
    on every refresh. Same applies to any future runtime-writable file
    under the rules tree.

27. **`[DESIGN]` Verdict is BINARY — allow or block. There is no
    per-request "review" band.** The SRS mockup originally described a
    three-arm decision (allow / review / block) where borderline-scored
    requests would be flagged for a human to approve or reject one by one.
    The user correctly rejected this on 2026-05-22: no real WAF works that
    way — they run at line speed and cannot wait for an operator to click
    through individual requests; that workflow is Burp Suite Repeater
    territory, not WAF territory. HITL belongs at the **rule** layer (M10):
    when M9 drafts a SecRule from mined patterns, a human approves the
    *rule* before it's merged into Coraza. Per-request approval was removed
    from `ml/app/consensus/engine.py` (all three modes — weighted now just
    `score >= threshold ? block : allow`, majority `votes >= 2`, strict
    unchanged), `ml/app/schemas.py` ScoreResponse Literal
    (`["allow","block"]`), `ml/app/api.py` metrics + log filter regex +
    timeseries series, `proxy/internal/decision/decision.go` (`ActionReview`
    constant deleted), and the dashboard (KPI tile, filter option, chart
    series). Historical rows in Mongo with `final_action: "review"` are
    preserved as data but render as a muted neutral pill (`.action-review`
    is now styled grey, no longer warning-amber) so they don't pretend to
    be a live verdict category.

28. **`[UI]` Don't override the HTML `hidden` attribute with class-level
    `display:`.** The drawer-backdrop had `.drawer-backdrop { display:
    flex; }` which beat the UA stylesheet's `[hidden] { display: none; }`
    at equal specificity (author beats UA), so the backdrop rendered on
    page load and covered every click. Fix: add an explicit
    `.drawer-backdrop[hidden] { display: none; }` rule — attribute+class
    selector has higher specificity than the bare class, hidden state wins
    again. Lesson generalises: if you have `display:` on a class that's
    also toggled via `[hidden]`, write the explicit
    `.foo[hidden] { display: none; }` companion rule.

29. **`[DESIGN]` JWT secret is SHARED between the ML service and the Go
    proxy via the same `JWT_SECRET` env var.** The dashboard authenticates
    once against the ML side (`POST /api/auth/login`) and gets a single
    JWT it then attaches to BOTH ML calls (`/api/*`) and proxy operator
    calls (`/__threatintel`, `/__safe-mode`). Both verifiers (FastAPI's
    `require_auth` and `proxy/internal/auth.Verifier`) read the same
    `JWT_SECRET`, validate the same `iss: "latentguard"` claim, and
    accept the same HS256 algorithm. **Keep the two env values
    bit-identical in `infra/docker-compose.yml`** — if they drift, the
    token the dashboard holds works on one side but not the other and
    the user sees half-broken pages with no obvious diagnostic.
    `/healthz` and `/__healthz` are deliberately UN-gated on both sides
    so docker healthchecks (and any external probes) keep working without
    needing a token. RBAC + per-role gating (mockup M1 + SDS §4.3) is
    deferred — today's model is single-admin.

30. **`[INFRA]` In docker-compose.yml env values, every literal `$` must
    be doubled to `$$`.** Compose interpolates `${VAR}` syntax through
    the env block; bcrypt password hashes contain three `$` characters
    (`$2b$12$...`) and would be silently mangled into empty strings
    otherwise. The `ADMIN_PASSWORD_HASH` line in our compose escapes
    every `$` -> `$$` for this reason. Same applies to any other secret
    that happens to contain dollar signs.

31. **`[ML]` Don't import `mlxtend` / `pandas` at module top-level.**
    They pull in ~50MB of state and a slow numpy fork; cold-starting the
    FastAPI process for an unrelated /api call would block on the import
    chain. `app/mining/miner.py` does both imports inside `mine_patterns()`
    so the cost is only paid when the operator triggers /api/mining/run.
    Same pattern as `models.py` deferring `tensorflow` / `hdbscan`.

32. **`[INFRA]` Generated rules live on the `lg-generated-rules` named
    volume mounted on BOTH `ml` and `proxy` at
    `/etc/coraza/rules/lg-generated/`.** The promoter writes
    `lg-<rule_id>.conf` files (one per live rule); Coraza's
    `loadRuleFiles` walks the rules dir recursively for `*.conf` so the
    sub-directory is picked up automatically on the next `Engine.Reload()`.
    Mongo (`rules_queue` collection) is the source of truth; the disk
    files are a projection rewritten end-to-end on every promote/expire.
    If you ever see a stale `lg-*.conf` after expiring a rule, the
    promoter's `_write_live_rules()` failed to remove it -- check the
    container's filesystem perms on the volume mount.

33. **`[DESIGN]` Rule-ID bands are reserved per source.** Baseline rules
    use 1000000-1099999, OWASP CRS uses ~900000-999999, and
    M9 mined/synthesized rules use 2000000-2999999. The allocator in
    `rulegen/store.py:_next_rule_id` enforces the LG band; if you ever
    hand-write a rule outside its band you risk a Coraza "duplicate id"
    error on reload that's hell to debug. When the 2M band fills up,
    expire old rules rather than widening the band -- a 1M-rule
    Coraza ruleset would be unusable anyway.

34. **`[ML]` The ML service signs its own JWT to call the proxy's
    `/__reload` endpoint.** `rulegen/promoter._trigger_proxy_reload`
    calls `auth.issue_token("ml-service")` and sends the token as a
    bearer header. The proxy's verifier accepts it because they share
    `JWT_SECRET` and the `iss: latentguard` claim matches (same
    issuer for service-to-service as user-to-service). The `sub` is
    `"ml-service"` to make it greppable in proxy logs vs human logins.
    If reload starts failing with 401 in prod, check that the proxy
    is on the same JWT_SECRET (see gotcha #29).

35. **`[ML]` Feature vector changed from 7 -> 11 (n-gram patch).**
    `features.py` and `proxy/internal/normalizer/normalizer.go` MUST
    stay in lock-step on field count and order. The parity test in
    `proxy/internal/normalizer/normalizer_test.go::TestNgramStatsParity`
    asserts the Go ngramStats output matches the Python
    `_ngram_stats` for a fixed set of inputs -- if either drifts,
    the test fails. After bumping the feature set, retrain both AE
    and HDBSCAN (dashboard's Anomaly Models tab -> Retrain) so the
    scaler sees the new dimension. `models.py` has a defensive shim
    that truncates/pads the vector to the scaler's expected dim and
    surfaces a one-time warning so the proxy does not crash while a
    stale model is still loaded -- but detection quality degrades
    until retrain completes.

36. **`[ML]` n-gram stats use BYTE indexing, not rune.** Both
    implementations use byte slicing (`text[i:i+n]` in Python,
    `text[i:i+n]` in Go) so they line up on ASCII canonicalised
    payloads. Multi-byte UTF-8 in the canonical text would produce
    different gram boundaries between the two -- but the canonical
    body is lowercased+stripped from a request body that has
    already been url-decoded, so non-ASCII in practice arrives
    only when an attacker is deliberately probing UTF-8 evasion,
    which is itself a useful signal.

37. **`[INFRA]` Container ages lie about "this is the current build".**
    `docker ps` shows `Up 16 hours` for `latentguard-ml` and
    `latentguard-proxy` is the FIRST thing future Claude will see, and
    will assume they have the latest code. They don't unless you've
    run `docker compose ... up -d --build ml proxy` since the last
    code change. Before reasoning about behaviour, ALWAYS rebuild and
    confirm the container age dropped to seconds. Surfaced when the
    operator hit "Run miner" and got a 404 from a 16-hour-old image
    that didn't have the M8 endpoints yet.

38. **`[ML]` Lazy import discipline matters in `model_promotion.py`.**
    The drift watcher background task in `ml/app/model_promotion.py`
    imports `models_drift` from `ml/app/api.py` -- but only INSIDE the
    coroutine, not at module top. If you hoist it to a top-level
    import you create a circular import (api -> model_promotion ->
    api). Same pattern is used by `siem.py::start_in_background`
    importing `app.version` only inside the worker.

39. **`[ML]` The `users` collection has only-active-admin guards on
    update + delete.** `auth_router.users_update` and `users_delete`
    refuse to demote / deactivate / delete the last active admin
    (returns 409). This is to prevent a deployment from locking itself
    out by mass-disabling. If you need to *intentionally* lock out the
    last admin (e.g. for a tenant-handover scenario), you'd have to
    create another admin first, then disable the old one. Documented
    behaviour; do not "fix" by removing the guard.

40. **`[INFRA]` The dashboard is an nginx volume mount of `dashboard/`.**
    Edits to `dashboard/index.html`, `dashboard/js/*.js`, or
    `dashboard/assets/style.css` go live on the next hard-refresh --
    no rebuild needed. But ensure the browser DOES hard-refresh
    (Ctrl+Shift+R / Cmd+Shift+R) because the JS is aggressively
    cached. Several "I made the change but the dashboard didn't
    update" moments came from this.

41. **`[DESIGN]` SafeMode now has THREE states, not two.**
    `proxy/internal/pipeline/pipeline.go::SafeMode` carries
    `(active, forced, reason, since)`. Heartbeat-driven transitions
    go through `SetAuto`, which is a NO-OP when `forced=true`. The
    operator endpoint POST /__safe-mode uses `SetForced`. Don't
    grep for `safe.Set(true)` and assume it's the whole story --
    the legacy `Set(b)` shortcut routes to SetAuto for back-compat
    with the original tests.

42. **`[ML]` The audit log's `overrides[]` array is the ground truth
    for `/api/models/accuracy`.** Operator-supplied decision overrides
    (FR4.5) are stored as `{verdict, reason, actor, at}` objects
    pushed onto each request's `overrides` array. The accuracy
    computation in `api.py::models_accuracy` treats the latest
    override as the true label, defaults to `final_action` when
    no override exists. This is weak supervision -- a future
    auto-FP-correction module (todo.md) should feed these into
    the next benign training cycle.
