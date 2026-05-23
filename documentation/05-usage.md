# Usage — dashboard tour and end-to-end demo

## Dashboard layout

The dashboard at `http://localhost:3000` is a single-page app with
five usable tabs. (Two further tabs — Alerts and Settings — are
deferred placeholders.)

### Dashboard tab

The default landing view. Four KPI tiles (Total / Blocked / Block
rate / P95 latency), the traffic chart (allow vs block per minute
over the last hour), and the threat-intel status cards.

The topbar carries live status pills:
- **ML** — green when `/healthz` returns OK
- **Threat intel** — count of loaded CIDRs, red if the feed last
  refresh failed
- **Drift** — z-score of the autoencoder anomaly score; red when
  drift detected, neutral during warm-up (<30 samples)

### Anomaly Models tab

Two cards (M4 autoencoder, M5 HDBSCAN). Each shows version, training
date, sample count, and per-model statistics (thresholds, cluster
counts). Each has a Retrain button — clicking it kicks off a
background subprocess inside the ML container and reloads the
artifacts on completion. Logs land in `ml/models/*.log`.

### Consensus tab

Three radio buttons for mode (weighted / majority / strict), four
sliders (AE weight / HDBSCAN weight / rule weight / overall
threshold), and a per-model-threshold slider. Configuration persists
to Mongo (`ml_config` collection) and is re-read on every scoring
call. The Recent Decisions table below shows the latest 20 scoring
verdicts with each component score.

### Request Log tab

Browsable audit log. Filters: action (allow/block), method, source
IP (exact match), path (substring), page size. Pagination. Click any
row → drawer with the full request canonicals, headers, features
dictionary, every Coraza rule that fired, ML score components, and
reasons.

### Rules tab *(new — M8/M9/M10 surface)*

Two cards:

**Mine new patterns.** Controls for min_support, lookback hours,
itemset size range, only-blocked toggle, emit-candidates toggle.
"Run miner" triggers M8 against the audit log, then M9 renders any
itemsets into draft rules. Status line shows transactions / patterns
/ inserts / refreshes / elapsed.

**Candidate rules table.** Chip filter by status (Pending /
Approved / Live / Rejected / Expired / All). Per-row actions:

| Status | Available actions |
|---|---|
| pending | View, Approve, Reject |
| approved | View, Expire (live promotion is automatic) |
| live | View, Expire |
| rejected | View, Delete |
| expired | View, Delete |

Click **View** to open the rule editor modal — full ModSecurity rule
text, message, operator notes, the pattern itemset that drove it,
state history. Edits demote the rule back to `pending`.

## End-to-end demo (the 5-minute viva script)

1. `docker compose ... up -d --build`. Wait for ML to log
   "Application startup complete".
2. Browser → `http://localhost:3000` → sign in.
3. Open a second terminal. Run a focused attack series, not the full
   battery:
   ```bash
   for i in $(seq 1 20); do
     curl -s -o /dev/null \
       "http://localhost:8080/rest/products/search?q=apple%27%20OR%201=1--"
   done
   ```
   You've just fired 20 identical-shape SQLi probes.
4. Dashboard → Request Log → filter `action=block` → confirm all 20
   blocked.
5. Dashboard → Rules tab → Run miner with `min_support=0.05`.
   The miner finds the pattern
   `path:/rest, method:GET, rule:942100, body:present` (or similar)
   and emits one candidate rule, status=pending.
6. Click View → see the generated `SecRule ... chain` block →
   Approve. Status flips to `live`; the file
   `/etc/coraza/rules/lg-generated/lg-2000000.conf` appears in the
   proxy container; Coraza reloads.
7. Re-run the curl loop. Requests now block at the M3 layer (the
   mined rule) instead of M6 consensus — observable in the audit
   log by which rules show up in `rule_hits`.

That demonstrates the full **detect → mine → approve → harden** loop
in one minute live.

## Common operator workflows

### "Block this IP range right now."

Dashboard → Rules tab. Skip the miner; click on any blocked request
from the offending IP → drawer shows the `/24`. Manually craft a
candidate? Not supported in the UI today — easier path is to add the
CIDR to a custom threat-intel feed and let M3 hot-reload pick it up.
(See `proxy/rules/20-threat-intel.conf`.)

### "The block rate looks wrong."

Dashboard → Consensus tab. Likely the threshold is set wrong for the
current traffic distribution. Lower the threshold to block more,
raise to block less. Sliders are live — no restart needed.

### "We just retrained the autoencoder."

The Retrain button calls back to the loader on success, so the new
artifacts are picked up automatically. Check Anomaly Models tab —
version string should update with a new timestamp. Watch the Drift
pill on the topbar — it should go back to green within a few minutes
once the new baseline reflects current traffic.
