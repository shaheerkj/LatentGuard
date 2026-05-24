// LatentGuard operator console - Phase A wiring (M3 anomaly cards + M6 consensus).
// All data flows through the FastAPI ML service (CORS-enabled).

const API_BASE = window.LATENTGUARD_API || "http://localhost:8000";
// Proxy exposes its own operator endpoints (/__healthz, /__safe-mode,
// /__threatintel) on a different port than the ML service. Override via
// window.LATENTGUARD_PROXY if the dashboard is served from elsewhere.
const PROXY_BASE = window.LATENTGUARD_PROXY || "http://localhost:8080";
const REFRESH_MS = 5000;

const els = {
    routes: document.querySelectorAll(".nav-link"),
    views: document.querySelectorAll(".view"),
    safePill: document.getElementById("safe-mode-pill"),
    kpi: {
        total:   document.getElementById("kpi-total"),
        blocked: document.getElementById("kpi-blocked"),
        rate:    document.getElementById("kpi-rate"),
        p95:     document.getElementById("kpi-p95"),
    },
    logBody:    document.getElementById("log-tbody"),
    log: {
        action:  document.getElementById("lf-action"),
        method:  document.getElementById("lf-method"),
        ip:      document.getElementById("lf-ip"),
        path:    document.getElementById("lf-path"),
        limit:   document.getElementById("lf-limit"),
        reset:   document.getElementById("lf-reset"),
        prev:    document.getElementById("lf-prev"),
        next:    document.getElementById("lf-next"),
        counter: document.getElementById("lf-counter"),
    },
    drawer: {
        root:     document.getElementById("drawer"),
        backdrop: document.getElementById("drawer-backdrop"),
        title:    document.getElementById("drawer-title"),
        subtitle: document.getElementById("drawer-subtitle"),
        body:     document.getElementById("drawer-body"),
        close:    document.getElementById("drawer-close"),
    },
    rulesBody:  document.getElementById("rules-tbody"),

    ae: {
        pill:       document.getElementById("ae-loaded-pill"),
        version:    document.getElementById("ae-version"),
        trained:    document.getElementById("ae-trained"),
        samples:    document.getElementById("ae-samples"),
        bottleneck: document.getElementById("ae-bottleneck"),
        p95:        document.getElementById("ae-p95"),
        threshold:  document.getElementById("ae-threshold"),
        status:     document.getElementById("ae-status"),
    },
    hdb: {
        pill:     document.getElementById("hdb-loaded-pill"),
        version:  document.getElementById("hdb-version"),
        trained:  document.getElementById("hdb-trained"),
        samples:  document.getElementById("hdb-samples"),
        clusters: document.getElementById("hdb-clusters"),
        noise:    document.getElementById("hdb-noise"),
        mcs:      document.getElementById("hdb-mcs"),
        status:   document.getElementById("hdb-status"),
    },
    ti: {
        pill:        document.getElementById("ti-pill"),
        topbarPill:  document.getElementById("ti-status-pill"),
        enabled:     document.getElementById("ti-enabled"),
        entries:     document.getElementById("ti-entries"),
        lastSync:    document.getElementById("ti-last-sync"),
        bytes:       document.getElementById("ti-bytes"),
        sourcesChips: document.getElementById("ti-sources-chips"),
        error:       document.getElementById("ti-error"),
    },
    consensus: {
        modes:    document.querySelectorAll('input[name="mode"]'),
        wAe:      document.getElementById("w-ae"),
        wHdb:     document.getElementById("w-hdb"),
        wRule:    document.getElementById("w-rule"),
        wAeV:     document.getElementById("w-ae-v"),
        wHdbV:    document.getElementById("w-hdb-v"),
        wRuleV:   document.getElementById("w-rule-v"),
        sum:      document.getElementById("w-sum"),
        threshold:    document.getElementById("threshold"),
        thresholdV:   document.getElementById("threshold-v"),
        pmt:      document.getElementById("per-model-threshold"),
        pmtV:     document.getElementById("pmt-v"),
        save:     document.getElementById("save-consensus"),
        status:   document.getElementById("consensus-status"),
        decisionsBody: document.getElementById("decisions-tbody"),
    },
};

let trafficChart = null;

function fmt(n) { return n == null ? "-" : new Intl.NumberFormat().format(n); }
function pct(x) { return x == null ? "-" : (x * 100).toFixed(2) + "%"; }
function fmt3(x) { return x == null ? "-" : Number(x).toFixed(3); }

function setActiveRoute(route) {
    els.routes.forEach(a => a.classList.toggle("active", a.dataset.route === route));
    els.views.forEach(v => v.classList.toggle("view--active", v.id === `view-${route}`));
}

els.routes.forEach(a => a.addEventListener("click", () => setActiveRoute(a.dataset.route)));

// Log view state — the page index is kept here so it survives auto-refresh
// ticks; filter changes reset it to 0.
const logState = { offset: 0, limit: 50, total: 0 };
function bindLogFilter(el, debounceMs = 0) {
    let timer = null;
    const handler = () => {
        clearTimeout(timer);
        timer = setTimeout(() => { logState.offset = 0; refreshLogs(); }, debounceMs);
    };
    el.addEventListener(debounceMs ? "input" : "change", handler);
}
bindLogFilter(els.log.action);
bindLogFilter(els.log.method);
bindLogFilter(els.log.ip, 250);
bindLogFilter(els.log.path, 250);
els.log.limit.addEventListener("change", () => {
    logState.limit = Number(els.log.limit.value) || 50;
    logState.offset = 0;
    refreshLogs();
});
els.log.prev.addEventListener("click", () => {
    logState.offset = Math.max(0, logState.offset - logState.limit);
    refreshLogs();
});
els.log.next.addEventListener("click", () => {
    if (logState.offset + logState.limit < logState.total) {
        logState.offset += logState.limit;
        refreshLogs();
    }
});
els.log.reset.addEventListener("click", () => {
    els.log.action.value = "";
    els.log.method.value = "";
    els.log.ip.value = "";
    els.log.path.value = "";
    els.log.limit.value = "50";
    logState.limit = 50;
    logState.offset = 0;
    refreshLogs();
});

// Drawer wiring -- ESC + backdrop click + X button all close.
function closeDrawer() {
    els.drawer.backdrop.hidden = true;
    els.drawer.root.classList.remove("drawer--open");
}
els.drawer.close.addEventListener("click", closeDrawer);
els.drawer.backdrop.addEventListener("click", (e) => {
    if (e.target === els.drawer.backdrop) closeDrawer();
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !els.drawer.backdrop.hidden) closeDrawer();
});

async function fetchJSON(path, init) {
    return fetchJSONFrom(API_BASE, path, init);
}

// Routed through LG_AUTH.authFetch so the bearer token is attached on every
// API call. 401 responses kick the user back to the login page (the wrapper
// throws; our catch swallows so dashboard ticks keep running until the
// redirect actually navigates away).
async function fetchJSONFrom(base, path, init) {
    try {
        const res = await LG_AUTH.authFetch(`${base}${path}`, init);
        if (!res.ok) {
            const detail = await res.text();
            throw new Error(`HTTP ${res.status}: ${detail.slice(0, 120)}`);
        }
        return await res.json();
    } catch (err) {
        // 'unauthenticated' is the marker authFetch throws after starting
        // a redirect; don't log it as noise.
        if (err && err.message !== "unauthenticated") {
            console.warn("fetch failed", `${base}${path}`, err);
        }
        return null;
    }
}

async function refreshHealth() {
    const h = await fetchJSON("/healthz");
    if (h && h.status === "ok") {
        els.safePill.textContent = "ML: healthy";
        els.safePill.className = "pill pill--ok";
    } else if (h && h.status === "degraded") {
        els.safePill.textContent = "ML: degraded";
        els.safePill.className = "pill pill--warn";
    } else {
        els.safePill.textContent = "ML: down";
        els.safePill.className = "pill pill--danger";
    }
}

// REL-2: safe-mode banner + force-toggle. Polled on the same tick as
// everything else. When safe-mode is on, a red banner sits above the
// main view across every tab so the operator can never miss it.
async function refreshSafeMode() {
    const banner = document.getElementById("safe-mode-banner");
    if (!banner) return;
    const s = await fetchJSONFrom(PROXY_BASE, "/__safe-mode");
    if (!s) return;
    const isActive = !!s.safe_mode;
    banner.hidden = !isActive;
    if (!isActive) return;
    const reasonEl = document.getElementById("safe-mode-reason");
    const sinceEl  = document.getElementById("safe-mode-since");
    if (reasonEl) reasonEl.textContent = s.reason || "ML scoring is bypassed.";
    if (sinceEl) {
        const since = s.since && s.since !== "0001-01-01T00:00:00Z" ? s.since : null;
        sinceEl.textContent = since ? `(since ${relativeTime(since)})` : "";
    }
    // Force buttons: visible only to rule-operators; the right button to
    // show depends on whether we're currently forced or in auto state.
    const onBtn = document.getElementById("safe-mode-force-on-btn");
    const offBtn = document.getElementById("safe-mode-force-off-btn");
    const canForce = LG_AUTH.canManageRules();
    if (onBtn) onBtn.hidden = !canForce || s.forced;
    if (offBtn) offBtn.hidden = !canForce || !s.forced;
}

// Idempotent button wiring; runs once on script load.
const _smForceOn = document.getElementById("safe-mode-force-on-btn");
if (_smForceOn) {
    _smForceOn.addEventListener("click", async () => {
        const reason = prompt("Force safe mode on -- reason for the audit log (e.g. \"ML acting weird, isolating\"):", "");
        if (reason === null) return;
        await fetchJSONFrom(PROXY_BASE, "/__safe-mode", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ force: true, reason: reason || "no reason" }),
        });
        refreshSafeMode();
    });
}
const _smForceOff = document.getElementById("safe-mode-force-off-btn");
if (_smForceOff) {
    _smForceOff.addEventListener("click", async () => {
        if (!confirm("Clear forced safe-mode? The heartbeat will resume control -- if ML is still down, safe-mode stays on; if it's healthy, it'll lift on the next probe.")) return;
        await fetchJSONFrom(PROXY_BASE, "/__safe-mode", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ force: false, reason: "operator cleared force" }),
        });
        refreshSafeMode();
    });
}

async function refreshMetrics() {
    const m = await fetchJSON("/api/metrics");
    if (!m) return;
    els.kpi.total.textContent   = fmt(m.total_requests);
    els.kpi.blocked.textContent = fmt(m.blocked);
    els.kpi.rate.textContent    = pct(m.block_rate);
    els.kpi.p95.textContent     = `${fmt(m.p95_latency_ms)} ms`;
}

async function refreshTraffic() {
    const series = await fetchJSON("/api/timeseries?minutes=60");
    if (!series) return;
    const labels = uniqueTimestamps(series);
    const data = (key, color) => ({
        label: key,
        data: labels.map(t => (series[key].find(p => p.t === t) || { n: 0 }).n),
        borderColor: color,
        backgroundColor: color + "33",
        tension: 0.2,
        fill: true,
        pointRadius: 0,
    });
    const cfg = {
        type: "line",
        data: {
            labels: labels.map(formatTime),
            datasets: [data("allow", "#10B981"), data("block", "#EF4444")],
        },
        options: {
            responsive: true,
            plugins: { legend: { labels: { color: "#9CA3AF" } } },
            scales: {
                x: { ticks: { color: "#9CA3AF" }, grid: { color: "#232732" } },
                y: { ticks: { color: "#9CA3AF" }, grid: { color: "#232732" }, beginAtZero: true },
            },
        },
    };
    if (trafficChart) {
        trafficChart.data = cfg.data;
        trafficChart.update("none");
    } else {
        trafficChart = new Chart(document.getElementById("chart-traffic"), cfg);
    }
}

function uniqueTimestamps(series) {
    const set = new Set();
    for (const k of Object.keys(series)) for (const p of series[k]) set.add(p.t);
    return [...set].sort();
}

function formatTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
function formatDateTime(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return d.toLocaleString();
}
function relativeTime(iso) {
    if (!iso) return "-";
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return "-";
    const diffS = Math.round((Date.now() - then) / 1000);
    if (diffS < 0)   return "just now";
    if (diffS < 45)  return "just now";
    if (diffS < 90)  return "a minute ago";
    const m = Math.round(diffS / 60);
    if (m < 45)  return `${m} min ago`;
    const h = Math.round(m / 60);
    if (h < 24)  return `${h} hr ago`;
    const days = Math.round(h / 24);
    if (days < 30) return `${days} d ago`;
    return new Date(iso).toLocaleDateString();
}
function shortenURL(u) {
    try {
        const x = new URL(u);
        const path = x.pathname.length > 24 ? x.pathname.slice(0, 23) + "..." : x.pathname;
        return x.hostname + path;
    } catch { return u; }
}

async function refreshLogs() {
    const q = new URLSearchParams();
    q.set("limit", String(logState.limit));
    q.set("offset", String(logState.offset));
    if (els.log.action.value) q.set("action", els.log.action.value);
    if (els.log.method.value) q.set("method", els.log.method.value);
    if (els.log.ip.value.trim())   q.set("source_ip", els.log.ip.value.trim());
    if (els.log.path.value.trim()) q.set("path_contains", els.log.path.value.trim());

    const data = await fetchJSON(`/api/logs?${q.toString()}`);
    if (!data) {
        els.logBody.innerHTML = `<tr><td colspan="8" class="empty">Storage unreachable. Retrying...</td></tr>`;
        return;
    }
    const { rows = [], total = 0, offset = 0, limit = logState.limit } = data;
    logState.total = total;
    logState.offset = offset;

    if (rows.length === 0) {
        els.logBody.innerHTML = `<tr><td colspan="8" class="empty">No requests match the current filters.</td></tr>`;
    } else {
        els.logBody.innerHTML = rows.map(r => `
            <tr data-req-id="${r.request_id || ''}">
                <td>${formatTime(r.timestamp)}</td>
                <td>${r.source_ip ?? "-"}</td>
                <td><span class="method-tag">${r.method}</span></td>
                <td title="${escapeHtml(r.path || '')}">${truncate(r.path, 70)}</td>
                <td><span class="action-tag action-${r.final_action}">${r.final_action}</span></td>
                <td>${fmt3(r.ml_score ?? 0)}</td>
                <td class="rule-hits-cell">${formatRuleHits(r.rule_hits)}</td>
                <td>${r.latency_ms} ms</td>
            </tr>`).join("");
        // Attach click handlers after render.
        els.logBody.querySelectorAll("tr[data-req-id]").forEach(tr => {
            tr.addEventListener("click", () => openRequestDrawer(tr.dataset.reqId));
        });
    }

    // Pager.
    const from = total ? offset + 1 : 0;
    const to = Math.min(offset + rows.length, total);
    els.log.counter.textContent = `${from}-${to} of ${fmt(total)}`;
    els.log.prev.disabled = offset === 0;
    els.log.next.disabled = offset + limit >= total;
}

function formatRuleHits(hits) {
    if (!hits || hits.length === 0) return "-";
    const shown = hits.slice(0, 3).join(", ");
    return hits.length > 3
        ? `${shown} <span class="muted">+${hits.length - 3}</span>`
        : shown;
}

function escapeHtml(s) {
    return String(s ?? "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function openRequestDrawer(requestId) {
    if (!requestId) return;
    els.drawer.backdrop.hidden = false;
    els.drawer.root.classList.add("drawer--open");
    els.drawer.title.textContent = "Request detail";
    els.drawer.subtitle.textContent = requestId;
    els.drawer.body.innerHTML = `<p class="empty">Loading...</p>`;
    const r = await fetchJSON(`/api/logs/${encodeURIComponent(requestId)}`);
    if (!r) {
        els.drawer.body.innerHTML = `<p class="empty">Failed to load request ${escapeHtml(requestId)}.</p>`;
        return;
    }
    els.drawer.title.textContent = `${r.method} ${truncate(r.path, 60)}`;
    els.drawer.subtitle.textContent = `${requestId} · ${formatDateTime(r.timestamp)} · ${r.latency_ms} ms`;
    const f = r.features || {};
    const features = Object.entries(f).map(([k, v]) =>
        `<div class="kv"><dt>${k}</dt><dd>${typeof v === "number" ? Number(v).toFixed(4) : String(v)}</dd></div>`
    ).join("");
    const reasons = (r.reasons || []).map(x => `<li>${escapeHtml(x)}</li>`).join("") || `<li class="muted">none</li>`;
    const headers = Object.entries(r.headers || {}).map(([k, v]) =>
        `<div class="kv"><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd></div>`
    ).join("") || `<p class="muted">no headers captured</p>`;

    const curl = buildCurl(r);
    const canOverride = LG_AUTH.canManageRules();
    const overrideBtn = canOverride
        ? `<button class="btn btn-sm" id="override-btn" type="button" title="Flag this verdict as wrong with a reason">Override verdict</button>`
        : "";
    const overrides = (r.overrides || []).slice().reverse();
    const overridesHtml = overrides.length === 0
        ? ""
        : `<section class="drawer-section">
              <h3>Overrides (${overrides.length})</h3>
              <ul class="override-list">${overrides.map(o =>
                  `<li><span class="override-verdict override-verdict-${escapeHtml(o.verdict)}">${escapeHtml(o.verdict)}</span> &middot; <span class="muted">${escapeHtml(o.actor || "?")} &middot; ${formatDateTime(o.at)}</span><br><span class="override-reason">${escapeHtml(o.reason || "")}</span></li>`
              ).join("")}</ul>
          </section>`;
    els.drawer.body.innerHTML = `
        <section class="drawer-section drawer-actions">
            <button class="btn btn-sm" id="copy-curl-btn" type="button" title="Copy a shell-pasteable curl that reproduces this request">Copy as curl</button>
            ${overrideBtn}
            <span class="copy-feedback" id="copy-curl-feedback" hidden>copied</span>
        </section>
        ${overridesHtml}
        <section class="drawer-section">
            <h3>Verdict</h3>
            <div class="drawer-grid">
                <div class="kv"><dt>Final action</dt><dd><span class="action-tag action-${r.final_action}">${r.final_action}</span></dd></div>
                <div class="kv"><dt>ML action</dt><dd>${escapeHtml(r.ml_action || "-")}</dd></div>
                <div class="kv"><dt>ML score</dt><dd>${fmt3(r.ml_score ?? 0)}</dd></div>
                <div class="kv"><dt>AE anomaly</dt><dd>${fmt3(r.ml_anomaly_score ?? 0)}</dd></div>
                <div class="kv"><dt>HDB outlier</dt><dd>${fmt3(r.ml_outlier_score ?? 0)}</dd></div>
                <div class="kv"><dt>Rule score</dt><dd>${fmt3(r.rule_score ?? 0)}</dd></div>
                <div class="kv"><dt>Rule action</dt><dd>${escapeHtml(r.rule_action || "-")}</dd></div>
                <div class="kv"><dt>Fallback used</dt><dd>${r.fallback_used ? "yes" : "no"}</dd></div>
            </div>
        </section>
        <section class="drawer-section">
            <h3>Reasons</h3>
            <ul class="reason-list">${reasons}</ul>
        </section>
        <section class="drawer-section">
            <h3>Rule hits (${(r.rule_hits || []).length})</h3>
            <p class="rule-hits-list">${(r.rule_hits || []).join(", ") || `<span class="muted">none</span>`}</p>
        </section>
        <section class="drawer-section">
            <h3>Request</h3>
            <div class="drawer-grid">
                <div class="kv"><dt>Source IP</dt><dd>${escapeHtml(r.source_ip || "-")}</dd></div>
                <div class="kv"><dt>Method</dt><dd>${escapeHtml(r.method || "-")}</dd></div>
                <div class="kv"><dt>Path</dt><dd>${escapeHtml(r.path || "-")}</dd></div>
                <div class="kv"><dt>Canonical path</dt><dd>${escapeHtml(r.canonical_path || "-")}</dd></div>
                <div class="kv"><dt>Canonical query</dt><dd>${escapeHtml(r.canonical_query || "-")}</dd></div>
            </div>
            <h4>Canonical body</h4>
            <pre class="code-block">${escapeHtml(r.canonical_body || "(empty)")}</pre>
        </section>
        <section class="drawer-section">
            <h3>Features</h3>
            <div class="drawer-grid">${features || `<p class="muted">no features captured</p>`}</div>
        </section>
        <section class="drawer-section">
            <h3>Headers</h3>
            <div class="drawer-grid drawer-grid--headers">${headers}</div>
        </section>`;

    const copyBtn = document.getElementById("copy-curl-btn");
    const copyFb = document.getElementById("copy-curl-feedback");
    if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(curl);
                if (copyFb) {
                    copyFb.hidden = false;
                    setTimeout(() => { copyFb.hidden = true; }, 1500);
                }
            } catch (err) {
                console.warn("clipboard write failed", err);
                alert("Copy failed. The curl text:\n\n" + curl);
            }
        });
    }
    const overrideBtnEl = document.getElementById("override-btn");
    if (overrideBtnEl) {
        overrideBtnEl.addEventListener("click", async () => {
            const opposite = r.final_action === "block" ? "allow" : "block";
            const verdict = prompt(
                `Override verdict for ${r.method} ${r.path}\nCurrent: ${r.final_action}\nType "allow" or "block":`,
                opposite,
            );
            if (!verdict || (verdict !== "allow" && verdict !== "block")) return;
            const reason = prompt("Reason (3-500 chars) -- this is permanently logged:");
            if (!reason || reason.length < 3) { alert("Reason required."); return; }
            const res = await fetchJSON(`/api/logs/${encodeURIComponent(requestId)}/override`, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({ verdict, reason }),
            });
            if (res) {
                openRequestDrawer(requestId);
            } else {
                alert("Override failed -- see console.");
            }
        });
    }
}

// Reconstruct a shell-pasteable curl from an audit record. Single quotes
// inside strings are POSIX-escaped via close-quote + escaped-quote + reopen
// ('\''), which is the only portable way to embed a single quote in a
// single-quoted bash string. Uses PROXY_BASE so the curl hits the WAF, not
// the upstream directly -- which is the whole point of reproducing the
// request in the first place.
function buildCurl(r) {
    const shellQuote = (s) => `'` + String(s).replace(/'/g, `'\\''`) + `'`;
    const parts = ["curl", "-i"];
    const method = (r.method || "GET").toUpperCase();
    if (method !== "GET") {
        parts.push("-X", method);
    }
    const skipHeaders = new Set(["host", "content-length", "connection"]);
    for (const [k, v] of Object.entries(r.headers || {})) {
        if (skipHeaders.has(k.toLowerCase())) continue;
        parts.push("-H", shellQuote(`${k}: ${v}`));
    }
    if (r.canonical_body) {
        parts.push("--data-raw", shellQuote(r.canonical_body));
    }
    const url = `${PROXY_BASE}${r.path || "/"}`;
    parts.push(shellQuote(url));
    return parts.join(" ");
}

// ---------------------------- M8/M9/M10 rules tab -------------------------
const rulesState = { status: "", lastRows: [] };

async function refreshRules() {
    const qs = rulesState.status ? `?status=${encodeURIComponent(rulesState.status)}` : "";
    const data = await fetchJSON(`/api/rules/candidates${qs}`);
    if (!data) return;
    const rows = data.rows || [];
    rulesState.lastRows = rows;
    const counter = document.getElementById("rules-counter");
    if (counter) counter.textContent = `${rows.length} shown`;
    if (rows.length === 0) {
        els.rulesBody.innerHTML = `<tr><td colspan="7" class="empty">No rules match this filter.</td></tr>`;
        return;
    }
    els.rulesBody.innerHTML = rows.map(r => {
        const items = (r.pattern && r.pattern.items) || [];
        const supportPct = r.pattern && r.pattern.support != null
            ? (r.pattern.support * 100).toFixed(1) + "%"
            : "-";
        const tags = (r.tags || []).map(t => `<span class="tag-chip">${escapeHtml(t)}</span>`).join("");
        return `<tr data-rule-id="${r.rule_id}">
            <td><code>${r.rule_id}</code></td>
            <td><span class="status-pill status-${r.status}">${r.status}</span></td>
            <td class="items-cell">${items.map(i => `<span class="item-chip">${escapeHtml(i)}</span>`).join("")}</td>
            <td>${supportPct}</td>
            <td>${tags || "-"}</td>
            <td title="${formatDateTime(r.updated_at)}">${relativeTime(r.updated_at)}</td>
            <td class="actions-cell">${renderRuleActions(r)}</td>
        </tr>`;
    }).join("");
}

function renderRuleActions(r) {
    const buttons = [];
    // View is read-only -- always available.
    buttons.push(`<button class="btn btn-sm" data-rule-act="view" data-rule-id="${r.rule_id}">View</button>`);
    if (!LG_AUTH.canManageRules()) return buttons.join(" ");
    if (r.status === "pending") {
        buttons.push(`<button class="btn btn-sm btn-primary" data-rule-act="approve" data-rule-id="${r.rule_id}">Approve</button>`);
        buttons.push(`<button class="btn btn-sm btn-danger" data-rule-act="reject" data-rule-id="${r.rule_id}">Reject</button>`);
    } else if (r.status === "approved" || r.status === "live") {
        buttons.push(`<button class="btn btn-sm btn-danger" data-rule-act="expire" data-rule-id="${r.rule_id}">Expire</button>`);
    } else if (r.status === "rejected" || r.status === "expired") {
        buttons.push(`<button class="btn btn-sm" data-rule-act="delete" data-rule-id="${r.rule_id}">Delete</button>`);
    }
    return buttons.join(" ");
}

// Single delegated handler so freshly-rendered rows pick up clicks.
els.rulesBody && els.rulesBody.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-rule-act]");
    if (!btn) return;
    const ruleId = Number(btn.dataset.ruleId);
    const act = btn.dataset.ruleAct;
    btn.disabled = true;
    try {
        if (act === "view") return openRuleModal(ruleId);
        const path = `/api/rules/candidates/${ruleId}/${act === "delete" ? "" : act}`;
        const init = act === "delete"
            ? { method: "DELETE" }
            : { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({}) };
        const res = await fetchJSON(act === "delete" ? `/api/rules/candidates/${ruleId}` : path, init);
        if (res === null) {
            alert(`Action ${act} failed - see console`);
        }
    } finally {
        btn.disabled = false;
        refreshRules();
    }
});

// Status filter chips.
const rulesFilters = document.getElementById("rules-filters");
if (rulesFilters) {
    rulesFilters.addEventListener("click", (e) => {
        const chip = e.target.closest("[data-rule-status]");
        if (!chip) return;
        rulesState.status = chip.dataset.ruleStatus;
        rulesFilters.querySelectorAll(".chip").forEach(c =>
            c.classList.toggle("chip--active", c === chip));
        refreshRules();
    });
}

// Mining controls.
const mineRunBtn = document.getElementById("mine-run");
const mineStatusEl = document.getElementById("mine-status");
if (mineRunBtn) {
    mineRunBtn.addEventListener("click", async () => {
        const payload = {
            min_support: Number(document.getElementById("mine-support").value) || 0.05,
            min_itemset_len: Number(document.getElementById("mine-min-len").value) || 2,
            max_itemset_len: Number(document.getElementById("mine-max-len").value) || 4,
            lookback_hours: Number(document.getElementById("mine-lookback").value) || 168,
            only_blocked: document.getElementById("mine-only-blocked").checked,
            emit_candidates: document.getElementById("mine-emit").checked,
        };
        mineRunBtn.disabled = true;
        if (mineStatusEl) mineStatusEl.textContent = "running...";
        const result = await fetchJSON("/api/mining/run", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload),
        });
        mineRunBtn.disabled = false;
        if (!result) {
            if (mineStatusEl) mineStatusEl.textContent = "failed - see console";
            return;
        }
        const synth = result.synthesis || {};
        const inserted = (synth.inserted || []).length;
        const refreshed = (synth.refreshed || []).length;
        if (mineStatusEl) {
            mineStatusEl.textContent =
                `${result.transactions} txns, ${(result.patterns || []).length} patterns, ` +
                `${inserted} new + ${refreshed} refreshed candidates ` +
                `(${result.elapsed_ms} ms)`;
        }
        refreshRules();
    });
}

// Rule modal (view + edit).
const ruleModal = {
    backdrop: document.getElementById("rule-modal-backdrop"),
    body:     document.getElementById("rule-modal-body"),
    title:    document.getElementById("rule-modal-title"),
    save:     document.getElementById("rule-modal-save"),
    cancel:   document.getElementById("rule-modal-cancel"),
    close:    document.getElementById("rule-modal-close"),
    currentId: null,
};
function closeRuleModal() {
    if (ruleModal.backdrop) ruleModal.backdrop.hidden = true;
    ruleModal.currentId = null;
}
if (ruleModal.close)  ruleModal.close.addEventListener("click", closeRuleModal);
if (ruleModal.cancel) ruleModal.cancel.addEventListener("click", closeRuleModal);
if (ruleModal.backdrop) ruleModal.backdrop.addEventListener("click", (e) => {
    if (e.target === ruleModal.backdrop) closeRuleModal();
});
const ruleModalPreview = document.getElementById("rule-modal-preview");
if (ruleModalPreview) {
    ruleModalPreview.addEventListener("click", async () => {
        const rid = ruleModal.currentId;
        if (rid == null) return;
        ruleModalPreview.disabled = true;
        ruleModalPreview.textContent = "Scanning...";
        const res = await fetchJSON(`/api/rules/candidates/${rid}/preview`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ lookback_hours: 168, limit: 50 }),
        });
        ruleModalPreview.disabled = false;
        ruleModalPreview.textContent = "Preview matches";
        if (!res) { alert("Preview failed -- see console"); return; }
        renderRulePreview(res);
    });
}

function renderRulePreview(res) {
    const body = document.getElementById("rule-modal-body");
    if (!body) return;
    const existing = document.getElementById("rule-preview-section");
    if (existing) existing.remove();
    const matched = res.matched || [];
    const html = `
        <div class="modal-section" id="rule-preview-section">
            <label>Preview (last ${res.lookback_hours} h)</label>
            <div class="preview-summary">
                <span><strong>${res.total_scanned}</strong> rows scanned</span>
                <span><strong>${matched.length}${res.total_matched === null ? "+" : ""}</strong> would match</span>
                <span class="${res.caught_new > 0 ? "preview-new" : "muted"}">
                    <strong>${res.caught_new}</strong> currently <code>allow</code> -- this rule would NEWLY block them
                </span>
            </div>
            ${matched.length === 0
                ? `<p class="muted">No audit rows in the lookback window match this candidate's items.</p>`
                : `<ul class="preview-list">
                    ${matched.map(m => `
                        <li class="${m.would_change ? "preview-row-new" : ""}">
                            <span class="action-tag action-${escapeHtml(m.final_action || "?")}">${escapeHtml(m.final_action || "?")}</span>
                            <code>${escapeHtml(m.method || "?")} ${escapeHtml((m.path || "").slice(0, 80))}</code>
                            <span class="muted">${relativeTime(m.timestamp)}</span>
                            ${m.would_change ? `<span class="preview-arrow">&rarr; block</span>` : ""}
                        </li>`).join("")}
                </ul>`}
        </div>`;
    body.insertAdjacentHTML("beforeend", html);
}

if (ruleModal.save) ruleModal.save.addEventListener("click", async () => {
    const rid = ruleModal.currentId;
    if (rid == null) return;
    const text = document.getElementById("rule-edit-text");
    const msg = document.getElementById("rule-edit-message");
    const notes = document.getElementById("rule-edit-notes");
    ruleModal.save.disabled = true;
    const res = await fetchJSON(`/api/rules/candidates/${rid}`, {
        method: "PUT",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            rule_text: text ? text.value : null,
            message:   msg ? msg.value : null,
            notes:     notes ? notes.value : null,
        }),
    });
    ruleModal.save.disabled = false;
    if (res) {
        closeRuleModal();
        refreshRules();
    } else {
        alert("Edit failed - see console");
    }
});

async function openRuleModal(rid) {
    const r = await fetchJSON(`/api/rules/candidates/${rid}`);
    if (!r || !ruleModal.backdrop) return;
    ruleModal.currentId = rid;
    ruleModal.title.textContent = `Rule ${rid} (${r.status})`;
    const history = (r.edit_history || []).slice(-5).reverse().map(h =>
        `<li><span class="muted">${formatDateTime(h.at)}</span> &mdash; ${escapeHtml(h.actor || "?")}: ${escapeHtml(h.from)} &rarr; ${escapeHtml(h.to)}${h.note ? " (" + escapeHtml(h.note) + ")" : ""}</li>`
    ).join("") || "<li class='muted'>no history</li>";
    ruleModal.body.innerHTML = `
        <div class="modal-section">
            <label>Message</label>
            <input type="text" id="rule-edit-message" value="${escapeHtml(r.message || "")}">
        </div>
        <div class="modal-section">
            <label>Rule text (ModSecurity)</label>
            <textarea id="rule-edit-text" rows="12" spellcheck="false">${escapeHtml(r.rule_text || "")}</textarea>
        </div>
        <div class="modal-section">
            <label>Notes (operator-only, never deployed)</label>
            <input type="text" id="rule-edit-notes" value="${escapeHtml(r.notes || "")}">
        </div>
        <div class="modal-section">
            <label>Pattern</label>
            <div>${((r.pattern && r.pattern.items) || []).map(i => `<span class="item-chip">${escapeHtml(i)}</span>`).join(" ")}</div>
            <div class="muted">support ${(r.pattern && r.pattern.support != null) ? (r.pattern.support * 100).toFixed(2) + "%" : "-"} &middot; ${(r.pattern && r.pattern.support_count) || 0} of ${(r.pattern && r.pattern.support_count != null) ? "..." : "?"} transactions</div>
        </div>
        <div class="modal-section">
            <label>State history</label>
            <ul class="history-list">${history}</ul>
        </div>`;
    ruleModal.backdrop.hidden = false;
}

function truncate(s, n) {
    if (!s) return "-";
    return s.length > n ? s.slice(0, n - 1) + "..." : s;
}

/* ----------------------------- M3 model cards ----------------------------- */

function renderLoadedPill(el, loaded) {
    el.textContent = loaded ? "loaded" : "not loaded";
    el.className = "pill " + (loaded ? "pill--ok" : "pill--danger");
}

async function refreshModels() {
    const s = await fetchJSON("/api/models/status");
    if (!s) return;
    const ae = s.autoencoder || {};
    const hdb = s.hdbscan || {};

    renderLoadedPill(els.ae.pill, !!ae.loaded);
    els.ae.version.textContent = ae.version ?? "-";
    els.ae.trained.textContent = formatDateTime(ae.trained_at);
    els.ae.samples.textContent = fmt(ae.samples);
    els.ae.bottleneck.textContent = ae.bottleneck ?? "-";
    els.ae.p95.textContent = ae.recon_error_p95 != null ? Number(ae.recon_error_p95).toExponential(3) : "-";
    els.ae.threshold.textContent = ae.threshold != null ? Number(ae.threshold).toExponential(3) : "-";

    renderLoadedPill(els.hdb.pill, !!hdb.loaded);
    els.hdb.version.textContent = hdb.version ?? "-";
    els.hdb.trained.textContent = formatDateTime(hdb.trained_at);
    els.hdb.samples.textContent = fmt(hdb.samples);
    els.hdb.clusters.textContent = hdb.n_clusters ?? "-";
    els.hdb.noise.textContent = hdb.n_noise != null ? `${fmt(hdb.n_noise)} (${(hdb.noise_ratio * 100).toFixed(2)}%)` : "-";
    els.hdb.mcs.textContent = hdb.min_cluster_size ?? "-";
}

document.querySelectorAll("[data-retrain]").forEach(btn => {
    btn.addEventListener("click", async () => {
        const model = btn.dataset.retrain;
        const statusEl = model === "autoencoder" ? els.ae.status : els.hdb.status;
        btn.disabled = true;
        statusEl.textContent = "starting retrain...";
        const res = await fetchJSON(`/api/models/retrain?model=${model}`, { method: "POST" });
        statusEl.textContent = res ? "training in background" : "failed to start (check ML logs)";
        setTimeout(() => { btn.disabled = false; statusEl.textContent = ""; refreshModels(); }, 4000);
    });
});

/* ----------------------------- M6 consensus ----------------------------- */

function setMode(m) {
    els.consensus.modes.forEach(r => r.checked = (r.value === m));
}

function getMode() {
    const sel = [...els.consensus.modes].find(r => r.checked);
    return sel ? sel.value : "weighted";
}

function updateWeightSum() {
    const sum = Number(els.consensus.wAe.value) + Number(els.consensus.wHdb.value) + Number(els.consensus.wRule.value);
    els.consensus.sum.textContent = sum;
    els.consensus.sum.parentElement.classList.toggle("bad", sum !== 100);
    els.consensus.save.disabled = sum !== 100;
}

function bindSlider(input, label, formatter) {
    input.addEventListener("input", () => { label.textContent = formatter(Number(input.value)); updateWeightSum(); });
}

bindSlider(els.consensus.wAe,   els.consensus.wAeV,   v => v);
bindSlider(els.consensus.wHdb,  els.consensus.wHdbV,  v => v);
bindSlider(els.consensus.wRule, els.consensus.wRuleV, v => v);
els.consensus.threshold.addEventListener("input", () => {
    els.consensus.thresholdV.textContent = (Number(els.consensus.threshold.value) / 100).toFixed(2);
});
els.consensus.pmt.addEventListener("input", () => {
    els.consensus.pmtV.textContent = (Number(els.consensus.pmt.value) / 100).toFixed(2);
});

async function refreshConsensusConfig() {
    const c = await fetchJSON("/api/consensus/config");
    if (!c) return;
    setMode(c.mode);
    els.consensus.wAe.value = c.weight_autoencoder;
    els.consensus.wHdb.value = c.weight_hdbscan;
    els.consensus.wRule.value = c.weight_rule;
    els.consensus.wAeV.textContent = c.weight_autoencoder;
    els.consensus.wHdbV.textContent = c.weight_hdbscan;
    els.consensus.wRuleV.textContent = c.weight_rule;
    els.consensus.threshold.value = Math.round(c.threshold * 100);
    els.consensus.thresholdV.textContent = c.threshold.toFixed(2);
    els.consensus.pmt.value = Math.round(c.per_model_threshold * 100);
    els.consensus.pmtV.textContent = c.per_model_threshold.toFixed(2);
    updateWeightSum();
}

els.consensus.save.addEventListener("click", async () => {
    const payload = {
        mode: getMode(),
        weight_autoencoder: Number(els.consensus.wAe.value),
        weight_hdbscan: Number(els.consensus.wHdb.value),
        weight_rule: Number(els.consensus.wRule.value),
        threshold: Number(els.consensus.threshold.value) / 100,
        per_model_threshold: Number(els.consensus.pmt.value) / 100,
    };
    els.consensus.save.disabled = true;
    els.consensus.status.textContent = "saving...";
    const res = await fetchJSON("/api/consensus/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    els.consensus.status.textContent = res ? "saved" : "failed (check ML logs)";
    els.consensus.save.disabled = false;
    setTimeout(() => { els.consensus.status.textContent = ""; }, 2500);
});

async function refreshDecisions() {
    const data = await fetchJSON("/api/logs?limit=20");
    if (!data) return;
    const rows = data.rows || [];
    if (rows.length === 0) {
        els.consensus.decisionsBody.innerHTML = `<tr><td colspan="7" class="empty">No requests yet.</td></tr>`;
        return;
    }
    els.consensus.decisionsBody.innerHTML = rows.map(r => `
        <tr>
            <td>${formatTime(r.timestamp)}</td>
            <td>${r.method}</td>
            <td>${truncate(r.path, 50)}</td>
            <td>${fmt3(r.ml_anomaly_score ?? 0)}</td>
            <td>${fmt3(r.ml_outlier_score ?? 0)}</td>
            <td>${fmt3(r.rule_score ?? 0)}</td>
            <td><span class="action-tag action-${r.final_action}">${r.final_action}</span></td>
        </tr>`).join("");
}

/* ------------------------------- main loop ------------------------------- */

async function refreshThreatIntel() {
    const s = await fetchJSONFrom(PROXY_BASE, "/__threatintel");
    const setPill = (el, klass, text) => { if (!el) return; el.className = "pill " + klass; el.textContent = text; };

    if (!s) {
        setPill(els.ti.pill, "pill--danger", "proxy unreachable");
        setPill(els.ti.topbarPill, "pill pill--danger", "Threat intel: down");
        return;
    }
    const ok = s.enabled && s.entry_count > 0 && !s.last_error;
    const pillText = !s.enabled ? "disabled"
        : s.last_error ? "stale" : `${fmt(s.entry_count)} entries`;
    const pillKlass = !s.enabled ? "pill--warn" : ok ? "pill--ok" : "pill--danger";
    setPill(els.ti.pill, pillKlass, pillText);

    // Topbar mini-pill mirrors the card status.
    const topbarText = !s.enabled ? "Threat intel: off"
        : s.last_error ? "Threat intel: stale" : `Threat intel: ${fmt(s.entry_count)}`;
    setPill(els.ti.topbarPill, pillKlass, topbarText);

    els.ti.enabled.textContent  = s.enabled ? "active" : "disabled";
    els.ti.entries.textContent  = fmt(s.entry_count);
    els.ti.lastSync.textContent = relativeTime(s.last_sync);
    if (s.last_sync) els.ti.lastSync.title = formatDateTime(s.last_sync); // hover for absolute
    els.ti.bytes.textContent    = s.bytes_written != null ? `${fmt(s.bytes_written)} B` : "-";
    els.ti.error.textContent    = s.last_error || "(none)";
    if (s.last_error) els.ti.error.classList.add("muted-danger"); else els.ti.error.classList.remove("muted-danger");

    // Source chips.
    const sources = s.sources || [];
    els.ti.sourcesChips.innerHTML = sources.length === 0
        ? `<span class="ti-source muted">none configured</span>`
        : sources.map(u => `<span class="ti-source" title="${escapeHtml(u)}">${escapeHtml(shortenURL(u))}</span>`).join("");
}

// M11-full: model-promotion HITL queue. Shows pending / live / rejected
// candidates with the AE training-stats delta vs the live model. Approve
// runs an atomic file swap + in-memory reload; reject deletes the
// .candidate.* artefacts without touching the live model.
async function refreshPromotion() {
    const tbody = document.getElementById("promotion-tbody");
    if (!tbody) return;
    const data = await fetchJSON("/api/models/candidates");
    if (!data) return;
    const rows = data.rows || [];
    if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty">No candidates yet. Drift detection or the manual button above will create one.</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(r => {
        const s = r.stats || {};
        const thr = s.threshold != null ? Number(s.threshold).toFixed(4) : "-";
        const p95 = s.recon_error_p95 != null ? Number(s.recon_error_p95).toFixed(4) : "-";
        const samples = s.samples != null ? s.samples : "-";
        const actions = [];
        if (r.status === "pending" && LG_AUTH.canManageModels()) {
            actions.push(`<button class="btn btn-sm btn-primary" data-promo-act="approve" data-id="${r._id}">Promote to live</button>`);
            actions.push(`<button class="btn btn-sm btn-danger" data-promo-act="reject" data-id="${r._id}">Reject</button>`);
        } else if (r.status === "training") {
            actions.push(`<span class="muted">training...</span>`);
        }
        return `<tr>
            <td><span class="status-pill status-${escapeHtml(r.status)}">${escapeHtml(r.status)}</span></td>
            <td>${escapeHtml(r.source || "-")}</td>
            <td title="${escapeHtml(r.created_at || "")}">${relativeTime(r.created_at)}</td>
            <td><code>${thr}</code></td>
            <td><code>${p95}</code></td>
            <td>${samples}</td>
            <td class="actions-cell">${actions.join(" ")}</td>
        </tr>`;
    }).join("");
}

// Manual retrain trigger.
const _promoRetrain = document.getElementById("promotion-retrain-btn");
if (_promoRetrain) {
    if (LG_AUTH.canManageModels()) _promoRetrain.hidden = false;
    _promoRetrain.addEventListener("click", async () => {
        const status = document.getElementById("promotion-status");
        _promoRetrain.disabled = true;
        if (status) status.textContent = "spawning...";
        const res = await fetchJSON("/api/models/candidates/retrain", { method: "POST" });
        _promoRetrain.disabled = false;
        if (!res) { if (status) status.textContent = "failed -- see console"; return; }
        if (res.existing) {
            if (status) status.textContent = "a pending candidate already exists -- approve/reject it first";
        } else {
            if (status) status.textContent = `training kicked off (id: ${res.candidate_id})`;
        }
        refreshPromotion();
    });
}

const _promoTbody = document.getElementById("promotion-tbody");
if (_promoTbody) {
    _promoTbody.addEventListener("click", async (e) => {
        const btn = e.target.closest("[data-promo-act]");
        if (!btn) return;
        const id = btn.dataset.id;
        const act = btn.dataset.promoAct;
        if (act === "approve" && !confirm("Promote this candidate to live? The current model is replaced atomically and the in-memory store reloads.")) return;
        if (act === "reject" && !confirm("Reject this candidate? The .candidate.* artefacts will be deleted; the live model is untouched.")) return;
        btn.disabled = true;
        const res = await fetchJSON(`/api/models/candidates/${id}/${act}`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({}),
        });
        btn.disabled = false;
        if (!res) alert(`${act} failed -- see console`);
        refreshPromotion();
    });
}

// SI-6: SIEM forwarder pill. Off when no destination configured;
// otherwise shows the rolling event count + last error if any.
async function refreshSiem() {
    const pill = document.getElementById("siem-pill");
    if (!pill) return;
    const s = await fetchJSON("/api/siem/status");
    if (!s) { pill.className = "pill pill--danger"; pill.textContent = "SIEM: down"; return; }
    if (!s.enabled) {
        pill.className = "pill pill--neutral";
        pill.textContent = "SIEM: off";
        pill.title = "Set SYSLOG_HOST or SIEM_LOG_PATH in compose to enable CEF export";
        return;
    }
    const dests = [];
    if (s.syslog_host) dests.push(`udp://${s.syslog_host}:${s.syslog_port}`);
    if (s.file_path) dests.push(s.file_path);
    if (s.errors_total > 0) {
        pill.className = "pill pill--warn";
        pill.textContent = `SIEM: ${s.events_total} ev / ${s.errors_total} err`;
    } else {
        pill.className = "pill pill--ok";
        pill.textContent = `SIEM: ${s.events_total} ev`;
    }
    pill.title = `Destinations: ${dests.join(", ") || "(none)"}\nLast export: ${s.last_export_at || "never"}\nLast error: ${s.last_error || "(none)"}`;
}

// FR-MON-1: model accuracy panel + topbar pill. Numbers derived from
// operator overrides via /api/models/accuracy.
async function refreshAccuracy() {
    const pill = document.getElementById("accuracy-pill");
    const a = await fetchJSON("/api/models/accuracy");
    const setPill = (cls, text, title) => {
        if (!pill) return;
        pill.className = cls;
        pill.textContent = text;
        if (title) pill.title = title;
    };
    if (!a) { setPill("pill pill--danger", "Accuracy: down"); return; }
    const fmtPct = (v) => v == null ? "-" : (v * 100).toFixed(1) + "%";
    const $ = (id) => document.getElementById(id);
    if ($("acc-precision")) $("acc-precision").textContent = fmtPct(a.precision);
    if ($("acc-recall"))    $("acc-recall").textContent    = fmtPct(a.recall);
    if ($("acc-f1"))        $("acc-f1").textContent        = a.f1 == null ? "-" : Number(a.f1).toFixed(3);
    if ($("acc-fpr"))       $("acc-fpr").textContent       = fmtPct(a.false_positive_rate);
    if ($("acc-confusion")) $("acc-confusion").textContent = `${a.tp} / ${a.tn} / ${a.fp} / ${a.fn}`;
    if ($("acc-sample"))    $("acc-sample").textContent    = `${a.total} requests over ${a.lookback_hours} h`;
    const alert = a.alert || {};
    if (alert.fpr_high) {
        setPill("pill pill--danger", `FPR ${fmtPct(a.false_positive_rate)} !`,
            `Above the ${(alert.fpr_threshold * 100).toFixed(1)}% alert threshold`);
    } else if (alert.recall_low) {
        setPill("pill pill--warn", `Recall ${fmtPct(a.recall)} !`,
            `Below the ${(alert.recall_threshold * 100).toFixed(0)}% alert threshold`);
    } else if (a.tp + a.fp + a.fn === 0) {
        setPill("pill pill--neutral", "Accuracy: no labels",
            "No operator overrides in the lookback window -- model accuracy is unmeasured");
    } else {
        setPill("pill pill--ok", `F1 ${a.f1 == null ? "-" : Number(a.f1).toFixed(2)}`,
            `Precision ${fmtPct(a.precision)} / Recall ${fmtPct(a.recall)}`);
    }
}

// FR7.4: live training loss chart on the Models tab. Polled by the
// normal 5 s tick; when the JSONL stops growing for >60s we mark
// status as "completed" and stop emphasising the chart.
let aeLossChart = null;
async function refreshAeLoss() {
    const status = document.getElementById("ae-loss-status");
    const canvas = document.getElementById("chart-ae-loss");
    if (!canvas) return;
    const data = await fetchJSON("/api/models/training-progress?model=autoencoder&tail=200");
    if (!data) return;
    const rows = data.rows || [];
    if (status) {
        status.textContent = rows.length === 0
            ? "no recent run"
            : (data.is_active ? `training... epoch ${rows[rows.length - 1].epoch}` : `last run: ${rows.length} epochs`);
        status.classList.toggle("loss-live", !!data.is_active);
    }
    if (rows.length === 0) return;
    const labels = rows.map(r => String(r.epoch));
    const lossSeries = rows.map(r => r.loss);
    const valSeries = rows.map(r => r.val_loss);
    if (!aeLossChart) {
        aeLossChart = new Chart(canvas, {
            type: "line",
            data: {
                labels,
                datasets: [
                    { label: "loss", data: lossSeries, borderColor: "#10B981", tension: 0.2, pointRadius: 0, fill: false },
                    { label: "val_loss", data: valSeries, borderColor: "#F59E0B", tension: 0.2, pointRadius: 0, fill: false },
                ],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { labels: { color: "#9CA3AF", boxWidth: 12 } } },
                scales: {
                    x: { ticks: { color: "#9CA3AF" }, grid: { color: "#232732" } },
                    y: { ticks: { color: "#9CA3AF" }, grid: { color: "#232732" } },
                },
            },
        });
    } else {
        aeLossChart.data.labels = labels;
        aeLossChart.data.datasets[0].data = lossSeries;
        aeLossChart.data.datasets[1].data = valSeries;
        aeLossChart.update("none");
    }
}

async function refreshDrift() {
    const pill = document.getElementById("drift-pill");
    if (!pill) return;
    const d = await fetchJSON("/api/models/drift?window_min=60&baseline_min=1440");
    if (!d) {
        pill.className = "pill pill--danger";
        pill.textContent = "Drift: down";
        return;
    }
    if (d.z_score == null) {
        pill.className = "pill pill--neutral";
        pill.textContent = `Drift: warm-up (${d.window.n}/${d.baseline.n})`;
        return;
    }
    const z = d.z_score;
    const klass = d.drift_detected
        ? (z > 0 ? "pill pill--danger" : "pill pill--warn")
        : "pill pill--ok";
    pill.className = klass;
    pill.textContent = `Drift z=${z.toFixed(2)}${d.drift_detected ? " !" : ""}`;
    pill.title = `Window n=${d.window.n} mean=${d.window.mean.toFixed(3)} | ` +
                 `Baseline n=${d.baseline.n} mean=${d.baseline.mean.toFixed(3)} std=${d.baseline.std.toFixed(3)}`;
}

async function tick() {
    const calls = [
        refreshHealth(), refreshSafeMode(), refreshMetrics(), refreshTraffic(),
        refreshLogs(), refreshRules(),
        refreshModels(), refreshDecisions(), refreshThreatIntel(), refreshDrift(),
        refreshBruteForce(), refreshAeLoss(), refreshAccuracy(), refreshSiem(),
        refreshPromotion(),
    ];
    if (LG_AUTH.canManageUsers()) calls.push(refreshUsers());
    await Promise.all(calls);
}

// SEC-10: top-of-screen pill + Users-tab table for IPs that hit
// the brute-force threshold within the rolling 5-minute window.
async function refreshBruteForce() {
    const pill = document.getElementById("bruteforce-pill");
    const data = await fetchJSON("/api/auth/alerts/brute-force");
    if (!data) {
        if (pill) { pill.className = "pill pill--danger"; pill.textContent = "Auth: down"; }
        return;
    }
    const alerts = data.alerts || [];
    if (pill) {
        if (alerts.length === 0) {
            pill.className = "pill pill--ok";
            pill.textContent = "Auth: clean";
        } else {
            pill.className = "pill pill--danger";
            pill.textContent = `Auth: ${alerts.length} hot IP${alerts.length === 1 ? "" : "s"}`;
            pill.title = alerts.map(a => `${a.ip} (${a.count} fails)`).join("\n");
        }
    }
    const tbody = document.getElementById("bruteforce-tbody");
    if (tbody) {
        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty">No alerts.</td></tr>`;
        } else {
            tbody.innerHTML = alerts.map(a => `
                <tr>
                    <td><code>${escapeHtml(a.ip)}</code></td>
                    <td>${a.count}</td>
                    <td title="${escapeHtml(a.last || "")}">${relativeTime(a.last)}</td>
                    <td>${(a.usernames || []).map(u => `<span class="item-chip">${escapeHtml(u)}</span>`).join("") || "<span class='muted'>none</span>"}</td>
                </tr>`).join("");
        }
    }
}

// MFA self-service flow on the Users tab.
async function refreshMfaState() {
    const statusEl = document.getElementById("mfa-status");
    if (!statusEl) return;
    const me = await fetchJSON("/api/auth/me");
    if (!me) { statusEl.textContent = "Unable to load MFA state."; return; }
    const enroll = document.getElementById("mfa-enroll-btn");
    const disable = document.getElementById("mfa-disable-btn");
    const pane = document.getElementById("mfa-enroll-pane");
    if (me.mfa_enabled) {
        statusEl.textContent = "MFA enabled.";
        enroll.hidden = true;
        disable.hidden = false;
        pane.hidden = true;
    } else {
        statusEl.textContent = "MFA not enabled.";
        enroll.hidden = false;
        disable.hidden = true;
    }
}

const mfaEnrollBtn = document.getElementById("mfa-enroll-btn");
if (mfaEnrollBtn) {
    mfaEnrollBtn.addEventListener("click", async () => {
        mfaEnrollBtn.disabled = true;
        const res = await fetchJSON("/api/auth/me/mfa/begin", { method: "POST" });
        mfaEnrollBtn.disabled = false;
        if (!res) { alert("Enrollment start failed."); return; }
        document.getElementById("mfa-uri").textContent = res.otpauth_uri;
        document.getElementById("mfa-secret").value = res.secret;
        document.getElementById("mfa-enroll-pane").hidden = false;
    });
}

const mfaConfirmBtn = document.getElementById("mfa-confirm-btn");
if (mfaConfirmBtn) {
    mfaConfirmBtn.addEventListener("click", async () => {
        const code = (document.getElementById("mfa-confirm-code").value || "").trim();
        if (code.length < 6) { alert("Enter the 6-digit code from your app."); return; }
        mfaConfirmBtn.disabled = true;
        const res = await fetchJSON("/api/auth/me/mfa/confirm", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ code }),
        });
        mfaConfirmBtn.disabled = false;
        if (!res) { alert("MFA confirmation failed -- check the code (it expires every 30s)."); return; }
        alert("MFA enabled. You'll need the code on every login from now on.");
        refreshMfaState();
    });
}

const mfaDisableBtn = document.getElementById("mfa-disable-btn");
if (mfaDisableBtn) {
    mfaDisableBtn.addEventListener("click", async () => {
        const pw = prompt("Confirm your current password to disable MFA:");
        if (!pw) return;
        const res = await fetchJSON("/api/auth/me/mfa/disable", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ password: pw }),
        });
        if (!res) { alert("Disable failed (wrong password?)."); return; }
        refreshMfaState();
    });
}

// Refresh MFA state on Users-tab activation so its visible immediately.
document.querySelectorAll('[data-route="users"]').forEach(link => {
    link.addEventListener("click", () => setTimeout(refreshMfaState, 50));
});

// ---------------------------- Users tab (admin) ---------------------------
async function refreshUsers() {
    const tbody = document.getElementById("users-tbody");
    if (!tbody) return;
    const data = await fetchJSON("/api/auth/users");
    if (!data) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty">Failed to load users.</td></tr>`;
        return;
    }
    const rows = data.rows || [];
    if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty">No users yet.</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(u => `
        <tr data-username="${escapeHtml(u.username)}">
            <td><code>${escapeHtml(u.username)}</code></td>
            <td>
                <select class="user-role-sel" data-username="${escapeHtml(u.username)}">
                    ${["admin","security-operator","ml-engineer","auditor"].map(r =>
                        `<option value="${r}" ${u.role===r?"selected":""}>${r}</option>`).join("")}
                </select>
            </td>
            <td>${u.active ? "<span class='status-pill status-live'>active</span>" : "<span class='status-pill status-expired'>inactive</span>"}</td>
            <td title="${escapeHtml(u.last_login || "")}">${u.last_login ? relativeTime(u.last_login) : "<span class='muted'>never</span>"}</td>
            <td>${u.created_at ? relativeTime(u.created_at) : "-"}</td>
            <td class="actions-cell">
                <button class="btn btn-sm" data-user-act="${u.active ? "deactivate" : "activate"}" data-username="${escapeHtml(u.username)}">${u.active ? "Disable" : "Enable"}</button>
                <button class="btn btn-sm" data-user-act="reset-password" data-username="${escapeHtml(u.username)}">Reset password</button>
                <button class="btn btn-sm btn-danger" data-user-act="delete" data-username="${escapeHtml(u.username)}">Delete</button>
            </td>
        </tr>
    `).join("");
}

// Users table delegated handler: role change, activate/deactivate, reset
// password, delete.
const usersTbody = document.getElementById("users-tbody");
if (usersTbody) {
    usersTbody.addEventListener("change", async (e) => {
        const sel = e.target.closest(".user-role-sel");
        if (!sel) return;
        const username = sel.dataset.username;
        const newRole = sel.value;
        if (!confirm(`Change role for ${username} to ${newRole}?`)) {
            refreshUsers();
            return;
        }
        sel.disabled = true;
        const res = await fetchJSON(`/api/auth/users/${encodeURIComponent(username)}`, {
            method: "PUT",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ role: newRole }),
        });
        sel.disabled = false;
        if (!res) alert("Role change failed (see console). Possibly the only-admin guard fired.");
        refreshUsers();
    });
    usersTbody.addEventListener("click", async (e) => {
        const btn = e.target.closest("[data-user-act]");
        if (!btn) return;
        const username = btn.dataset.username;
        const act = btn.dataset.userAct;
        btn.disabled = true;
        try {
            if (act === "delete") {
                if (!confirm(`Hard-delete ${username}? This breaks the audit trail. Prefer Disable.`)) return;
                const res = await fetchJSON(`/api/auth/users/${encodeURIComponent(username)}`, { method: "DELETE" });
                if (!res) alert("Delete failed (see console).");
            } else if (act === "deactivate" || act === "activate") {
                const res = await fetchJSON(`/api/auth/users/${encodeURIComponent(username)}`, {
                    method: "PUT",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({ active: act === "activate" }),
                });
                if (!res) alert("Status change failed.");
            } else if (act === "reset-password") {
                const pw = prompt(`New password for ${username} (min 8 chars):`);
                if (!pw || pw.length < 8) { alert("Cancelled or too short."); return; }
                const res = await fetchJSON(`/api/auth/users/${encodeURIComponent(username)}`, {
                    method: "PUT",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({ password: pw }),
                });
                if (!res) alert("Password reset failed.");
                else alert("Password reset.");
            }
        } finally {
            btn.disabled = false;
            refreshUsers();
        }
    });
}

// Create-user form.
const ucForm = document.getElementById("user-create-form");
if (ucForm) {
    ucForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("uc-username").value.trim();
        const password = document.getElementById("uc-password").value;
        const role = document.getElementById("uc-role").value;
        const fb = document.getElementById("uc-feedback");
        const submit = document.getElementById("uc-submit");
        submit.disabled = true;
        if (fb) fb.textContent = "creating...";
        const res = await fetchJSON("/api/auth/users", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ username, password, role }),
        });
        submit.disabled = false;
        if (res) {
            if (fb) fb.textContent = `created ${res.username} (${res.role})`;
            ucForm.reset();
            refreshUsers();
        } else {
            if (fb) fb.textContent = "failed - see console";
        }
    });
}

// Change-own-password form.
const pwForm = document.getElementById("pw-change-form");
if (pwForm) {
    pwForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const current = document.getElementById("pw-current").value;
        const next    = document.getElementById("pw-new").value;
        const fb = document.getElementById("pw-feedback");
        const submit = document.getElementById("pw-submit");
        submit.disabled = true;
        if (fb) fb.textContent = "changing...";
        const res = await fetchJSON("/api/auth/me/password", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ current_password: current, new_password: next }),
        });
        submit.disabled = false;
        if (res) {
            if (fb) fb.textContent = "password changed";
            pwForm.reset();
        } else {
            if (fb) fb.textContent = "failed - check current password";
        }
    });
}

// Topbar username + role + sign-out wiring (auth.js was already loaded by
// index.html before this script ran). Role pill mirrors current JWT role
// so the operator can tell at a glance which permissions they have.
const _topbarUser = document.getElementById("topbar-user");
if (_topbarUser) _topbarUser.textContent = LG_AUTH.user() || "admin";
const _topbarRole = document.getElementById("topbar-role");
if (_topbarRole) {
    const r = LG_AUTH.role() || "admin";
    _topbarRole.textContent = `role: ${r}`;
}
const _logout = document.getElementById("logout-btn");
if (_logout) _logout.addEventListener("click", () => LG_AUTH.logout());

// Role-aware UI: hide nav items + buttons the current user has no
// permission to use. Backend still enforces -- this is *cosmetic* so
// users don't see buttons they'd only get 403s on. Run synchronously
// before any data fetch so the user never sees a flash of disabled state.
(function applyRoleVisibility() {
    // Users tab (admin only).
    document.querySelectorAll('[data-role-required="admin"]').forEach(el => {
        el.hidden = !LG_AUTH.canManageUsers();
    });
    // Retrain buttons + consensus save button (model operators).
    if (!LG_AUTH.canManageModels()) {
        document.querySelectorAll('[data-retrain]').forEach(b => b.hidden = true);
        const saveCons = document.getElementById("save-consensus");
        if (saveCons) saveCons.hidden = true;
        // Disable consensus sliders so an auditor doesn't think they can
        // change them and lose the change on the next refresh.
        document.querySelectorAll('#view-consensus input[type="range"]').forEach(i => i.disabled = true);
        document.querySelectorAll('#view-consensus input[name="mode"]').forEach(i => i.disabled = true);
    }
    // Mining run + rule action buttons (rule operators).
    if (!LG_AUTH.canManageRules()) {
        const mineBtn = document.getElementById("mine-run");
        if (mineBtn) mineBtn.hidden = true;
        // Per-row buttons in the rules table are rendered dynamically;
        // renderRuleActions checks the same predicate.
    }
})();

refreshConsensusConfig();
tick();
setInterval(tick, REFRESH_MS);
