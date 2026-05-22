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
        review:  document.getElementById("kpi-review"),
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

async function fetchJSONFrom(base, path, init) {
    try {
        const res = await fetch(`${base}${path}`, init);
        if (!res.ok) {
            const detail = await res.text();
            throw new Error(`HTTP ${res.status}: ${detail.slice(0, 120)}`);
        }
        return await res.json();
    } catch (err) {
        console.warn("fetch failed", `${base}${path}`, err);
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

async function refreshMetrics() {
    const m = await fetchJSON("/api/metrics");
    if (!m) return;
    els.kpi.total.textContent   = fmt(m.total_requests);
    els.kpi.blocked.textContent = fmt(m.blocked);
    els.kpi.review.textContent  = fmt(m.review);
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
            datasets: [data("allow", "#10B981"), data("review", "#F59E0B"), data("block", "#EF4444")],
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

    els.drawer.body.innerHTML = `
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
}

async function refreshRules() {
    const rows = await fetchJSON("/api/rules");
    if (!rows) return;
    if (rows.length === 0) {
        els.rulesBody.innerHTML = `<tr><td colspan="5" class="empty">No drafts yet - run pattern mining to populate this queue.</td></tr>`;
        return;
    }
    els.rulesBody.innerHTML = rows.map(r => `
        <tr>
            <td>${r.rule_id}</td>
            <td>${truncate(r.pattern || "-", 50)}</td>
            <td>${fmt3(r.confidence ?? 0)}</td>
            <td><span class="action-tag action-${r.status === 'approved' ? 'allow' : r.status === 'rejected' ? 'block' : 'review'}">${r.status || "pending"}</span></td>
            <td>${r.created_at ? formatTime(r.created_at) : "-"}</td>
        </tr>`).join("");
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

async function tick() {
    await Promise.all([
        refreshHealth(), refreshMetrics(), refreshTraffic(), refreshLogs(), refreshRules(),
        refreshModels(), refreshDecisions(), refreshThreatIntel(),
    ]);
}

refreshConsensusConfig();
tick();
setInterval(tick, REFRESH_MS);
