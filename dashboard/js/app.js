// LatentGuard operator console - Phase A wiring (M3 anomaly cards + M6 consensus).
// All data flows through the FastAPI ML service (CORS-enabled).

const API_BASE = window.LATENTGUARD_API || "http://localhost:8000";
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
    logFilter:  document.getElementById("log-filter"),
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
els.logFilter.addEventListener("change", refreshLogs);

async function fetchJSON(path, init) {
    try {
        const res = await fetch(`${API_BASE}${path}`, init);
        if (!res.ok) {
            const detail = await res.text();
            throw new Error(`HTTP ${res.status}: ${detail.slice(0, 120)}`);
        }
        return await res.json();
    } catch (err) {
        console.warn("fetch failed", path, err);
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
        els.safePill.textContent = "ML: unreachable";
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

async function refreshLogs() {
    const action = els.logFilter.value;
    const path = action ? `/api/logs?action=${action}&limit=100` : "/api/logs?limit=100";
    const rows = await fetchJSON(path);
    if (!rows) return;
    if (rows.length === 0) {
        els.logBody.innerHTML = `<tr><td colspan="8" class="empty">No matching requests yet.</td></tr>`;
        return;
    }
    els.logBody.innerHTML = rows.map(r => `
        <tr>
            <td>${formatTime(r.timestamp)}</td>
            <td>${r.source_ip ?? "-"}</td>
            <td>${r.method}</td>
            <td>${truncate(r.path, 60)}</td>
            <td><span class="action-tag action-${r.final_action}">${r.final_action}</span></td>
            <td>${fmt3(r.ml_score ?? 0)}</td>
            <td>${(r.rule_hits || []).join(", ") || "-"}</td>
            <td>${r.latency_ms} ms</td>
        </tr>`).join("");
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
    const rows = await fetchJSON("/api/logs?limit=20");
    if (!rows) return;
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

async function tick() {
    await Promise.all([
        refreshHealth(), refreshMetrics(), refreshTraffic(), refreshLogs(), refreshRules(),
        refreshModels(), refreshDecisions(),
    ]);
}

refreshConsensusConfig();
tick();
setInterval(tick, REFRESH_MS);
