// LatentGuard operator console — Phase 1 skeleton.
// All data is fetched from the FastAPI ML service (CORS-enabled).

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
};

let trafficChart = null;

function fmt(n) {
    if (n == null) return "—";
    return new Intl.NumberFormat().format(n);
}

function pct(x) {
    if (x == null) return "—";
    return (x * 100).toFixed(2) + "%";
}

function setActiveRoute(route) {
    els.routes.forEach(a => a.classList.toggle("active", a.dataset.route === route));
    els.views.forEach(v => v.classList.toggle("view--active", v.id === `view-${route}`));
}

els.routes.forEach(a => a.addEventListener("click", () => setActiveRoute(a.dataset.route)));
els.logFilter.addEventListener("change", refreshLogs);

async function fetchJSON(path) {
    try {
        const res = await fetch(`${API_BASE}${path}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
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
            datasets: [
                data("allow",  "#10B981"),
                data("review", "#F59E0B"),
                data("block",  "#EF4444"),
            ],
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
    for (const k of Object.keys(series)) {
        for (const p of series[k]) set.add(p.t);
    }
    return [...set].sort();
}

function formatTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
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
            <td>${r.source_ip ?? "—"}</td>
            <td>${r.method}</td>
            <td>${truncate(r.path, 60)}</td>
            <td><span class="action-tag action-${r.final_action}">${r.final_action}</span></td>
            <td>${(r.ml_score ?? 0).toFixed(3)}</td>
            <td>${(r.rule_hits || []).join(", ") || "—"}</td>
            <td>${r.latency_ms} ms</td>
        </tr>
    `).join("");
}

async function refreshRules() {
    const rows = await fetchJSON("/api/rules");
    if (!rows) return;
    if (rows.length === 0) {
        els.rulesBody.innerHTML = `<tr><td colspan="5" class="empty">No drafts yet — run pattern mining to populate this queue.</td></tr>`;
        return;
    }
    els.rulesBody.innerHTML = rows.map(r => `
        <tr>
            <td>${r.rule_id}</td>
            <td>${truncate(r.pattern || "—", 50)}</td>
            <td>${(r.confidence ?? 0).toFixed(3)}</td>
            <td><span class="action-tag action-${r.status === 'approved' ? 'allow' : r.status === 'rejected' ? 'block' : 'review'}">${r.status || "pending"}</span></td>
            <td>${r.created_at ? formatTime(r.created_at) : "—"}</td>
        </tr>
    `).join("");
}

function truncate(s, n) {
    if (!s) return "—";
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

async function tick() {
    await Promise.all([refreshHealth(), refreshMetrics(), refreshTraffic(), refreshLogs(), refreshRules()]);
}

tick();
setInterval(tick, REFRESH_MS);
