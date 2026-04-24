from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import json
import os
from threading import Lock

from .pipeline import LatentGuardPipeline

_PIPELINE: LatentGuardPipeline | None = None
_PIPELINE_LOCK = Lock()


def get_pipeline() -> LatentGuardPipeline:
    global _PIPELINE
    if _PIPELINE is None:
        with _PIPELINE_LOCK:
            if _PIPELINE is None:
                _PIPELINE = LatentGuardPipeline(data_path=os.getenv("LATENTGUARD_DATA_PATH", "./data"))
    return _PIPELINE


class LatentGuardHandler(BaseHTTPRequestHandler):
    @property
    def pipeline(self) -> LatentGuardPipeline:
        return get_pipeline()

    def _send(self, status: int, payload: dict | str, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        if isinstance(payload, str):
            self.wfile.write(payload.encode("utf-8"))
        else:
            self.wfile.write(json.dumps(payload).encode("utf-8"))

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/":
            html = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LatentGuard Console</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #0b1020;
      --card: #141b2d;
      --border: #2a3555;
      --fg: #e8ecf8;
      --muted: #a7b3d4;
      --ok: #28a745;
      --warn: #f39c12;
      --bad: #e74c3c;
      --btn: #3b82f6;
    }
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      margin: 0;
      padding: 20px;
      background: var(--bg);
      color: var(--fg);
    }
    h1, h2 { margin: 0 0 10px; }
    .sub { color: var(--muted); margin-bottom: 18px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 14px;
      align-items: start;
    }
    .card {
      border: 1px solid var(--border);
      background: var(--card);
      border-radius: 10px;
      padding: 12px;
    }
    .row { display: flex; gap: 8px; flex-wrap: wrap; margin: 8px 0; }
    input, select, textarea, button {
      font: inherit;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: #0f1628;
      color: var(--fg);
      padding: 8px 10px;
    }
    textarea { width: 100%; min-height: 120px; resize: vertical; }
    button {
      background: var(--btn);
      border: none;
      cursor: pointer;
      font-weight: 600;
    }
    button.secondary {
      background: transparent;
      border: 1px solid var(--border);
      font-weight: 500;
    }
    pre {
      margin: 8px 0 0;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      overflow: auto;
      max-height: 340px;
      background: #0f1628;
    }
    .tag {
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      display: inline-block;
    }
    .allow { background: rgba(40, 167, 69, 0.16); color: #7ee4a0; }
    .review { background: rgba(243, 156, 18, 0.17); color: #ffd087; }
    .block { background: rgba(231, 76, 60, 0.19); color: #ff9e97; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .status { margin-left: auto; color: var(--muted); font-size: 13px; }
  </style>
</head>
<body>
  <h1>LatentGuard Console</h1>
  <div class="sub">Interactively inspect traffic, tune consensus, manage rules, and monitor logs.</div>

  <div class="grid">
    <section class="card">
      <h2>System Overview</h2>
      <div class="row">
        <button id="refresh-dashboard">Refresh Dashboard</button>
        <button id="refresh-logs" class="secondary">Refresh Logs</button>
        <button id="refresh-rules" class="secondary">Refresh Rule Queue</button>
        <span id="status" class="status">Ready</span>
      </div>
      <div class="row">
        <strong>Last Decision:</strong>
        <span id="last-decision" class="tag review">N/A</span>
      </div>
      <pre id="dashboard-out">{}</pre>
    </section>

    <section class="card">
      <h2>Inspect Request</h2>
      <textarea id="inspect-input" class="mono">{
  "method": "GET",
  "path": "/search",
  "query": "q=hello",
  "headers": {"Host": "example.com"},
  "body": "",
  "source_ip": "198.51.100.42"
}</textarea>
      <div class="row">
        <button id="inspect-btn">Inspect</button>
      </div>
      <pre id="inspect-out">{}</pre>
    </section>

    <section class="card">
      <h2>Consensus Config</h2>
      <div class="row">
        <input id="weight-m4" type="number" step="0.01" placeholder="weight_m4" />
        <input id="weight-m5" type="number" step="0.01" placeholder="weight_m5" />
        <input id="weight-rules" type="number" step="0.01" placeholder="weight_rules" />
      </div>
      <div class="row">
        <input id="block-threshold" type="number" step="0.01" placeholder="block_threshold" />
        <input id="review-threshold" type="number" step="0.01" placeholder="review_threshold" />
      </div>
      <div class="row">
        <button id="load-config" class="secondary">Load Current</button>
        <button id="save-config">Save Config</button>
      </div>
      <pre id="config-out">{}</pre>
    </section>

    <section class="card">
      <h2>Safe Mode</h2>
      <div class="row">
        <select id="safe-mode-enabled">
          <option value="false">Disabled</option>
          <option value="true">Enabled</option>
        </select>
        <button id="set-safe-mode">Apply</button>
      </div>
      <pre id="safe-mode-out">{}</pre>
    </section>

    <section class="card">
      <h2>Logs</h2>
      <div class="row">
        <input id="logs-limit" type="number" value="25" min="1" />
        <select id="logs-action">
          <option value="">all actions</option>
          <option value="allow">allow</option>
          <option value="review">review</option>
          <option value="block">block</option>
        </select>
        <button id="fetch-logs">Fetch Logs</button>
      </div>
      <pre id="logs-out">{}</pre>
    </section>

    <section class="card">
      <h2>Rules</h2>
      <div class="row">
        <button id="generate-rules">Generate Rules</button>
      </div>
      <div class="row">
        <input id="rule-id" placeholder="rule_id" />
        <select id="rule-action">
          <option value="approve">approve</option>
          <option value="reject">reject</option>
          <option value="deploy">deploy</option>
        </select>
        <input id="rule-notes" placeholder="notes (optional)" />
        <button id="review-rule">Submit Review</button>
      </div>
      <pre id="rules-out">{}</pre>
    </section>
  </div>

  <script>
    const statusEl = document.getElementById("status");
    const lastDecisionEl = document.getElementById("last-decision");

    function setStatus(message) {
      statusEl.textContent = message;
    }

    function errorText(err) {
      if (err && typeof err === "object" && "message" in err) {
        return String(err.message);
      }
      return String(err);
    }

    function setJson(elId, obj) {
      document.getElementById(elId).textContent = JSON.stringify(obj, null, 2);
    }

    function parseJsonInput(elId) {
      try {
        return [JSON.parse(document.getElementById(elId).value), null];
      } catch (e) {
        return [null, String(e)];
      }
    }

    async function api(path, method = "GET", body) {
      setStatus(method + " " + path + " ...");
      const res = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined
      });
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
      if (!res.ok) {
        setStatus("Error: " + method + " " + path + " failed");
        throw new Error((data && data.error) || ("HTTP " + res.status));
      }
      setStatus("Done: " + method + " " + path);
      return data;
    }

    function setDecisionBadge(action) {
      lastDecisionEl.textContent = action || "N/A";
      lastDecisionEl.className = "tag " + (action || "review");
    }

    async function refreshDashboard() {
      const data = await api("/dashboard");
      setJson("dashboard-out", data);
      if (typeof data.safe_mode === "boolean") {
        document.getElementById("safe-mode-enabled").value = String(data.safe_mode);
      }
    }

    async function refreshLogs() {
      const rawLimit = Number(document.getElementById("logs-limit").value);
      const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.floor(rawLimit) : 25;
      const action = document.getElementById("logs-action").value;
      const qs = new URLSearchParams({ limit: String(limit) });
      if (action) qs.set("action", action);
      const data = await api("/logs?" + qs.toString());
      setJson("logs-out", data);
    }

    async function refreshRulesQueue() {
      const data = await api("/rules/queue");
      setJson("rules-out", data);
    }

    async function loadConfig() {
      const cfg = await api("/config");
      setJson("config-out", cfg);
      document.getElementById("weight-m4").value = cfg.weight_m4 ?? "";
      document.getElementById("weight-m5").value = cfg.weight_m5 ?? "";
      document.getElementById("weight-rules").value = cfg.weight_rules ?? "";
      document.getElementById("block-threshold").value = cfg.block_threshold ?? "";
      document.getElementById("review-threshold").value = cfg.review_threshold ?? "";
    }

    async function saveConfig() {
      const payload = {};
      const fields = [
        ["weight_m4", "weight-m4"],
        ["weight_m5", "weight-m5"],
        ["weight_rules", "weight-rules"],
        ["block_threshold", "block-threshold"],
        ["review_threshold", "review-threshold"]
      ];
      for (const [apiName, inputId] of fields) {
        const v = document.getElementById(inputId).value;
        if (v !== "") {
          const n = Number(v);
          if (!Number.isFinite(n)) {
            setJson("config-out", { error: "Invalid numeric value", field: apiName, value: v });
            return;
          }
          payload[apiName] = n;
        }
      }
      const out = await api("/config", "POST", payload);
      setJson("config-out", out);
      await refreshDashboard();
    }

    async function inspectRequest() {
      const [payload, parseErr] = parseJsonInput("inspect-input");
      if (parseErr) {
        setJson("inspect-out", { error: "Invalid JSON", details: parseErr });
        return;
      }
      const out = await api("/inspect", "POST", payload);
      setJson("inspect-out", out);
      setDecisionBadge(out?.decision?.action);
      await refreshDashboard();
      await refreshLogs();
    }

    async function setSafeMode() {
      const enabled = document.getElementById("safe-mode-enabled").value === "true";
      const out = await api("/safe-mode", "POST", { enabled });
      setJson("safe-mode-out", out);
      await refreshDashboard();
    }

    async function generateRules() {
      const out = await api("/rules/generate", "POST", {});
      setJson("rules-out", out);
      await refreshRulesQueue();
    }

    async function reviewRule() {
      const ruleId = document.getElementById("rule-id").value.trim();
      const action = document.getElementById("rule-action").value;
      const notes = document.getElementById("rule-notes").value;
      if (!ruleId) {
        setJson("rules-out", { error: "rule_id is required" });
        return;
      }
      const out = await api("/rules/review", "POST", { rule_id: ruleId, action, notes });
      setJson("rules-out", out);
      await refreshRulesQueue();
    }

    document.getElementById("refresh-dashboard").addEventListener("click", () => refreshDashboard().catch(e => setStatus(errorText(e))));
    document.getElementById("refresh-logs").addEventListener("click", () => refreshLogs().catch(e => setStatus(errorText(e))));
    document.getElementById("refresh-rules").addEventListener("click", () => refreshRulesQueue().catch(e => setStatus(errorText(e))));
    document.getElementById("inspect-btn").addEventListener("click", () => inspectRequest().catch(e => setStatus(errorText(e))));
    document.getElementById("load-config").addEventListener("click", () => loadConfig().catch(e => setStatus(errorText(e))));
    document.getElementById("save-config").addEventListener("click", () => saveConfig().catch(e => setStatus(errorText(e))));
    document.getElementById("set-safe-mode").addEventListener("click", () => setSafeMode().catch(e => setStatus(errorText(e))));
    document.getElementById("fetch-logs").addEventListener("click", () => refreshLogs().catch(e => setStatus(errorText(e))));
    document.getElementById("generate-rules").addEventListener("click", () => generateRules().catch(e => setStatus(errorText(e))));
    document.getElementById("review-rule").addEventListener("click", () => reviewRule().catch(e => setStatus(errorText(e))));

    Promise.all([refreshDashboard(), refreshLogs(), refreshRulesQueue(), loadConfig()]).catch(e => setStatus(errorText(e)));
  </script>
</body>
</html>
""".strip()
            return self._send(200, html, "text/html; charset=utf-8")

        if parsed.path == "/health":
            return self._send(200, {"status": "ok"})

        if parsed.path == "/dashboard":
            return self._send(200, self.pipeline.dashboard())

        if parsed.path == "/logs":
            q = parse_qs(parsed.query)
            try:
                limit = int(q.get("limit", ["100"])[0])
            except (TypeError, ValueError):
                return self._send(400, {"error": "invalid limit parameter"})
            action = q.get("action", [None])[0]
            return self._send(200, {"logs": self.pipeline.store.list_logs(limit=limit, action=action)})

        if parsed.path == "/config":
            return self._send(200, self.pipeline.dashboard().get("consensus", {}))

        if parsed.path == "/rules/queue":
            return self._send(200, {"rules": self.pipeline.store.list_rules(status="pending")})

        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/inspect":
            body = self._json_body()
            return self._send(200, self.pipeline.process_request(body))

        if parsed.path == "/config":
            body = self._json_body()
            return self._send(200, self.pipeline.set_consensus_config(body))

        if parsed.path == "/rules/generate":
            return self._send(200, self.pipeline.generate_rules())

        if parsed.path == "/rules/review":
            body = self._json_body()
            action = body.get("action", "reject")
            if action not in {"approve", "reject", "deploy"}:
                return self._send(400, {"error": "invalid review action"})
            result = self.pipeline.store.review_rule(
                rule_id=body.get("rule_id", ""),
                action=action,
                notes=body.get("notes", ""),
            )
            if not result:
                return self._send(404, {"error": "rule not found"})
            return self._send(200, result)

        if parsed.path == "/safe-mode":
            body = self._json_body()
            enabled = bool(body.get("enabled", False))
            self.pipeline.safe_mode = enabled
            return self._send(200, {"safe_mode": self.pipeline.safe_mode})

        self._send(404, {"error": "not found"})


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), LatentGuardHandler)
    print(f"LatentGuard running on http://{host}:{port}")
    server.serve_forever()
