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
<!doctype html><html><head><title>LatentGuard MVP</title></head>
<body style='font-family: sans-serif; margin: 24px;'>
<h1>LatentGuard MVP Dashboard</h1>
<pre id='out'>Loading...</pre>
<script>
fetch('/dashboard').then(r=>r.json()).then(d=>{document.getElementById('out').textContent = JSON.stringify(d,null,2)});
</script>
</body></html>
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
    print(f"LatentGuard MVP running on http://{host}:{port}")
    server.serve_forever()
