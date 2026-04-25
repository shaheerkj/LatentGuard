from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
import json

from .contracts import RequestContext


class ReverseProxyInterceptor:
    """Captures incoming HTTP metadata and converts it to RequestContext."""

    @staticmethod
    def _normalize_headers(raw_headers: Any) -> dict[str, str]:
        if not isinstance(raw_headers, dict):
            return {}
        normalized: dict[str, str] = {}
        for key, value in raw_headers.items():
            if key is None:
                continue
            if isinstance(value, (list, tuple)):
                value = ",".join(str(v) for v in value)
            normalized[str(key)] = str(value)
        return normalized

    @staticmethod
    def _pick_source_ip(headers: dict[str, str], provided_ip: Any) -> str:
        for key in ("X-Forwarded-For", "x-forwarded-for"):
            if key in headers and headers[key].strip():
                forwarded = headers[key].split(",")[0].strip()
                if forwarded:
                    return forwarded
        return str(provided_ip or "0.0.0.0")

    def intercept(self, request_payload: dict[str, Any]) -> RequestContext:
        path = str(request_payload.get("path", "/") or "/")
        query = str(request_payload.get("query", "") or "")

        parsed = urlparse(path)
        if parsed.scheme or parsed.netloc:
            path = parsed.path or "/"
            if not query:
                query = parsed.query

        if not path.startswith("/"):
            path = "/" + path

        headers = self._normalize_headers(request_payload.get("headers", {}))
        body = request_payload.get("body", "")
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        else:
            body = str(body)

        return RequestContext(
            method=str(request_payload.get("method", "GET")).upper(),
            path=path,
            query=query,
            headers=headers,
            body=body,
            source_ip=self._pick_source_ip(headers, request_payload.get("source_ip")),
        )
