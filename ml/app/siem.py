"""SI-6 SIEM export: tail the audit log and forward events in ArcSight CEF.

CEF spec:
    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|[Extension]

We map LatentGuard audit rows like this:
    Vendor       = LatentGuard
    Product      = WAF
    Version      = service version (FastAPI app.version)
    SignatureID  = "block" | "allow"
    Name         = "HTTP request blocked" | "HTTP request allowed"
    Severity     = 7 for block, 3 for allow (CEF 0-10 scale)
    Extensions:
        src                source_ip
        request            path
        requestMethod      method
        cs1                ml_score
        cs1Label           ml_score
        cs2                rule_hits joined by ','
        cs2Label           rule_hits
        msg                first reason
        rt                 timestamp in ms since epoch (CEF convention)
        externalId         request_id

Transport:
    SYSLOG_HOST + SYSLOG_PORT (UDP) when set -- forwards each event
        as a syslog RFC 3164 line prefixed with the standard
        priority header.
    SIEM_LOG_PATH file fallback when set -- appends one CEF line
        per event for "syslog-able by anything else" deployments.
    Both can be enabled simultaneously; either is optional.

Polling:
    Every SIEM_INTERVAL_SECONDS (default 5) the worker pulls audit
    rows newer than the last seen timestamp + _id pair, in insert
    order, capped at SIEM_BATCH (default 200). State is in-memory:
    if the ML service restarts we resume from the timestamp at boot,
    so we never re-export old data, but we may MISS rows that
    landed during the brief outage. Tracked as a small known gap;
    a future iteration could persist the cursor in a tiny Mongo
    collection.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pymongo.errors import PyMongoError

from .db import requests_collection

logger = logging.getLogger("latentguard.ml.siem")


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


def _enabled() -> bool:
    return bool(_env("SYSLOG_HOST")) or bool(_env("SIEM_LOG_PATH"))


# Module-level state. Updated by the worker, read by /api/siem/status.
_state: dict[str, Any] = {
    "enabled": False,
    "syslog_host": "",
    "syslog_port": 514,
    "file_path": "",
    "running": False,
    "last_export_at": None,
    "last_cursor_ts": None,
    "events_total": 0,
    "errors_total": 0,
    "last_error": "",
}


def status() -> dict[str, Any]:
    out = dict(_state)
    out["enabled"] = _enabled()
    return out


def _escape_extension_value(s: str) -> str:
    # CEF extension values escape '|', '\\', '=', '\n', '\r' per spec.
    return (
        s.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "")
    )


def _format_cef(row: dict[str, Any], version: str) -> str:
    action = (row.get("final_action") or "?").lower()
    severity = "7" if action == "block" else "3"
    sig_id = action
    name = "HTTP request blocked" if action == "block" else "HTTP request allowed"
    rule_hits = row.get("rule_hits") or []
    reasons = row.get("reasons") or []
    msg = reasons[0] if reasons else ""

    ts = row.get("timestamp")
    rt = ""
    if hasattr(ts, "timestamp"):
        rt = str(int(ts.timestamp() * 1000))

    ext_pairs = [
        ("externalId", str(row.get("request_id", ""))),
        ("src", str(row.get("source_ip", ""))),
        ("request", str(row.get("path", ""))),
        ("requestMethod", str(row.get("method", "")).upper()),
        ("cs1", f"{float(row.get('ml_score') or 0.0):.4f}"),
        ("cs1Label", "ml_score"),
        ("cs2", ",".join(str(r) for r in rule_hits)),
        ("cs2Label", "rule_hits"),
        ("rt", rt),
        ("msg", msg),
    ]
    ext = " ".join(f"{k}={_escape_extension_value(v)}" for k, v in ext_pairs if v)
    header = f"CEF:0|LatentGuard|WAF|{version}|{sig_id}|{name}|{severity}"
    return f"{header}|{ext}"


def _syslog_priority(facility: int = 16, severity: int = 6) -> int:
    # facility=local0 (16), severity=informational (6) by default.
    return facility * 8 + severity


def _wrap_syslog(cef_line: str) -> str:
    """RFC 3164 wrapper: <PRI>TIMESTAMP HOST APP: MSG."""
    pri = _syslog_priority()
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    host = socket.gethostname()
    return f"<{pri}>{ts} {host} latentguard: {cef_line}"


class _UDPForwarder:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, line: str) -> None:
        self.sock.sendto(line.encode("utf-8"), (self.host, self.port))


class _FileForwarder:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Touch so /api/siem/status can stat() it even before first event.
        self.path.touch(exist_ok=True)

    def send(self, line: str) -> None:
        with self.path.open("a", encoding="utf-8") as fp:
            fp.write(line + "\n")


async def _worker(version: str) -> None:
    if not _enabled():
        return

    _state["enabled"] = True
    _state["syslog_host"] = _env("SYSLOG_HOST")
    _state["syslog_port"] = _env_int("SYSLOG_PORT", 514)
    _state["file_path"] = _env("SIEM_LOG_PATH")
    _state["running"] = True

    interval = _env_int("SIEM_INTERVAL_SECONDS", 5)
    batch = _env_int("SIEM_BATCH", 200)

    udp: _UDPForwarder | None = None
    if _state["syslog_host"]:
        try:
            udp = _UDPForwarder(_state["syslog_host"], int(_state["syslog_port"]))
            logger.info("siem: UDP forwarder -> %s:%s", udp.host, udp.port)
        except OSError as exc:
            logger.warning("siem: UDP init failed: %s", exc)

    fileFwd: _FileForwarder | None = None
    if _state["file_path"]:
        try:
            fileFwd = _FileForwarder(_state["file_path"])
            logger.info("siem: file forwarder -> %s", fileFwd.path)
        except OSError as exc:
            logger.warning("siem: file init failed: %s", exc)

    if udp is None and fileFwd is None:
        logger.warning("siem: no destinations configured, worker exiting")
        _state["running"] = False
        return

    # Start from "now": we don't backfill historic rows, only export new ones.
    cursor_ts = datetime.now(timezone.utc)
    _state["last_cursor_ts"] = cursor_ts.isoformat()

    while True:
        try:
            col = requests_collection()
            query = {"timestamp": {"$gt": cursor_ts}}
            rows = list(col.find(query).sort("timestamp", 1).limit(batch))
            for row in rows:
                cef = _format_cef(row, version)
                if udp is not None:
                    try:
                        udp.send(_wrap_syslog(cef))
                    except OSError as exc:
                        _state["errors_total"] += 1
                        _state["last_error"] = f"udp: {exc}"
                if fileFwd is not None:
                    try:
                        fileFwd.send(cef)
                    except OSError as exc:
                        _state["errors_total"] += 1
                        _state["last_error"] = f"file: {exc}"
                cursor_ts = row["timestamp"]
                _state["events_total"] += 1
            if rows:
                _state["last_export_at"] = datetime.now(timezone.utc).isoformat()
                _state["last_cursor_ts"] = cursor_ts.isoformat()
        except PyMongoError as exc:
            _state["errors_total"] += 1
            _state["last_error"] = f"mongo: {exc}"
            logger.warning("siem: mongo error: %s", exc)
        await asyncio.sleep(interval)


def start_in_background(loop: asyncio.AbstractEventLoop, version: str) -> None:
    if not _enabled():
        logger.info("siem: disabled (SYSLOG_HOST and SIEM_LOG_PATH both unset)")
        return
    loop.create_task(_worker(version))
    logger.info("siem: background worker scheduled")
