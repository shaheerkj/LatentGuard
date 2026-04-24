from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import json
import threading
from collections import deque
from typing import Any

from .contracts import RuleDraft


class AuditStore:
    def __init__(self, base_path: str) -> None:
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.logs_path = self.base_path / "logs.jsonl"
        self.rules_path = self.base_path / "rules.json"
        self._lock = threading.Lock()
        if not self.rules_path.exists():
            self.rules_path.write_text("[]", encoding="utf-8")

    def append_log(self, entry: dict[str, Any]) -> None:
        with self._lock:
            with self.logs_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def list_logs(self, limit: int = 100, action: str | None = None) -> list[dict[str, Any]]:
        if not self.logs_path.exists():
            return []

        if limit <= 0:
            return []

        rows: deque[dict[str, Any]] = deque(maxlen=limit)
        with self.logs_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if action and row.get("decision", {}).get("action") != action:
                    continue
                rows.append(row)

        return list(reversed(rows))

    def metrics(self) -> dict[str, Any]:
        if not self.logs_path.exists():
            return {
                "total_requests": 0,
                "blocked": 0,
                "allowed": 0,
                "review": 0,
                "block_rate": 0.0,
            }

        total = 0
        block = 0
        allow = 0
        review = 0
        with self.logs_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                action = row.get("decision", {}).get("action")
                if action == "block":
                    block += 1
                elif action == "allow":
                    allow += 1
                elif action == "review":
                    review += 1
        return {
            "total_requests": total,
            "blocked": block,
            "allowed": allow,
            "review": review,
            "block_rate": round((block / total), 4) if total else 0.0,
        }

    def _read_rules(self) -> list[dict[str, Any]]:
        try:
            return json.loads(self.rules_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _write_rules(self, rows: list[dict[str, Any]]) -> None:
        self.rules_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    def queue_rules(self, drafts: list[RuleDraft]) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._read_rules()
            for d in drafts:
                rows.append(asdict(d))
            self._write_rules(rows)
            return rows

    def list_rules(self, status: str | None = None) -> list[dict[str, Any]]:
        rows = self._read_rules()
        if status:
            rows = [r for r in rows if r.get("status") == status]
        return rows

    def review_rule(self, rule_id: str, action: str, notes: str = "") -> dict[str, Any] | None:
        with self._lock:
            if action not in {"approve", "reject", "deploy"}:
                return None
            rows = self._read_rules()
            target = None
            for r in rows:
                if r.get("rule_id") == rule_id:
                    if action == "approve":
                        r["status"] = "approved"
                    elif action == "deploy":
                        r["status"] = "deployed"
                    else:
                        r["status"] = "rejected"
                    r["reviewer_notes"] = notes
                    target = r
                    break
            self._write_rules(rows)
            return target
