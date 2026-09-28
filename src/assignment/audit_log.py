"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"{user_id}-{len(self.logs)}-{len(self._open)}"
        self._open[req_id] = {
            "user_id": user_id,
            "text": text,
            "started_at": utc_now_iso(),
        }
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        req_id = request_id or f"{user_id}-{len(self.logs)}"
        started = self._open.get(req_id)
        latency_ms = 0.0
        if started:
            started_at = started.get("started_at")
            if started_at:
                try:
                    start_dt = datetime.fromisoformat(started_at)
                    latency_ms = max(0.0, (datetime.now(timezone.utc) - start_dt).total_seconds() * 1000)
                except ValueError:
                    latency_ms = 0.0
            self._open.pop(req_id, None)

        entry = {
            "request_id": req_id,
            "user_id": user_id,
            "text": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round(latency_ms, 2),
            "timestamp": utc_now_iso(),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path_str = filepath or default_audit_log_path()
        path = Path(path_str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
