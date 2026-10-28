"""Structured logging for tapm serve (W1.1).

Emits one structured log line per pipeline stage and per agent role (beat 5).
Supports JSON lines and human-readable text output for live terminal demonstrations.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any, TextIO


@dataclass
class LogEvent:
    timestamp: str
    job_id: str
    kind: str  # "stage" | "role"
    name: str  # stage name (e.g. "deterministic", "plan_deletion") or role name (e.g. "path_narrator")
    status: str  # "started", "completed", "accepted", "held", "rejected", "deleted", etc.
    latency_ms: int | None = None
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "timestamp": self.timestamp,
            "job_id": self.job_id,
            "kind": self.kind,
            "name": self.name,
            "status": self.status,
        }
        if self.latency_ms is not None:
            d["latency_ms"] = self.latency_ms
        if self.details:
            d.update(self.details)
        return d

    def format_text(self) -> str:
        """Formatted single-line log for beat 5 live demo display."""
        ts = self.timestamp.split(".")[0] + "Z" if "." in self.timestamp else self.timestamp
        parts = [f"[{ts}]", f"job={self.job_id}"]
        if self.kind == "stage":
            parts.append(f"stage={self.name}")
            parts.append(f"status={self.status}")
            if self.latency_ms is not None:
                parts.append(f"duration_ms={self.latency_ms}")
        elif self.kind == "role":
            parts.append(f"role={self.name}")
            parts.append(f"status={self.status}")
            if self.latency_ms is not None:
                parts.append(f"latency_ms={self.latency_ms}")
        else:
            parts.append(f"event={self.name}")
            parts.append(f"status={self.status}")

        if self.details:
            for k, v in sorted(self.details.items()):
                if k not in ("timestamp", "job_id", "kind", "name", "status", "latency_ms") and v is not None:
                    parts.append(f"{k}={v}")
        return " ".join(parts)


class ServiceLogger:
    """Central logger that formats and dispatches log events."""

    def __init__(self, stream: TextIO | None = None, log_format: str = "text") -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.log_format = log_format  # "text" | "json"

    def _now(self) -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat()

    def emit(self, event: LogEvent) -> None:
        if self.stream:
            if self.log_format == "json":
                line = json.dumps(event.to_dict())
            else:
                line = event.format_text()
            print(line, file=self.stream, flush=True)

    def log_stage(
        self,
        job_id: str,
        stage: str,
        status: str,
        latency_ms: int | None = None,
        **details: Any,
    ) -> LogEvent:
        event = LogEvent(
            timestamp=self._now(),
            job_id=job_id,
            kind="stage",
            name=stage,
            status=status,
            latency_ms=latency_ms,
            details=details or None,
        )
        self.emit(event)
        return event

    def log_role(
        self,
        job_id: str,
        role: str,
        status: str,
        latency_ms: int | None = None,
        model: str | None = None,
        annotation_id: str | None = None,
        **details: Any,
    ) -> LogEvent:
        det = dict(details)
        if model:
            det["model"] = model
        if annotation_id:
            det["annotation"] = annotation_id
        event = LogEvent(
            timestamp=self._now(),
            job_id=job_id,
            kind="role",
            name=role,
            status=status,
            latency_ms=latency_ms,
            details=det or None,
        )
        self.emit(event)
        return event
