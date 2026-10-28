"""Data models for tapm serve (W1.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class JobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class GateVerdict:
    PASS = "pass"
    WOULD_BLOCK = "would_block"
    BLOCKED = "blocked"


class EnrichmentStatus:
    NONE = "none"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Job:
    id: str
    repo: str
    pr: int | str
    sha: str
    root_module: str
    level: str
    status: str = JobStatus.QUEUED
    verdict: str | None = None
    created_at: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    enqueued_at: float = 0.0
    temp_dir: Path | None = None
    temp_plan_path: Path | None = None
    artifacts_dir: Path | None = None
    plan_deleted: bool = False
    paths_count: int = 0
    in_scope_count: int = 0
    accepted_count: int = 0
    without_decision_count: int = 0
    timings_ms: dict[str, int] = field(default_factory=dict)
    enrichment_status: str = EnrichmentStatus.NONE
    auto_enrich: bool = True
    error: str | None = None
    logs: list[dict[str, Any]] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """External representation for GET /v1/jobs/{id}."""
        data = {
            "id": self.id,
            "job_id": self.id,
            "status": self.status,
            "verdict": self.verdict,
            "gate_verdict": self.verdict,
            "repo": self.repo,
            "pr": self.pr,
            "sha": self.sha,
            "root_module": self.root_module,
            "level": self.level,
            "paths_count": self.paths_count,
            "in_scope_count": self.in_scope_count,
            "accepted_count": self.accepted_count,
            "without_decision_count": self.without_decision_count,
            "timings_ms": self.timings_ms,
            "plan_deleted": self.plan_deleted,
            "enrichment_status": self.enrichment_status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }
        if self.artifacts_dir and self.artifacts_dir.exists():
            data["artifacts"] = sorted(
                [f.name for f in self.artifacts_dir.iterdir() if f.is_file() and not f.name.endswith(".tmp")]
            )
        return data

