"""Counts-only metrics for tapm serve (W1.1 / W1.4).

Feeds the platform-owner report with aggregate operational counts:
jobs total, queue depth, queue wait, runtime split across stages (plan, scanners,
engine, AI), cache hits, canary status, trigger counts, and component/model versions.
No customer, repository, or resource names are stored.
"""

from __future__ import annotations

import platform
import threading
from collections import Counter
from typing import Any

from .. import PROMPT_VERSION, SCHEMA_VERSION, __version__
from ..pytm_gen.generator import PYTM_VERSION


class MetricsCollector:
    """Thread-safe counts-only metrics collector."""

    def __init__(self, model: str | None = None, prompt_version: str = PROMPT_VERSION) -> None:
        self._lock = threading.Lock()
        self._jobs_total: int = 0
        self._jobs_by_status: Counter[str] = Counter()
        self._jobs_by_verdict: Counter[str] = Counter()
        self._jobs_by_level: Counter[str] = Counter()
        self._queue_wait_ms_total: int = 0
        self._queue_wait_ms_max: int = 0
        self._queue_wait_count: int = 0
        self._runtime_split: Counter[str] = Counter()
        self._cache_hits: int = 0
        self._canary_status: str = "pass"
        self._canary_runs_total: int = 0
        self._canary_runs_failed: int = 0
        self._triggers: Counter[str] = Counter()
        self._model: str | None = model
        self._prompt_version: str = prompt_version
        self._queue_depth_fn = lambda: 0

    def set_queue_depth_provider(self, fn) -> None:
        self._queue_depth_fn = fn

    def set_model(self, model: str | None) -> None:
        if model:
            with self._lock:
                self._model = model

    def record_trigger(self, trigger: str = "pr_change", count: int = 1) -> None:
        with self._lock:
            self._triggers[trigger] += count

    def record_job_enqueued(self, level: str | None = None, trigger: str | None = None) -> None:
        with self._lock:
            self._jobs_total += 1
            self._jobs_by_status["queued"] += 1
            if level:
                self._jobs_by_level[level] += 1
            if trigger:
                self._triggers[trigger] += 1

    def record_job_started(self, queue_wait_ms: int) -> None:
        with self._lock:
            if self._jobs_by_status["queued"] > 0:
                self._jobs_by_status["queued"] -= 1
            self._jobs_by_status["running"] += 1
            self._queue_wait_ms_total += queue_wait_ms
            if queue_wait_ms > self._queue_wait_ms_max:
                self._queue_wait_ms_max = queue_wait_ms
            self._queue_wait_count += 1

    def record_job_completed(
        self,
        verdict: str | None,
        timings_ms: dict[str, int],
        level: str | None = None,
    ) -> None:
        with self._lock:
            if self._jobs_by_status["running"] > 0:
                self._jobs_by_status["running"] -= 1
            self._jobs_by_status["completed"] += 1
            if verdict:
                self._jobs_by_verdict[verdict] += 1
            for stage, ms in timings_ms.items():
                self._runtime_split[stage] += ms

    def record_job_failed(self, level: str | None = None) -> None:
        with self._lock:
            if self._jobs_by_status["running"] > 0:
                self._jobs_by_status["running"] -= 1
            self._jobs_by_status["failed"] += 1

    def record_cache_hits(self, count: int = 1) -> None:
        with self._lock:
            self._cache_hits += count

    def set_canary_status(self, status: str) -> None:
        with self._lock:
            self._canary_status = status

    def record_canary_run(self, passed: bool) -> None:
        with self._lock:
            self._canary_runs_total += 1
            if not passed:
                self._canary_runs_failed += 1
                self._canary_status = "fail"
            else:
                self._canary_status = "pass"

    def get_metrics(self) -> dict[str, Any]:
        with self._lock:
            avg_wait = (
                round(self._queue_wait_ms_total / self._queue_wait_count, 1)
                if self._queue_wait_count > 0
                else 0.0
            )
            return {
                "jobs_total": self._jobs_total,
                "jobs_by_status": dict(self._jobs_by_status),
                "jobs_by_verdict": dict(self._jobs_by_verdict),
                "jobs_by_level": dict(self._jobs_by_level),
                "queue_depth": self._queue_depth_fn(),
                "queue_wait_ms_avg": avg_wait,
                "queue_wait_ms_max": self._queue_wait_ms_max,
                "runtime_split_ms": dict(self._runtime_split),
                "cache_hits": self._cache_hits,
                "canary_status": self._canary_status,
                "canaries_total": self._canary_runs_total,
                "canaries_failed": self._canary_runs_failed,
                "triggers": dict(self._triggers),
                "versions": {
                    "tapm": __version__,
                    "pytm": PYTM_VERSION,
                    "python": platform.python_version(),
                    "schema_version": SCHEMA_VERSION,
                    "prompt_version": self._prompt_version,
                    "model": self._model or "simulated",
                },
            }
