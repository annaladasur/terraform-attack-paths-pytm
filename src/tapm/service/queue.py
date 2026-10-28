"""In-process job queue and worker pool for tapm serve (W1.1).

Coordinates deterministic pipeline execution, strict plan deletion, gate evaluation,
and asynchronous AI enrichment with structured logging.
"""

from __future__ import annotations

import datetime as dt
import json
import queue
import shutil
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from ..ai.enrich import enrich_artifacts
from ..gate import draft_exceptions, evaluate, load_exceptions, markdown
from ..pipeline import RunConfig, run
from ..util import dump_json
from .adapters import GitServerAdapter
from .logging import LogEvent, ServiceLogger
from .metrics import MetricsCollector
from .models import EnrichmentStatus, GateVerdict, Job, JobStatus


class JobQueue:
    """Thread-safe job queue and worker pool."""

    def __init__(
        self,
        data_dir: Path | str | None = None,
        workers: int = 2,
        default_llm: str = "simulated",
        default_jev: str = "local",
        default_model: str | None = None,
        logger: ServiceLogger | None = None,
        metrics: MetricsCollector | None = None,
        git_adapter: GitServerAdapter | None = None,
    ) -> None:
        self.data_dir = Path(data_dir) if data_dir else Path(tempfile.mkdtemp(prefix="tapm-serve-"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.workers = max(1, workers)
        self.default_llm = default_llm
        self.default_jev = default_jev
        self.default_model = default_model
        self.logger = logger or ServiceLogger()
        self.metrics = metrics or MetricsCollector(model=default_model)
        if default_model:
            self.metrics.set_model(default_model)
        self.git_adapter = git_adapter

        self._queue: queue.Queue[tuple[str, str]] = queue.Queue()  # (job_id, task_type)
        self.metrics.set_queue_depth_provider(self._queue.qsize)

        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._shutdown = threading.Event()
        self._worker_threads: list[threading.Thread] = []

        for i in range(self.workers):
            t = threading.Thread(target=self._worker_loop, name=f"tapm-worker-{i}", daemon=True)
            t.start()
            self._worker_threads.append(t)

    def shutdown(self, timeout: float = 5.0) -> None:
        self._shutdown.set()
        for _ in range(self.workers):
            self._queue.put(("", "stop"))
        for t in self._worker_threads:
            t.join(timeout=timeout)

    def get_job(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())

    def _resolve_git_adapter(self, job: Job) -> GitServerAdapter | None:
        """Resolve Git adapter for a job from job options, queue default, or environment."""
        if "git_adapter" in job.options and isinstance(job.options["git_adapter"], GitServerAdapter):
            return job.options["git_adapter"]
        if "git_server" in job.options:
            from .adapters import get_adapter

            return get_adapter(
                server_type=job.options["git_server"],
                base_url=job.options.get("git_base_url"),
                token=job.options.get("git_token"),
            )
        return self.git_adapter

    def _append_log(self, job: Job, event: LogEvent) -> None:
        with self._lock:
            job.logs.append(event.to_dict())
            if job.artifacts_dir and job.artifacts_dir.exists():
                try:
                    log_file = job.artifacts_dir / "service-log.jsonl"
                    with log_file.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(event.to_dict()) + "\n")
                except Exception:
                    pass

    def submit_job(self, req: dict[str, Any]) -> Job:
        """Enqueue a new analysis job from an API request."""
        plan_json = req.get("plan_json")
        if plan_json is None:
            raise ValueError("Missing required field 'plan_json'")

        repo = str(req.get("repo") or "unknown/repo")
        pr = req.get("pr", 0)
        sha = str(req.get("sha") or "head")
        root_module = str(req.get("root_module") or ".")
        level = str(req.get("level") or "observe")
        auto_enrich = bool(req.get("auto_enrich", True))

        job_id = f"job-{uuid.uuid4().hex[:12]}"
        now_iso = dt.datetime.now(dt.timezone.utc).isoformat()

        temp_dir = self.data_dir / "temp" / job_id
        temp_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir = self.data_dir / "artifacts" / job_id
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        temp_plan_path = temp_dir / "plan.json"
        if isinstance(plan_json, (dict, list)):
            dump_json(plan_json, temp_plan_path)
        elif isinstance(plan_json, str):
            temp_plan_path.write_text(plan_json, encoding="utf-8")
        else:
            raise ValueError(f"Invalid plan_json type: {type(plan_json)}")

        # Optional source files written to temp directory
        if "source_files" in req and isinstance(req["source_files"], dict):
            for fname, content in req["source_files"].items():
                fpath = temp_dir / fname
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(content, encoding="utf-8")

        # Optional exceptions file or YAML string
        if "exceptions_yaml" in req and req["exceptions_yaml"]:
            (temp_dir / "attack-path-exceptions.yaml").write_text(req["exceptions_yaml"], encoding="utf-8")
        elif "exceptions" in req and isinstance(req["exceptions"], list):
            import yaml

            (temp_dir / "attack-path-exceptions.yaml").write_text(
                yaml.safe_dump({"exceptions": req["exceptions"]}), encoding="utf-8"
            )

        # Optional threat answers file or YAML string
        if "threat_answers_yaml" in req and req["threat_answers_yaml"]:
            (temp_dir / "threat-answers.yaml").write_text(req["threat_answers_yaml"], encoding="utf-8")

        job = Job(
            id=job_id,
            repo=repo,
            pr=pr,
            sha=sha,
            root_module=root_module,
            level=level,
            status=JobStatus.QUEUED,
            created_at=now_iso,
            enqueued_at=time.time(),
            temp_dir=temp_dir,
            temp_plan_path=temp_plan_path,
            artifacts_dir=artifacts_dir,
            auto_enrich=auto_enrich,
            options=req,
        )

        with self._lock:
            self._jobs[job_id] = job

        trigger = req.get("trigger") or (
            "exceptions_only"
            if ("exceptions" in req or "exceptions_yaml" in req) and not req.get("has_tf_changes", True)
            else "pr_change"
        )
        self.metrics.record_job_enqueued(level=level, trigger=trigger)
        evt = self.logger.log_stage(job_id, "receive", "queued", repo=repo, pr=pr, sha=sha, level=level)
        self._append_log(job, evt)

        self._queue.put((job_id, "run"))
        return job

    def submit_enrichment(self, job_id: str) -> bool:
        """Trigger asynchronous AI enrichment for a completed job."""
        job = self.get_job(job_id)
        if not job:
            return False
        with self._lock:
            if job.enrichment_status in (EnrichmentStatus.RUNNING, EnrichmentStatus.COMPLETED):
                return True
            job.enrichment_status = EnrichmentStatus.QUEUED

        evt = self.logger.log_stage(job_id, "enrichment", "queued")
        self._append_log(job, evt)
        self._queue.put((job_id, "enrich"))
        return True

    def _worker_loop(self) -> None:
        while not self._shutdown.is_set():
            try:
                job_id, task_type = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if not job_id or task_type == "stop":
                self._queue.task_done()
                break

            job = self.get_job(job_id)
            if not job:
                self._queue.task_done()
                continue

            try:
                if task_type == "run":
                    self._execute_run(job)
                elif task_type == "enrich":
                    self._execute_enrich(job)
            except Exception as e:
                self.metrics.record_job_failed(level=job.level if job else None)
                with self._lock:
                    job.status = JobStatus.FAILED
                    job.error = str(e)
                evt = self.logger.log_stage(job.id, "job", "failed", error=str(e))
                self._append_log(job, evt)
            finally:
                self._queue.task_done()

    def _execute_run(self, job: Job) -> None:
        wait_ms = int((time.time() - job.enqueued_at) * 1000)
        self.metrics.record_job_started(wait_ms)

        with self._lock:
            job.status = JobStatus.RUNNING
            job.started_at = dt.datetime.now(dt.timezone.utc).isoformat()

        git_adapter = self._resolve_git_adapter(job)
        if git_adapter and job.sha and job.sha != "head" and job.options.get("post_git_status", True):
            try:
                git_adapter.post_status(
                    repo=job.repo,
                    sha=job.sha,
                    state="pending",
                    description="Attack path analysis in progress",
                )
                evt = self.logger.log_stage(job.id, "git_status", "posted", state="pending")
                self._append_log(job, evt)
            except Exception as e:
                evt = self.logger.log_stage(job.id, "git_status", "error", error=str(e))
                self._append_log(job, evt)

        # ---------------------------------------------------------------- deterministic stage
        t0 = time.monotonic()
        evt = self.logger.log_stage(job.id, "deterministic", "started")
        self._append_log(job, evt)

        tf_dir = job.temp_dir
        if job.options.get("tf_dir") and Path(job.options["tf_dir"]).exists():
            tf_dir = Path(job.options["tf_dir"])
        elif job.options.get("fixture"):
            from ..cli import resolve_fixture

            tf_dir = resolve_fixture(job.options["fixture"])

        answers_file = tf_dir / "threat-answers.yaml" if (tf_dir / "threat-answers.yaml").exists() else None
        if not answers_file and job.temp_dir and (job.temp_dir / "threat-answers.yaml").exists():
            answers_file = job.temp_dir / "threat-answers.yaml"

        cfg = RunConfig(
            tf_dir=tf_dir,
            plan_path=job.temp_plan_path,
            out_dir=job.artifacts_dir,
            name=f"{job.repo}-pr{job.pr}",
            render_dfd=bool(job.options.get("render_dfd", True)),
            sarif_uri_prefix=job.root_module,
            answers_file=answers_file,
            heuristic_sensitivity=bool(job.options.get("heuristic_sensitivity", False)),
            user_entries=bool(job.options.get("user_entries", False)),
        )

        res = run(cfg)
        det_ms = int((time.monotonic() - t0) * 1000)
        paths_count = len(res.paths)

        evt = self.logger.log_stage(
            job.id,
            "deterministic",
            "completed",
            latency_ms=det_ms,
            paths=paths_count,
            findings=len(res.findings),
        )
        self._append_log(job, evt)

        # ---------------------------------------------------------------- strict plan deletion
        t_del = time.monotonic()
        evt = self.logger.log_stage(job.id, "plan_deletion", "started")
        self._append_log(job, evt)

        # 1. Unlink uploaded plan file in temporary directory
        if job.temp_plan_path and job.temp_plan_path.exists():
            job.temp_plan_path.unlink()

        # 2. Unlink any plan copy written to artifacts directory
        art_plan = job.artifacts_dir / "terraform-plan.json"
        if art_plan.exists():
            art_plan.unlink()

        # 3. Clean up temporary working directory
        if job.temp_dir and job.temp_dir.exists():
            shutil.rmtree(job.temp_dir, ignore_errors=True)

        del_ms = int((time.monotonic() - t_del) * 1000)
        with self._lock:
            job.plan_deleted = True

        evt = self.logger.log_stage(job.id, "plan_deletion", "deleted", latency_ms=del_ms)
        self._append_log(job, evt)

        # ---------------------------------------------------------------- gate check stage
        t_gate = time.monotonic()
        evt = self.logger.log_stage(job.id, "gate", "started", level=job.level)
        self._append_log(job, evt)

        exc_entries: list[dict] = []
        file_problems: list[str] = []
        if "exceptions" in job.options and isinstance(job.options["exceptions"], list):
            exc_entries = job.options["exceptions"]
        elif "exceptions_yaml" in job.options and job.options["exceptions_yaml"]:
            import yaml

            try:
                doc = yaml.safe_load(job.options["exceptions_yaml"]) or {}
                exc_entries = doc.get("exceptions", [])
            except Exception as e:
                file_problems.append(f"Invalid exceptions YAML: {e}")

        g = evaluate(
            [p.to_json() for p in res.paths],
            exc_entries,
            level=job.level,
            fail_on=job.options.get("fail_on", "high"),
            file_problems=file_problems,
        )

        draft = draft_exceptions(g, [p.to_json() for p in res.paths]) if g.get("without_decision") else ""
        dump_json(g, job.artifacts_dir / "gate.json")
        (job.artifacts_dir / "gate.md").write_text(markdown(g, draft), encoding="utf-8")

        # Determine gate verdict: pass, would_block, or blocked
        if job.level in ("validate", "prevent") and g["decision"] == "fail":
            verdict = GateVerdict.BLOCKED
        elif g.get("without_decision", 0) > 0 and job.level == "recommend":
            verdict = GateVerdict.WOULD_BLOCK
        else:
            verdict = GateVerdict.PASS

        gate_ms = int((time.monotonic() - t_gate) * 1000)
        plan_ms = int(job.options.get("plan_ms", res.timings_ms.get("parse_plan", 0)))
        scanners_ms = int(job.options.get("scanners_ms", res.timings_ms.get("scanner_join", 0)))
        engine_ms = det_ms
        with self._lock:
            job.verdict = verdict
            job.paths_count = paths_count
            job.in_scope_count = g.get("in_scope", 0)
            job.accepted_count = g.get("accepted", 0)
            job.without_decision_count = g.get("without_decision", 0)
            job.timings_ms = {
                "plan": plan_ms,
                "scanners": scanners_ms,
                "engine": engine_ms,
                "deterministic": det_ms,
                "plan_deletion": del_ms,
                "gate": gate_ms,
            }

        evt = self.logger.log_stage(
            job.id,
            "gate",
            "evaluated",
            latency_ms=gate_ms,
            level=job.level,
            verdict=verdict,
            in_scope=job.in_scope_count,
            accepted=job.accepted_count,
            without_decision=job.without_decision_count,
        )
        self._append_log(job, evt)

        # ---------------------------------------------------------------- Git notifications
        if git_adapter:
            if job.sha and job.sha != "head" and job.options.get("post_git_status", True):
                try:
                    state, desc = git_adapter.map_verdict_to_status(verdict, job.level, paths_count)
                    git_adapter.post_status(
                        repo=job.repo,
                        sha=job.sha,
                        state=state,
                        description=desc,
                    )
                    evt = self.logger.log_stage(job.id, "git_status", "posted", state=state, description=desc)
                    self._append_log(job, evt)
                except Exception as e:
                    evt = self.logger.log_stage(job.id, "git_status", "error", error=str(e))
                    self._append_log(job, evt)

            if job.pr and job.options.get("post_git_comment", True):
                try:
                    gate_md = (job.artifacts_dir / "gate.md").read_text(encoding="utf-8") if (job.artifacts_dir / "gate.md").exists() else ""
                    report_md = (job.artifacts_dir / "report.md").read_text(encoding="utf-8") if (job.artifacts_dir / "report.md").exists() else ""
                    comment_body = f"{gate_md}\n\n{report_md}".strip()
                    res_c = git_adapter.post_comment(
                        repo=job.repo,
                        pr=job.pr,
                        body=comment_body,
                        update_existing=True,
                    )
                    evt = self.logger.log_stage(job.id, "git_comment", res_c.get("_action", "posted"))
                    self._append_log(job, evt)
                except Exception as e:
                    evt = self.logger.log_stage(job.id, "git_comment", "error", error=str(e))
                    self._append_log(job, evt)

        # ---------------------------------------------------------------- async AI enrichment
        if job.auto_enrich and paths_count > 0:
            self._execute_enrich(job)

        with self._lock:
            job.status = JobStatus.COMPLETED
            job.completed_at = dt.datetime.now(dt.timezone.utc).isoformat()

        if job.options.get("model"):
            self.metrics.set_model(job.options["model"])

        self.metrics.record_job_completed(job.verdict, job.timings_ms, level=job.level)

    def _execute_enrich(self, job: Job) -> None:
        with self._lock:
            job.enrichment_status = EnrichmentStatus.RUNNING

        t_enrich = time.monotonic()
        evt = self.logger.log_stage(job.id, "enrichment", "started")
        self._append_log(job, evt)

        ai_cfg = {
            "llm": job.options.get("llm", self.default_llm),
            "model": job.options.get("model", self.default_model),
            "jev": job.options.get("jev", self.default_jev),
            "max_paths": job.options.get("max_paths", 3),
            "cache": bool(job.options.get("cache", True)),
            "cache_dir": str(self.data_dir / "ai-cache"),
        }

        def on_role_event(event_data: dict[str, Any]) -> None:
            r_evt = self.logger.log_role(
                job.id,
                role=event_data["role"],
                status=event_data["status"],
                latency_ms=event_data.get("latency_ms"),
                model=event_data.get("model"),
                annotation_id=event_data.get("annotation_id"),
                from_cache=event_data.get("from_cache"),
            )
            self._append_log(job, r_evt)
            if event_data.get("from_cache"):
                self.metrics.record_cache_hits(1)

        enrich_doc = enrich_artifacts(
            job.artifacts_dir,
            cfg=ai_cfg,
            on_event=on_role_event,
        )

        enrich_ms = int((time.monotonic() - t_enrich) * 1000)
        s = enrich_doc.get("summary", {})
        with self._lock:
            job.enrichment_status = EnrichmentStatus.COMPLETED
            job.timings_ms["enrichment"] = enrich_ms
            job.timings_ms["ai"] = enrich_ms

        evt = self.logger.log_stage(
            job.id,
            "enrichment",
            "completed",
            latency_ms=enrich_ms,
            generated=s.get("generated", 0),
            accepted=s.get("accepted", 0),
            rejected=s.get("rejected", 0),
            human_review=s.get("human_review", 0),
        )
        self._append_log(job, evt)

        git_adapter = self._resolve_git_adapter(job)
        if git_adapter and job.pr and job.options.get("post_git_comment", True):
            try:
                gate_md = (job.artifacts_dir / "gate.md").read_text(encoding="utf-8") if (job.artifacts_dir / "gate.md").exists() else ""
                report_md = (job.artifacts_dir / "report.md").read_text(encoding="utf-8") if (job.artifacts_dir / "report.md").exists() else ""
                comment_body = f"{gate_md}\n\n{report_md}".strip()
                res_c = git_adapter.post_comment(
                    repo=job.repo,
                    pr=job.pr,
                    body=comment_body,
                    update_existing=True,
                )
                evt = self.logger.log_stage(job.id, "git_comment", res_c.get("_action", "updated"), enriched=True)
                self._append_log(job, evt)
            except Exception as e:
                evt = self.logger.log_stage(job.id, "git_comment", "error", error=str(e))
                self._append_log(job, evt)
