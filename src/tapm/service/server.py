"""HTTP server for tapm serve (W1.1).

Implements the analysis service REST API:
- POST /v1/jobs                     Submit plan and start analysis
- GET  /v1/jobs/{id}                Get job status and gate verdict
- GET  /v1/jobs/{id}/artifacts/{n}  Get generated artifacts (never the plan)
- POST /v1/jobs/{id}/enrich         Trigger async AI enrichment
- GET  /v1/metrics                  Counts-only metrics
- GET  /v1/jobs/{id}/logs           Structured stage and role logs
- GET  /health                      Health check
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .adapters import GitServerAdapter
from .auth import TokenAuth
from .logging import ServiceLogger
from .metrics import MetricsCollector
from .queue import JobQueue

FORBIDDEN_ARTIFACT_NAMES = {
    "terraform-plan.json",
    "plan.json",
    "plan",
    "raw-plan.json",
}


class AnalysisRequestHandler(BaseHTTPRequestHandler):
    """Request handler implementing the analysis service REST endpoints."""

    server: AnalysisServer  # Type annotation for ThreadingHTTPServer subclass

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default unformatted HTTP access logs; logger handles structured logs."""
        pass

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _check_auth(self) -> bool:
        auth_header = self.headers.get("Authorization")
        if not self.server.auth.is_authorized(auth_header):
            self._send_error(401, "Unauthorized: missing or invalid Bearer token")
            return False
        return True

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Health check (unauthenticated)
        if path in ("/health", "/v1/health", ""):
            self._send_json(200, {"status": "ok", "service": "tapm-serve"})
            return

        # Metrics endpoint (counts only)
        if path == "/v1/metrics":
            if not self._check_auth():
                return
            self._send_json(200, self.server.metrics.get_metrics())
            return

        # List jobs
        if path == "/v1/jobs":
            if not self._check_auth():
                return
            jobs = [j.to_dict() for j in self.server.job_queue.list_jobs()]
            self._send_json(200, {"jobs": jobs})
            return

        # Job status: GET /v1/jobs/{id}
        m_job = re.fullmatch(r"/v1/jobs/([^/]+)", path)
        if m_job:
            if not self._check_auth():
                return
            job_id = m_job.group(1)
            job = self.server.job_queue.get_job(job_id)
            if not job:
                self._send_error(404, f"Job '{job_id}' not found")
                return
            self._send_json(200, job.to_dict())
            return

        # Job logs: GET /v1/jobs/{id}/logs
        m_logs = re.fullmatch(r"/v1/jobs/([^/]+)/logs", path)
        if m_logs:
            if not self._check_auth():
                return
            job_id = m_logs.group(1)
            job = self.server.job_queue.get_job(job_id)
            if not job:
                self._send_error(404, f"Job '{job_id}' not found")
                return
            self._send_json(200, {"job_id": job_id, "logs": job.logs})
            return

        # Artifacts: GET /v1/jobs/{id}/artifacts/{name}
        m_art = re.fullmatch(r"/v1/jobs/([^/]+)/artifacts/(.+)", path)
        if m_art:
            if not self._check_auth():
                return
            job_id = m_art.group(1)
            artifact_name = m_art.group(2)
            self._serve_artifact(job_id, artifact_name)
            return

        self._send_error(404, "Not found")

    def _serve_artifact(self, job_id: str, artifact_name: str) -> None:
        """Serve an artifact file, strictly preventing plan access and path traversal."""
        # 1. Path traversal check
        if ".." in artifact_name or artifact_name.startswith("/") or "\\" in artifact_name:
            self._send_error(400, "Invalid artifact name")
            return

        # 2. Strict refusal for plan files
        lower_name = artifact_name.lower()
        if lower_name in FORBIDDEN_ARTIFACT_NAMES or "plan" in lower_name and lower_name.endswith(".json"):
            self._send_error(403, "Forbidden: Terraform plans are deleted after analysis and are never served.")
            return

        job = self.server.job_queue.get_job(job_id)
        if not job or not job.artifacts_dir:
            self._send_error(404, f"Job '{job_id}' not found")
            return

        art_file = job.artifacts_dir / artifact_name
        if not art_file.exists() or not art_file.is_file():
            self._send_error(404, f"Artifact '{artifact_name}' not found for job '{job_id}'")
            return

        content = art_file.read_bytes()
        mime_type, _ = mimetypes.guess_type(str(art_file))
        if artifact_name.endswith(".sarif"):
            mime_type = "application/sarif+json"
        elif artifact_name.endswith(".md"):
            mime_type = "text/markdown; charset=utf-8"
        elif artifact_name.endswith(".dot"):
            mime_type = "text/vnd.graphviz"
        elif artifact_name.endswith(".puml"):
            mime_type = "text/plain"
        elif not mime_type:
            mime_type = "application/octet-stream"

        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Submit job: POST /v1/jobs
        if path == "/v1/jobs":
            if not self._check_auth():
                return
            self._handle_submit_job()
            return

        # Trigger enrichment: POST /v1/jobs/{id}/enrich
        m_enrich = re.fullmatch(r"/v1/jobs/([^/]+)/enrich", path)
        if m_enrich:
            if not self._check_auth():
                return
            job_id = m_enrich.group(1)
            job = self.server.job_queue.get_job(job_id)
            if not job:
                self._send_error(404, f"Job '{job_id}' not found")
                return
            ok = self.server.job_queue.submit_enrichment(job_id)
            if not ok:
                self._send_error(409, f"Job '{job_id}' cannot be enriched")
                return
            self._send_json(202, {"id": job_id, "enrichment_status": job.enrichment_status})
            return

        self._send_error(404, "Not found")

    def _handle_submit_job(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len == 0:
            self._send_error(400, "Empty request body")
            return

        raw_body = self.wfile.read(content_len) if hasattr(self, "wfile_read") else self.rfile.read(content_len)
        try:
            req_data = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            self._send_error(400, f"Malformed JSON: {e}")
            return

        if not isinstance(req_data, dict):
            self._send_error(400, "JSON body must be an object")
            return

        if "plan_json" not in req_data:
            self._send_error(400, "Missing required field 'plan_json'")
            return

        try:
            job = self.server.job_queue.submit_job(req_data)
        except Exception as e:
            self._send_error(400, f"Failed to submit job: {e}")
            return

        self._send_json(
            202,
            {
                "id": job.id,
                "job_id": job.id,
                "status": job.status,
                "repo": job.repo,
                "pr": job.pr,
                "sha": job.sha,
                "level": job.level,
                "created_at": job.created_at,
            },
        )


class AnalysisServer(ThreadingHTTPServer):
    """HTTP server hosting the analysis service."""

    def __init__(
        self,
        server_address: tuple[str, int],
        job_queue: JobQueue,
        auth: TokenAuth | None = None,
        metrics: MetricsCollector | None = None,
        logger: ServiceLogger | None = None,
    ) -> None:
        super().__init__(server_address, AnalysisRequestHandler)
        self.job_queue = job_queue
        self.auth = auth or TokenAuth()
        self.metrics = metrics or job_queue.metrics
        self.logger = logger or job_queue.logger


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    token: str | None = None,
    data_dir: Path | str | None = None,
    workers: int = 2,
    default_llm: str = "simulated",
    default_jev: str = "local",
    default_model: str | None = None,
    log_format: str = "text",
    git_adapter: GitServerAdapter | None = None,
) -> AnalysisServer:
    """Create a configured AnalysisServer instance."""
    logger = ServiceLogger(log_format=log_format)
    metrics = MetricsCollector(model=default_model)
    auth = TokenAuth(token)
    job_queue = JobQueue(
        data_dir=data_dir,
        workers=workers,
        default_llm=default_llm,
        default_jev=default_jev,
        default_model=default_model,
        logger=logger,
        metrics=metrics,
        git_adapter=git_adapter,
    )
    return AnalysisServer((host, port), job_queue=job_queue, auth=auth, metrics=metrics, logger=logger)
