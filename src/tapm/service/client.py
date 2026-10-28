"""Runner client for submitting plans to tapm serve (W1.3).

Submits plans to the analysis service, polls for completion, optionally
downloads artifacts, and exits according to the adoption level:
- observe: never fails (exit 0 always, even on timeout, service error, or unaccepted paths)
- recommend: as observe, reports paths that would block, never fails (exit 0)
- validate: blocks (exit 3) if paths at/above threshold lack decision; fails closed (exit 1) on timeout/error
- prevent: blocks (exit 3) if paths at/above threshold lack decision; fails closed (exit 1) on timeout/error
- timeout passes at observe and recommend (fail-open)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Signature for custom HTTP transports: (method, url, headers, body_bytes) -> (status_code, response_data)
HttpTransport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, Any]]

DEFAULT_SERVER_URL = "http://127.0.0.1:8080"
BLOCKING_LEVELS = {"validate", "prevent"}
STANDARD_ARTIFACTS = (
    "gate.md",
    "gate.json",
    "report.md",
    "attack-paths.json",
    "evidence.json",
    "attack-paths.sarif",
    "story.md",
)


class ClientError(Exception):
    """Base error for analysis client operations."""

    def __init__(self, message: str, status_code: int | None = None, response_body: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class ClientTimeoutError(ClientError):
    """Raised when job polling times out."""
    pass


class ClientConnectionError(ClientError):
    """Raised when connection to analysis service fails."""
    pass


@dataclass
class SubmitResult:
    """Result of submitting and polling a job via tapm submit."""

    job_id: str | None
    level: str
    status: str  # completed, failed, timeout, error
    verdict: str | None  # pass, would_block, blocked, or None
    exit_code: int
    error: str | None = None
    timed_out: bool = False
    failed_open: bool = False
    job_data: dict[str, Any] = field(default_factory=dict)
    artifacts_downloaded: list[str] = field(default_factory=list)
    paths_count: int = 0
    in_scope_count: int = 0
    accepted_count: int = 0
    without_decision_count: int = 0

    @property
    def passed(self) -> bool:
        return self.exit_code == 0

    @property
    def blocked(self) -> bool:
        return self.exit_code == 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "level": self.level,
            "status": self.status,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "error": self.error,
            "timed_out": self.timed_out,
            "failed_open": self.failed_open,
            "paths_count": self.paths_count,
            "in_scope_count": self.in_scope_count,
            "accepted_count": self.accepted_count,
            "without_decision_count": self.without_decision_count,
            "artifacts_downloaded": self.artifacts_downloaded,
            "job_data": self.job_data,
        }


def compute_exit_code(
    level: str,
    verdict: str | None,
    status: str,
    timed_out: bool = False,
    is_error: bool = False,
) -> tuple[int, bool]:
    """Compute (exit_code, failed_open) given level and run outcome.

    Policy:
    - observe: never fails (exit 0). Fails open on timeout, server error, or blocked verdict.
    - recommend: never fails (exit 0). Fails open on timeout, server error, or blocked verdict.
    - validate: blocking level.
        - pass: exit 0
        - blocked: exit 3
        - would_block: exit 0 (only blocks at validate if actual verdict is blocked)
        - timeout: exit 1 (fails closed)
        - error / failed: exit 1 (fails closed)
    - prevent: blocking level.
        - pass: exit 0
        - blocked: exit 3
        - timeout: exit 1 (fails closed)
        - error / failed: exit 1 (fails closed)
    """
    is_blocking = level in BLOCKING_LEVELS

    if timed_out:
        if not is_blocking:
            # Timeout passes at observe and recommend
            return 0, True
        return 1, False

    if is_error or status == "failed":
        if not is_blocking:
            # Fail-open at observe and recommend
            return 0, True
        return 1, False

    if status == "completed":
        if verdict == "blocked":
            if is_blocking:
                return 3, False
            # observe / recommend never fail
            return 0, False
        if verdict in ("pass", "would_block"):
            return 0, False
        return 0, False

    # Fallback for unknown status
    if is_blocking:
        return 1, False
    return 0, True


def detect_git_context() -> tuple[str, int | str, str]:
    """Detect repo, PR/MR number, and commit SHA from CI environment variables or git."""
    repo = (
        os.environ.get("GITHUB_REPOSITORY")
        or os.environ.get("GITEA_REPO")
        or os.environ.get("CI_PROJECT_PATH")
    )
    if not repo:
        try:
            rem = subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                stderr=subprocess.DEVNULL,
                timeout=1.0,
                text=True,
            ).strip()
            # Parse git remote e.g. git@github.com:owner/repo.git or https://host/owner/repo.git
            m = re.search(r"[:/]([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+?)(?:\.git)?$", rem)
            if m:
                repo = m.group(1)
        except Exception:
            pass
    repo = repo or "unknown/repo"

    pr: int | str = 0
    # PR number heuristics
    pr_env = (
        os.environ.get("PULL_NUMBER")
        or os.environ.get("PR_NUMBER")
        or os.environ.get("CI_MERGE_REQUEST_IID")
    )
    if pr_env and pr_env.isdigit():
        pr = int(pr_env)
    elif os.environ.get("GITHUB_REF"):
        ref = os.environ["GITHUB_REF"]
        m = re.match(r"refs/pull/(\d+)", ref)
        if m:
            pr = int(m.group(1))

    sha = (
        os.environ.get("GITHUB_SHA")
        or os.environ.get("CI_COMMIT_SHA")
        or os.environ.get("GITEA_COMMIT_SHA")
    )
    if not sha:
        try:
            sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL,
                timeout=1.0,
                text=True,
            ).strip()
        except Exception:
            pass
    sha = sha or "head"

    return repo, pr, sha


class SubmitClient:
    """Client for posting plans to tapm serve and polling results."""

    def __init__(
        self,
        server_url: str | None = None,
        token: str | None = None,
        transport: HttpTransport | None = None,
        timeout: float = 60.0,
        poll_interval: float = 0.5,
    ) -> None:
        raw_url = server_url or os.environ.get("TAPM_SERVER_URL") or DEFAULT_SERVER_URL
        self.server_url = raw_url.rstrip("/")
        self.token = token if token is not None else os.environ.get("TAPM_SERVER_TOKEN")
        self.transport = transport
        self.timeout = float(timeout)
        self.poll_interval = float(poll_interval)

    def _auth_headers(self) -> dict[str, str]:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _http_request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, Any]:
        """Send an HTTP request via the injected transport or urllib."""
        req_timeout = timeout if timeout is not None else self.timeout
        path_clean = path if path.startswith("/") else f"/{path}"
        url = f"{self.server_url}{path_clean}"

        req_headers = {"User-Agent": "tapm-submit/0.1.0"}
        req_headers.update(self._auth_headers())
        if headers:
            req_headers.update(headers)

        body_bytes = None
        if data is not None:
            body_bytes = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        if self.transport:
            return self.transport(method, url, req_headers, body_bytes)

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=req_timeout) as resp:
                status_code = resp.status
                raw = resp.read()
                content_type = resp.headers.get("Content-Type", "")
                if "json" in content_type:
                    try:
                        return status_code, json.loads(raw.decode("utf-8"))
                    except Exception:
                        return status_code, raw
                return status_code, raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            parsed: Any = raw
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                pass
            return e.code, parsed
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ClientConnectionError(f"Connection to analysis service failed: {e}") from e

    def submit_job(self, req_data: dict[str, Any]) -> dict[str, Any]:
        """POST /v1/jobs with plan and metadata."""
        status_code, body = self._http_request("POST", "/v1/jobs", data=req_data)
        if status_code not in (200, 201, 202):
            msg = body.get("error") if isinstance(body, dict) else str(body)
            raise ClientError(f"Failed to submit job (HTTP {status_code}): {msg}", status_code, body)
        if not isinstance(body, dict) or "id" not in body:
            raise ClientError(f"Malformed submit response: {body}", status_code, body)
        return body

    def get_job(self, job_id: str) -> dict[str, Any]:
        """GET /v1/jobs/{id}."""
        status_code, body = self._http_request("GET", f"/v1/jobs/{job_id}")
        if status_code != 200:
            msg = body.get("error") if isinstance(body, dict) else str(body)
            raise ClientError(f"Failed to fetch job {job_id} (HTTP {status_code}): {msg}", status_code, body)
        if not isinstance(body, dict):
            raise ClientError(f"Malformed job response for {job_id}: {body}", status_code, body)
        return body

    def poll_job(
        self,
        job_id: str,
        timeout: float | None = None,
        poll_interval: float | None = None,
    ) -> dict[str, Any]:
        """Poll GET /v1/jobs/{id} until status is completed or failed, or timeout."""
        limit = timeout if timeout is not None else self.timeout
        interval = poll_interval if poll_interval is not None else self.poll_interval
        deadline = time.monotonic() + limit

        while True:
            job_data = self.get_job(job_id)
            status = job_data.get("status")
            if status in ("completed", "failed"):
                return job_data

            if time.monotonic() >= deadline:
                raise ClientTimeoutError(
                    f"Timed out after {limit:.1f}s waiting for job {job_id} to complete",
                    response_body=job_data,
                )

            time.sleep(interval)

    def get_metrics(self) -> dict[str, Any]:
        """GET /v1/metrics: returns counts-only service metrics (W1.4)."""
        status_code, body = self._http_request("GET", "/v1/metrics")
        if status_code != 200:
            msg = body.get("error") if isinstance(body, dict) else str(body)
            raise ClientError(f"Failed to fetch metrics (HTTP {status_code}): {msg}", status_code, body)
        if not isinstance(body, dict):
            raise ClientError(f"Malformed metrics response: {body}", status_code, body)
        return body

    def download_artifact(self, job_id: str, artifact_name: str, dest_dir_or_file: Path | str) -> Path | None:
        """Download a single artifact via GET /v1/jobs/{id}/artifacts/{name}."""
        status_code, raw = self._http_request("GET", f"/v1/jobs/{job_id}/artifacts/{artifact_name}")
        if status_code != 200:
            return None

        target = Path(dest_dir_or_file)
        if target.is_dir() or not target.suffix:
            target.mkdir(parents=True, exist_ok=True)
            out_path = target / artifact_name
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            out_path = target

        if isinstance(raw, str):
            out_path.write_text(raw, encoding="utf-8")
        elif isinstance(raw, bytes):
            out_path.write_bytes(raw)
        elif isinstance(raw, (dict, list)):
            out_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        return out_path

    def download_artifacts(
        self,
        job_id: str,
        dest_dir: Path | str,
        artifact_names: list[str] | tuple[str, ...] | None = None,
    ) -> list[str]:
        """Download artifacts to destination directory."""
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        names = artifact_names or STANDARD_ARTIFACTS
        downloaded = []
        for name in names:
            saved = self.download_artifact(job_id, name, dest)
            if saved is not None:
                downloaded.append(name)
        return downloaded

    def run(
        self,
        plan: str | dict | Path,
        repo: str | None = None,
        pr: int | str | None = None,
        sha: str | None = None,
        root_module: str = ".",
        level: str = "observe",
        fail_on: str = "high",
        timeout: float | None = None,
        poll_interval: float | None = None,
        auto_enrich: bool = True,
        exceptions_yaml: str | None = None,
        threat_answers_yaml: str | None = None,
        out_dir: Path | str | None = None,
        **options: Any,
    ) -> SubmitResult:
        """Submit a plan, poll for completion, download artifacts, and apply level exit policy."""
        # Detect git context if not provided
        d_repo, d_pr, d_sha = detect_git_context()
        final_repo = repo or d_repo
        final_pr = pr if pr is not None else d_pr
        final_sha = sha or d_sha

        # Read plan content
        plan_content: Any
        if isinstance(plan, (dict, list)):
            plan_content = plan
        elif isinstance(plan, Path) or (isinstance(plan, str) and (Path(plan).exists() or "\n" not in plan)):
            p = Path(plan)
            if not p.exists():
                exit_code, failed_open = compute_exit_code(level, None, "failed", is_error=True)
                return SubmitResult(
                    job_id=None,
                    level=level,
                    status="error",
                    verdict=None,
                    exit_code=exit_code,
                    error=f"Plan file not found: {p}",
                    failed_open=failed_open,
                )
            try:
                plan_content = json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                exit_code, failed_open = compute_exit_code(level, None, "failed", is_error=True)
                return SubmitResult(
                    job_id=None,
                    level=level,
                    status="error",
                    verdict=None,
                    exit_code=exit_code,
                    error=f"Malformed plan JSON in {p}: {e}",
                    failed_open=failed_open,
                )
        else:
            try:
                plan_content = json.loads(str(plan))
            except Exception:
                plan_content = str(plan)

        payload: dict[str, Any] = {
            "repo": final_repo,
            "pr": final_pr,
            "sha": final_sha,
            "root_module": root_module,
            "level": level,
            "fail_on": fail_on,
            "plan_json": plan_content,
            "auto_enrich": auto_enrich,
        }
        if exceptions_yaml:
            payload["exceptions_yaml"] = exceptions_yaml
        if threat_answers_yaml:
            payload["threat_answers_yaml"] = threat_answers_yaml
        payload.update(options)

        # 1. Submit job
        job_id: str | None = None
        try:
            submit_resp = self.submit_job(payload)
            job_id = submit_resp.get("id")
        except ClientConnectionError as e:
            exit_code, failed_open = compute_exit_code(level, None, "error", is_error=True)
            return SubmitResult(
                job_id=None,
                level=level,
                status="error",
                verdict=None,
                exit_code=exit_code,
                error=str(e),
                failed_open=failed_open,
            )
        except ClientError as e:
            exit_code, failed_open = compute_exit_code(level, None, "error", is_error=True)
            return SubmitResult(
                job_id=None,
                level=level,
                status="error",
                verdict=None,
                exit_code=exit_code,
                error=str(e),
                failed_open=failed_open,
            )

        # 2. Poll job
        assert job_id is not None
        job_data: dict[str, Any] = {}
        try:
            job_data = self.poll_job(job_id, timeout=timeout, poll_interval=poll_interval)
        except ClientTimeoutError as e:
            exit_code, failed_open = compute_exit_code(level, None, "timeout", timed_out=True)
            return SubmitResult(
                job_id=job_id,
                level=level,
                status="timeout",
                verdict=None,
                exit_code=exit_code,
                error=str(e),
                timed_out=True,
                failed_open=failed_open,
                job_data=e.response_body if isinstance(e.response_body, dict) else {},
            )
        except ClientConnectionError as e:
            exit_code, failed_open = compute_exit_code(level, None, "error", is_error=True)
            return SubmitResult(
                job_id=job_id,
                level=level,
                status="error",
                verdict=None,
                exit_code=exit_code,
                error=str(e),
                failed_open=failed_open,
            )
        except ClientError as e:
            exit_code, failed_open = compute_exit_code(level, None, "error", is_error=True)
            return SubmitResult(
                job_id=job_id,
                level=level,
                status="error",
                verdict=None,
                exit_code=exit_code,
                error=str(e),
                failed_open=failed_open,
            )

        # 3. Handle completion
        status = job_data.get("status", "unknown")
        verdict = job_data.get("verdict")
        error = job_data.get("error")

        exit_code, failed_open = compute_exit_code(
            level,
            verdict,
            status,
            timed_out=False,
            is_error=bool(error or status == "failed"),
        )

        downloaded: list[str] = []
        if out_dir and job_id:
            available = job_data.get("artifacts") or STANDARD_ARTIFACTS
            downloaded = self.download_artifacts(job_id, out_dir, available)

        return SubmitResult(
            job_id=job_id,
            level=level,
            status=status,
            verdict=verdict,
            exit_code=exit_code,
            error=error,
            timed_out=False,
            failed_open=failed_open,
            job_data=job_data,
            artifacts_downloaded=downloaded,
            paths_count=int(job_data.get("paths_count", 0)),
            in_scope_count=int(job_data.get("in_scope_count", 0)),
            accepted_count=int(job_data.get("accepted_count", 0)),
            without_decision_count=int(job_data.get("without_decision_count", 0)),
        )


# AnalysisClient alias for SubmitClient
AnalysisClient = SubmitClient
