"""Base class and common types for Git server adapters (W1.2).

Supports posting PR comments and commit statuses across Git platforms
(Gitea, GitHub, GitLab) with support for comment editing/updating and
verdict-to-status mapping.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Callable

DEFAULT_MARKER = "<!-- tapm:attack-paths -->"


class GitAdapterError(Exception):
    """Exception raised by Git server adapters."""

    def __init__(self, message: str, status_code: int | None = None, response_body: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


# Signature for custom HTTP transports: (method, url, headers, body_bytes) -> (status_code, response_data)
HttpTransport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, Any]]


class GitServerAdapter(ABC):
    """Abstract base class for Git server adapters."""

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        transport: HttpTransport | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.transport = transport
        self.timeout = timeout

    def _http_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        """Perform an HTTP request either via the custom transport or urllib."""
        url = f"{self.base_url}{path}" if path.startswith("/") else f"{self.base_url}/{path}"
        req_headers = {"User-Agent": "tapm-git-adapter/0.1.0"}
        if self.token:
            req_headers.update(self._auth_headers())
        if headers:
            req_headers.update(headers)

        body_bytes: bytes | None = None
        if data is not None:
            req_headers["Content-Type"] = "application/json; charset=utf-8"
            body_bytes = json.dumps(data).encode("utf-8")

        if self.transport is not None:
            return self.transport(method, url, req_headers, body_bytes)

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.status
                raw = resp.read()
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    try:
                        return status_code, json.loads(raw.decode("utf-8"))
                    except Exception:
                        return status_code, raw.decode("utf-8", errors="replace")
                return status_code, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read()
            body = raw.decode("utf-8", errors="replace")
            try:
                body_json = json.loads(body)
                raise GitAdapterError(
                    f"HTTP {e.code} {e.reason}: {body}",
                    status_code=e.code,
                    response_body=body_json,
                ) from e
            except json.JSONDecodeError:
                raise GitAdapterError(
                    f"HTTP {e.code} {e.reason}: {body}",
                    status_code=e.code,
                    response_body=body,
                ) from e
        except urllib.error.URLError as e:
            raise GitAdapterError(f"Network error connecting to {url}: {e.reason}") from e

    @abstractmethod
    def _auth_headers(self) -> dict[str, str]:
        """Return authentication headers for this platform."""
        raise NotImplementedError

    @abstractmethod
    def post_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "attack-paths",
        target_url: str = "",
    ) -> dict[str, Any]:
        """Post commit status (pending, success, warning, failure, error)."""
        raise NotImplementedError

    @abstractmethod
    def post_comment(
        self,
        repo: str,
        pr: int | str,
        body: str,
        update_existing: bool = True,
        marker: str = DEFAULT_MARKER,
    ) -> dict[str, Any]:
        """Post or edit a comment on a pull request / issue."""
        raise NotImplementedError

    def map_verdict_to_status(
        self,
        verdict: str | None,
        level: str = "observe",
        paths_count: int = 0,
    ) -> tuple[str, str]:
        """Map gate verdict and level to a standard commit status state and description.

        Returns: (state, description)
        """
        lvl = (level or "observe").lower()
        v = (verdict or "pass").lower()

        if v == "pass":
            if paths_count == 0:
                return "success", "Attack paths: 0 paths (pass)"
            return "success", f"Attack paths: {paths_count} path(s) allowed (pass)"

        if v == "would_block":
            if lvl == "observe":
                return "success", f"Attack paths: {paths_count} path(s) detected (observe mode, passed)"
            # At recommend level, Gitea supports 'warning'; GitHub maps warning to 'success' or 'pending'
            return "warning", f"Attack paths: {paths_count} path(s) without decision (recommend mode)"

        if v == "blocked":
            return "failure", f"Attack paths: {paths_count} path(s) blocked (level: {lvl})"

        return "error", f"Attack paths: unknown verdict '{verdict}'"
