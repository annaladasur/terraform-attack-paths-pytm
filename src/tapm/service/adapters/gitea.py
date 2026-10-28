"""Gitea Git server adapter (W1.2).

Implements commit statuses and PR comments via the Gitea REST API:
- POST  /api/v1/repos/{owner}/{repo}/statuses/{sha}
- GET   /api/v1/repos/{owner}/{repo}/issues/{index}/comments
- POST  /api/v1/repos/{owner}/{repo}/issues/{index}/comments
- PATCH /api/v1/repos/{owner}/{repo}/issues/comments/{id}
"""

from __future__ import annotations

import os
from typing import Any

from .base import DEFAULT_MARKER, GitAdapterError, GitServerAdapter, HttpTransport


class GiteaAdapter(GitServerAdapter):
    """Adapter for Gitea REST API v1."""

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        transport: HttpTransport | None = None,
        timeout: float = 15.0,
    ) -> None:
        url = base_url or os.environ.get("GITEA_URL") or os.environ.get("TAPM_GITEA_URL") or "http://localhost:3000"
        tok = token or os.environ.get("GITEA_TOKEN") or os.environ.get("TAPM_GITEA_TOKEN")
        super().__init__(base_url=url, token=tok, transport=transport, timeout=timeout)

    def _auth_headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        # Gitea accepts 'token <token>' or 'Bearer <token>'
        return {"Authorization": f"token {self.token}"}

    def _split_repo(self, repo: str) -> tuple[str, str]:
        parts = repo.strip("/").split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid repository format '{repo}', expected 'owner/repo'")
        return parts[0], parts[1]

    def post_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "attack-paths",
        target_url: str = "",
    ) -> dict[str, Any]:
        """Post a commit status check on Gitea.

        Gitea supports states: pending, success, warning, failure, error.
        """
        owner, repo_name = self._split_repo(repo)
        valid_states = {"pending", "success", "warning", "failure", "error"}
        gitea_state = state.lower()
        if gitea_state not in valid_states:
            gitea_state = "error"

        payload = {
            "state": gitea_state,
            "context": context,
            "description": description[:255] if description else "",
            "target_url": target_url or "",
        }

        path = f"/api/v1/repos/{owner}/{repo_name}/statuses/{sha}"
        code, resp = self._http_request("POST", path, data=payload)
        if isinstance(resp, dict):
            return resp
        return {"status_code": code, "response": resp}

    def list_comments(self, repo: str, pr: int | str) -> list[dict[str, Any]]:
        """List comments for an issue / PR on Gitea."""
        owner, repo_name = self._split_repo(repo)
        path = f"/api/v1/repos/{owner}/{repo_name}/issues/{pr}/comments"
        code, resp = self._http_request("GET", path)
        if isinstance(resp, list):
            return resp
        return []

    def post_comment(
        self,
        repo: str,
        pr: int | str,
        body: str,
        update_existing: bool = True,
        marker: str = DEFAULT_MARKER,
    ) -> dict[str, Any]:
        """Post or edit a comment on a Gitea pull request."""
        owner, repo_name = self._split_repo(repo)
        formatted_body = body
        if marker and marker not in formatted_body:
            formatted_body = f"{formatted_body}\n\n{marker}"

        if update_existing and marker:
            try:
                comments = self.list_comments(repo, pr)
                for comment in comments:
                    c_body = comment.get("body", "")
                    if marker in c_body:
                        # Update the existing comment
                        comment_id = comment.get("id")
                        patch_path = f"/api/v1/repos/{owner}/{repo_name}/issues/comments/{comment_id}"
                        code, resp = self._http_request("PATCH", patch_path, data={"body": formatted_body})
                        if isinstance(resp, dict):
                            resp["_action"] = "updated"
                            return resp
                        return {"id": comment_id, "_action": "updated", "status_code": code}
            except Exception:
                # If listing or updating fails, fall through to creating a new comment
                pass

        # Create new comment
        post_path = f"/api/v1/repos/{owner}/{repo_name}/issues/{pr}/comments"
        code, resp = self._http_request("POST", post_path, data={"body": formatted_body})
        if isinstance(resp, dict):
            resp["_action"] = "created"
            return resp
        return {"_action": "created", "status_code": code}
