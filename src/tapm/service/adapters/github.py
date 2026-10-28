"""GitHub server adapter (W1.2).

Implements commit statuses and PR comments via the GitHub REST API:
- POST  /repos/{owner}/{repo}/statuses/{sha}
- GET   /repos/{owner}/{repo}/issues/{issue_number}/comments
- POST  /repos/{owner}/{repo}/issues/{issue_number}/comments
- PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}

Also supports CLI fallback to `gh pr comment` if no token is configured
but the `gh` CLI is authenticated (the existing workflow path).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .base import DEFAULT_MARKER, GitAdapterError, GitServerAdapter, HttpTransport


class GitHubAdapter(GitServerAdapter):
    """Adapter for GitHub REST API v3 and GitHub Actions environment."""

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        transport: HttpTransport | None = None,
        timeout: float = 15.0,
    ) -> None:
        url = (
            base_url
            or os.environ.get("GITHUB_API_URL")
            or os.environ.get("TAPM_GITHUB_API_URL")
            or "https://api.github.com"
        )
        tok = (
            token
            or os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GH_TOKEN")
            or os.environ.get("TAPM_GITHUB_TOKEN")
        )
        super().__init__(base_url=url, token=tok, transport=transport, timeout=timeout)

    def _auth_headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

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
        """Post a commit status check on GitHub.

        GitHub supports states: error, failure, pending, success.
        If state is 'warning', maps to 'success' (with advisory description).
        """
        owner, repo_name = self._split_repo(repo)
        gh_state = state.lower()
        if gh_state == "warning":
            # GitHub lacks native 'warning' commit status state; treat as success advisory
            gh_state = "success"
        elif gh_state not in {"error", "failure", "pending", "success"}:
            gh_state = "error"

        payload = {
            "state": gh_state,
            "context": context,
            "description": description[:140] if description else "",
            "target_url": target_url or "",
        }

        path = f"/repos/{owner}/{repo_name}/statuses/{sha}"
        code, resp = self._http_request("POST", path, data=payload)
        if isinstance(resp, dict):
            return resp
        return {"status_code": code, "response": resp}

    def list_comments(self, repo: str, pr: int | str) -> list[dict[str, Any]]:
        """List comments for an issue / PR on GitHub."""
        owner, repo_name = self._split_repo(repo)
        path = f"/repos/{owner}/{repo_name}/issues/{pr}/comments"
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
        """Post or edit a comment on a GitHub pull request.

        If a token is available or a custom transport is used, calls the REST API.
        If no token is configured and `gh` is in PATH, falls back to `gh pr comment`.
        """
        owner, repo_name = self._split_repo(repo)
        formatted_body = body
        if marker and marker not in formatted_body:
            formatted_body = f"{formatted_body}\n\n{marker}"

        if not self.token and self.transport is None and shutil.which("gh"):
            # Existing CLI path fallback (pr-security.yml style)
            return self._post_comment_via_gh_cli(repo, pr, formatted_body)

        if update_existing and marker:
            try:
                comments = self.list_comments(repo, pr)
                for comment in comments:
                    c_body = comment.get("body", "")
                    if marker in c_body:
                        # Update the existing comment
                        comment_id = comment.get("id")
                        patch_path = f"/repos/{owner}/{repo_name}/issues/comments/{comment_id}"
                        code, resp = self._http_request("PATCH", patch_path, data={"body": formatted_body})
                        if isinstance(resp, dict):
                            resp["_action"] = "updated"
                            return resp
                        return {"id": comment_id, "_action": "updated", "status_code": code}
            except Exception:
                pass

        # Create new comment
        post_path = f"/repos/{owner}/{repo_name}/issues/{pr}/comments"
        code, resp = self._http_request("POST", post_path, data={"body": formatted_body})
        if isinstance(resp, dict):
            resp["_action"] = "created"
            return resp
        return {"_action": "created", "status_code": code}

    def _post_comment_via_gh_cli(self, repo: str, pr: int | str, body: str) -> dict[str, Any]:
        """Existing fallback path using the GitHub CLI (gh pr comment)."""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as tf:
            tf.write(body)
            tpath = tf.name

        try:
            # Try editing the last comment first (--edit-last)
            res = subprocess.run(
                ["gh", "pr", "comment", str(pr), "--repo", repo, "--body-file", tpath, "--edit-last"],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                return {"_action": "updated", "output": res.stdout.strip()}

            # If edit-last failed, post a new comment
            res = subprocess.run(
                ["gh", "pr", "comment", str(pr), "--repo", repo, "--body-file", tpath],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                return {"_action": "created", "output": res.stdout.strip()}

            raise GitAdapterError(f"gh pr comment failed: {res.stderr.strip()}", status_code=res.returncode)
        finally:
            Path(tpath).unlink(missing_ok=True)
