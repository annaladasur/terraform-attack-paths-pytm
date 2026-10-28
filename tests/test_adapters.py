"""Tests for Task W1.2: Git server adapters (Gitea comment + status; GitHub).

Acceptance criteria:
1. Tested against recorded HTTP fixtures of the Gitea API (no live server needed);
2. Gitea comment creation and update (edit-last / marker based) via REST API;
3. Gitea commit status posting for pending, success, warning, failure states;
4. Verdict-to-status mapping across observe, recommend, and validate adoption levels;
5. GitHub adapter comment and status posting via REST API;
6. End-to-end integration with tapm serve job lifecycle (status pending -> verdict status,
   initial PR comment -> updated comment after async AI enrichment);
7. Error handling for network and authentication errors fails gracefully.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tapm.service.adapters import (
    DEFAULT_MARKER,
    FixtureHttpTransport,
    GitAdapterError,
    GiteaAdapter,
    GitHubAdapter,
    detect_adapter,
    get_adapter,
)
from tapm.service.models import GateVerdict, JobStatus
from tapm.service.queue import JobQueue
from tapm.util import PROJECT_ROOT


@pytest.fixture
def plan_cache_006() -> dict:
    p = PROJECT_ROOT / "plan-cache" / "23ed19c9b2746e05ce939100d8ee09831964a8b23c4fb8f11df4a2a31d9a2b8e.json"
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def fixture_transport() -> FixtureHttpTransport:
    return FixtureHttpTransport()


# ---------------------------------------------------------------- Gitea tests


def test_gitea_post_status(fixture_transport):
    """Test posting pending, success, warning, and failure commit statuses to Gitea."""
    adapter = GiteaAdapter(
        base_url="http://gitea:3000",
        token="test-gitea-token",
        transport=fixture_transport,
    )

    # 1. Pending status
    resp = adapter.post_status(
        repo="demo-org/infra-demo",
        sha="abcdef1234567890",
        state="pending",
        description="Attack path analysis in progress",
        target_url="http://localhost:8080/v1/jobs/job-001",
    )
    assert resp.get("status") == "pending" or resp.get("state") == "pending" or resp.get("id") == 501
    assert len(fixture_transport.requests_log) == 1
    req1 = fixture_transport.requests_log[-1]
    assert req1["method"] == "POST"
    assert "/api/v1/repos/demo-org/infra-demo/statuses/abcdef1234567890" in req1["url"]
    assert req1["headers"].get("Authorization") == "token test-gitea-token"
    assert req1["body"]["state"] == "pending"

    # 2. Success status
    resp2 = adapter.post_status(
        repo="demo-org/infra-demo",
        sha="abcdef1234567890",
        state="success",
        description="Attack paths: 0 paths (pass)",
    )
    assert resp2.get("id") == 502 or resp2.get("status") == "success"

    # 3. Warning status
    resp3 = adapter.post_status(
        repo="demo-org/infra-demo",
        sha="abcdef1234567890",
        state="warning",
        description="Attack paths: 1 path(s) without decision (recommend mode)",
    )
    assert resp3.get("id") == 504 or resp3.get("status") == "warning"

    # 4. Failure status
    resp4 = adapter.post_status(
        repo="demo-org/infra-demo",
        sha="abcdef1234567890",
        state="failure",
        description="Attack paths: 1 path(s) blocked (level: validate)",
    )
    assert resp4.get("id") == 503 or resp4.get("status") == "failure"


def test_gitea_post_comment_create_and_update(fixture_transport):
    """Test posting a new PR comment and updating an existing comment via the marker."""
    adapter = GiteaAdapter(
        base_url="http://gitea:3000",
        token="test-gitea-token",
        transport=fixture_transport,
    )

    # 1. Update existing comment when marker is present in comment list fixture
    resp_update = adapter.post_comment(
        repo="demo-org/infra-demo",
        pr=42,
        body="## Attack path review\nUpdated report with AI annotations",
        update_existing=True,
    )
    assert resp_update.get("_action") == "updated"
    # Verify PATCH request was made
    patch_reqs = [r for r in fixture_transport.requests_log if r["method"] == "PATCH"]
    assert len(patch_reqs) == 1
    assert "/api/v1/repos/demo-org/infra-demo/issues/comments/101" in patch_reqs[0]["url"]
    assert DEFAULT_MARKER in patch_reqs[0]["body"]["body"]

    # 2. Force create a new comment when update_existing is False or empty comment list
    fixture_transport.register("GET", "/issues/99/comments", 200, [])
    resp_create = adapter.post_comment(
        repo="demo-org/infra-demo",
        pr=99,
        body="## Initial attack path report",
        update_existing=True,
    )
    assert resp_create.get("_action") == "created"
    post_reqs = [r for r in fixture_transport.requests_log if r["method"] == "POST" and "/issues/99/comments" in r["url"]]
    assert len(post_reqs) == 1
    assert "## Initial attack path report" in post_reqs[0]["body"]["body"]


# ---------------------------------------------------------------- Verdict mapping tests


def test_adapter_verdict_to_status_mapping():
    """Verify verdict mapping across adoption levels."""
    adapter = GiteaAdapter(base_url="http://localhost:3000")

    # Pass verdict
    state, desc = adapter.map_verdict_to_status("pass", level="observe", paths_count=0)
    assert state == "success"
    assert "0 paths (pass)" in desc

    state, desc = adapter.map_verdict_to_status("pass", level="validate", paths_count=2)
    assert state == "success"
    assert "2 path(s) allowed (pass)" in desc

    # Would_block at observe -> success (advisory)
    state, desc = adapter.map_verdict_to_status("would_block", level="observe", paths_count=1)
    assert state == "success"
    assert "observe mode, passed" in desc

    # Would_block at recommend -> warning
    state, desc = adapter.map_verdict_to_status("would_block", level="recommend", paths_count=1)
    assert state == "warning"
    assert "recommend mode" in desc

    # Blocked at validate -> failure
    state, desc = adapter.map_verdict_to_status("blocked", level="validate", paths_count=1)
    assert state == "failure"
    assert "blocked (level: validate)" in desc


# ---------------------------------------------------------------- GitHub tests


def test_github_post_status_and_comment(fixture_transport):
    """Test GitHub adapter for commit status and PR comment."""
    adapter = GitHubAdapter(
        base_url="https://api.github.com",
        token="ghp_test_token_12345",
        transport=fixture_transport,
    )

    # 1. Status creation
    fixture_transport.register("POST", "/repos/demo-org/infra-demo/statuses/sha123", 201, {"id": 888, "state": "success"})
    resp_status = adapter.post_status(
        repo="demo-org/infra-demo",
        sha="sha123",
        state="success",
        description="Attack paths: 0 paths (pass)",
    )
    assert resp_status.get("id") == 888
    req = fixture_transport.requests_log[-1]
    assert req["headers"].get("Authorization") == "Bearer ghp_test_token_12345"
    assert req["headers"].get("Accept") == "application/vnd.github+json"

    # Warning state on GitHub maps to success (since GitHub has no warning state)
    fixture_transport.register("POST", "/repos/demo-org/infra-demo/statuses/sha456", 201, {"id": 889, "state": "success"})
    adapter.post_status(
        repo="demo-org/infra-demo",
        sha="sha456",
        state="warning",
        description="Warning notice",
    )
    req_warn = fixture_transport.requests_log[-1]
    assert req_warn["body"]["state"] == "success"

    # 2. PR comment creation
    fixture_transport.register("GET", "/repos/demo-org/infra-demo/issues/42/comments", 200, [])
    fixture_transport.register("POST", "/repos/demo-org/infra-demo/issues/42/comments", 201, {"id": 999, "body": "test comment"})
    resp_comment = adapter.post_comment(
        repo="demo-org/infra-demo",
        pr=42,
        body="## GitHub PR comment",
    )
    assert resp_comment.get("_action") == "created"
    assert resp_comment.get("id") == 999

    # 3. PR comment update via marker
    existing_gh_comments = [{"id": 999, "body": f"Old comment\n\n{DEFAULT_MARKER}"}]
    fixture_transport.register("GET", "/repos/demo-org/infra-demo/issues/42/comments", 200, existing_gh_comments)
    fixture_transport.register("PATCH", "/repos/demo-org/infra-demo/issues/comments/999", 200, {"id": 999, "body": "Updated comment"})

    resp_update = adapter.post_comment(
        repo="demo-org/infra-demo",
        pr=42,
        body="## Updated GitHub PR comment",
    )
    assert resp_update.get("_action") == "updated"
    patch_req = fixture_transport.requests_log[-1]
    assert patch_req["method"] == "PATCH"
    assert "/repos/demo-org/infra-demo/issues/comments/999" in patch_req["url"]


# ---------------------------------------------------------------- Factory and auto-detection


def test_adapter_factory_and_detection(monkeypatch):
    """Test get_adapter factory and detect_adapter environment logic."""
    a_gitea = get_adapter("gitea", base_url="http://gitea.local:3000", token="tok1")
    assert isinstance(a_gitea, GiteaAdapter)
    assert a_gitea.base_url == "http://gitea.local:3000"
    assert a_gitea.token == "tok1"

    a_github = get_adapter("github", token="gh_tok")
    assert isinstance(a_github, GitHubAdapter)
    assert a_github.token == "gh_tok"

    with pytest.raises(ValueError, match="Unsupported git adapter type"):
        get_adapter("unknown-server")

    # Detection via GITEA_URL
    monkeypatch.setenv("GITEA_URL", "http://my-gitea:3000")
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("TAPM_GIT_ADAPTER", raising=False)
    detected = detect_adapter()
    assert isinstance(detected, GiteaAdapter)
    assert detected.base_url == "http://my-gitea:3000"

    # Detection via GITHUB_ACTIONS
    monkeypatch.delenv("GITEA_URL", raising=False)
    monkeypatch.delenv("GITEA_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "actions-secret")
    detected_gh = detect_adapter()
    assert isinstance(detected_gh, GitHubAdapter)
    assert detected_gh.token == "actions-secret"


# ---------------------------------------------------------------- Error handling


def test_adapter_error_handling():
    """Verify error handling on HTTP failure and invalid repository format."""
    def error_transport(method, url, headers, body):
        raise GitAdapterError("HTTP 401 Unauthorized", status_code=401, response_body={"message": "Bad credentials"})

    adapter = GiteaAdapter(
        base_url="http://gitea:3000",
        token="invalid-token",
        transport=error_transport,
    )

    with pytest.raises(GitAdapterError) as exc_info:
        adapter.post_status("org/repo", sha="abc", state="pending", description="test")
    assert exc_info.value.status_code == 401

    with pytest.raises(ValueError, match="expected 'owner/repo'"):
        adapter.post_status("invalid-repo-without-slash", sha="abc", state="pending", description="test")


# ---------------------------------------------------------------- End-to-end integration with JobQueue


def test_job_queue_git_adapter_lifecycle(tmp_path, plan_cache_006, fixture_transport):
    """End-to-end test verifying Git status and PR comments during the JobQueue lifecycle."""
    adapter = GiteaAdapter(
        base_url="http://gitea:3000",
        token="test-token",
        transport=fixture_transport,
    )

    queue = JobQueue(
        data_dir=tmp_path / "queue-data",
        workers=1,
        default_llm="simulated",
        default_jev="local",
        git_adapter=adapter,
    )

    try:
        # Submit job for fixture 006 (has 1 high attack path)
        job = queue.submit_job(
            {
                "repo": "demo-org/infra-demo",
                "pr": 42,
                "sha": "c0ffee1234567890",
                "level": "validate",
                "plan_json": plan_cache_006,
                "auto_enrich": True,
            }
        )

        # Wait for job completion
        import time
        t_start = time.time()
        while job.status != JobStatus.COMPLETED and time.time() - t_start < 10.0:
            time.sleep(0.1)

        assert job.status == JobStatus.COMPLETED
        assert job.verdict == GateVerdict.BLOCKED

        # Verify Git interactions in the transport log:
        # 1. Pending status posted on job start
        status_reqs = [r for r in fixture_transport.requests_log if "/statuses/c0ffee1234567890" in r["url"]]
        assert len(status_reqs) >= 2, f"Expected at least pending and final status, got {len(status_reqs)}"
        assert status_reqs[0]["body"]["state"] == "pending"
        assert status_reqs[1]["body"]["state"] == "failure"  # Blocked mapped to failure

        # 2. PR comment was posted / updated
        comment_reqs = [
            r for r in fixture_transport.requests_log
            if r["method"] in ("POST", "PATCH") and ("/issues/42/comments" in r["url"] or "/issues/comments/" in r["url"])
        ]
        assert len(comment_reqs) >= 1, "Expected PR comment requests to Git adapter"

        # 3. Check structured logs in job for git_status and git_comment stages
        stages_logged = [log.get("name") for log in job.logs]
        assert "git_status" in stages_logged
        assert "git_comment" in stages_logged

    finally:
        queue.shutdown()


def test_cli_git_status(capsys, monkeypatch):
    """Test tapm git-status CLI command execution."""
    from tapm.cli import main

    def fake_post_status(self, repo, sha, state, description="", context="attack-paths", target_url=""):
        return {"id": 12345, "state": state}

    monkeypatch.setattr(GiteaAdapter, "post_status", fake_post_status)

    main([
        "git-status",
        "--server", "gitea",
        "--base-url", "http://gitea.local:3000",
        "--token", "dummy-tok",
        "--repo", "test-org/repo",
        "--sha", "1234567890abcdef",
        "--state", "success",
        "--description", "0 attack paths",
    ])

    captured = capsys.readouterr()
    assert "Posted status 'success' to test-org/repo@12345678" in captured.out


def test_cli_git_comment(tmp_path, capsys, monkeypatch):
    """Test tapm git-comment CLI command execution with body and body-file."""
    from tapm.cli import main

    def fake_post_comment(self, repo, pr, body, update_existing=True, marker=None):
        return {"id": 67890, "_action": "created"}

    monkeypatch.setattr(GiteaAdapter, "post_comment", fake_post_comment)

    # 1. Direct body
    main([
        "git-comment",
        "--server", "gitea",
        "--base-url", "http://gitea.local:3000",
        "--token", "dummy-tok",
        "--repo", "test-org/repo",
        "--pr", "42",
        "--body", "## Attack path check",
    ])
    captured1 = capsys.readouterr()
    assert "Created comment on test-org/repo PR #42" in captured1.out

    # 2. Body from file
    bf = tmp_path / "comment.md"
    bf.write_text("## File comment content", encoding="utf-8")
    main([
        "git-comment",
        "--server", "gitea",
        "--base-url", "http://gitea.local:3000",
        "--token", "dummy-tok",
        "--repo", "test-org/repo",
        "--pr", "42",
        "--body-file", str(bf),
    ])
    captured2 = capsys.readouterr()
    assert "Created comment on test-org/repo PR #42" in captured2.out

