"""Unit and integration tests for Task W1.3: Runner client tapm submit.

Acceptance criteria:
1. posts the plan, polls, exits per level;
2. observe never fails (exit 0 on pass, blocked, timeout, or server error);
3. timeout passes at observe and recommend (fail-open);
4. validate and prevent block (exit 3) on unaccepted paths;
5. validate and prevent fail closed (exit 1) on timeout or server error;
6. unit tests for each level and the timeout;
7. end-to-end integration with live test server.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from tapm.cli import main
from tapm.gate import evaluate
from tapm.service.client import (
    ClientConnectionError,
    ClientError,
    ClientTimeoutError,
    SubmitClient,
    SubmitResult,
    compute_exit_code,
    detect_git_context,
)
from tapm.service.models import GateVerdict, JobStatus
from tapm.service.server import create_server
from tapm.util import PROJECT_ROOT


# ----------------------------------------------------------------------------- 1. Unit tests for compute_exit_code
def test_compute_exit_code_observe():
    """Level observe never fails: exit 0 in all scenarios."""
    # Pass verdict -> exit 0
    code, failed_open = compute_exit_code("observe", "pass", "completed")
    assert code == 0 and not failed_open

    # Would block verdict -> exit 0
    code, failed_open = compute_exit_code("observe", "would_block", "completed")
    assert code == 0 and not failed_open

    # Blocked verdict -> exit 0 (observe never fails)
    code, failed_open = compute_exit_code("observe", "blocked", "completed")
    assert code == 0 and not failed_open

    # Timeout -> exit 0, failed_open=True (timeout passes at observe)
    code, failed_open = compute_exit_code("observe", None, "timeout", timed_out=True)
    assert code == 0 and failed_open

    # Server error / connection failure -> exit 0, failed_open=True
    code, failed_open = compute_exit_code("observe", None, "failed", is_error=True)
    assert code == 0 and failed_open


def test_compute_exit_code_recommend():
    """Level recommend reports would_block, never fails: exit 0 in all scenarios."""
    # Pass verdict -> exit 0
    code, failed_open = compute_exit_code("recommend", "pass", "completed")
    assert code == 0 and not failed_open

    # Would block verdict -> exit 0
    code, failed_open = compute_exit_code("recommend", "would_block", "completed")
    assert code == 0 and not failed_open

    # Blocked verdict -> exit 0
    code, failed_open = compute_exit_code("recommend", "blocked", "completed")
    assert code == 0 and not failed_open

    # Timeout -> exit 0, failed_open=True (timeout passes at recommend)
    code, failed_open = compute_exit_code("recommend", None, "timeout", timed_out=True)
    assert code == 0 and failed_open

    # Server error -> exit 0, failed_open=True
    code, failed_open = compute_exit_code("recommend", None, "failed", is_error=True)
    assert code == 0 and failed_open


def test_compute_exit_code_validate():
    """Level validate blocks on unaccepted paths (exit 3) and fails closed on timeout/error (exit 1)."""
    # Pass verdict -> exit 0
    code, failed_open = compute_exit_code("validate", "pass", "completed")
    assert code == 0 and not failed_open

    # Blocked verdict -> exit 3
    code, failed_open = compute_exit_code("validate", "blocked", "completed")
    assert code == 3 and not failed_open

    # Timeout -> exit 1, failed_open=False (fails closed)
    code, failed_open = compute_exit_code("validate", None, "timeout", timed_out=True)
    assert code == 1 and not failed_open

    # Server error -> exit 1, failed_open=False (fails closed)
    code, failed_open = compute_exit_code("validate", None, "failed", is_error=True)
    assert code == 1 and not failed_open


def test_compute_exit_code_prevent():
    """Level prevent blocks on unaccepted paths (exit 3) and fails closed on timeout/error (exit 1)."""
    # Pass verdict -> exit 0
    code, failed_open = compute_exit_code("prevent", "pass", "completed")
    assert code == 0 and not failed_open

    # Blocked verdict -> exit 3
    code, failed_open = compute_exit_code("prevent", "blocked", "completed")
    assert code == 3 and not failed_open

    # Timeout -> exit 1, failed_open=False (fails closed)
    code, failed_open = compute_exit_code("prevent", None, "timeout", timed_out=True)
    assert code == 1 and not failed_open

    # Server error -> exit 1, failed_open=False (fails closed)
    code, failed_open = compute_exit_code("prevent", None, "failed", is_error=True)
    assert code == 1 and not failed_open


# ----------------------------------------------------------------------------- 2. Unit tests with simulated transport
class MockTransport:
    """Mock HTTP transport returning controlled job states."""

    def __init__(self, job_sequence: list[dict[str, Any]], artifacts: dict[str, str] | None = None):
        self.job_sequence = list(job_sequence)
        self.artifacts = artifacts or {}
        self.requests: list[tuple[str, str, dict, bytes | None]] = []
        self._seq_idx = 0

    def __call__(self, method: str, url: str, headers: dict[str, str], body_bytes: bytes | None) -> tuple[int, Any]:
        self.requests.append((method, url, headers, body_bytes))

        # POST /v1/jobs
        if method == "POST" and url.endswith("/v1/jobs"):
            job_init = self.job_sequence[0]
            return 202, {"id": job_init["id"], "status": job_init.get("status", "queued")}

        # GET /v1/jobs/{id}/artifacts/{name}
        if method == "GET" and "/artifacts/" in url:
            art_name = url.split("/artifacts/")[-1]
            if art_name in self.artifacts:
                return 200, self.artifacts[art_name]
            return 404, {"error": "not found"}

        # GET /v1/jobs/{id}
        if method == "GET" and "/v1/jobs/" in url:
            cur = self.job_sequence[min(self._seq_idx, len(self.job_sequence) - 1)]
            self._seq_idx += 1
            return 200, cur

        return 404, {"error": "not found"}


def test_client_observe_flow_with_blocked_verdict():
    """At observe, even a blocked job verdict exits 0."""
    transport = MockTransport([
        {"id": "job-1", "status": "running"},
        {
            "id": "job-1",
            "status": "completed",
            "verdict": "blocked",
            "paths_count": 2,
            "in_scope_count": 2,
            "accepted_count": 0,
            "without_decision_count": 2,
        },
    ])
    client = SubmitClient(server_url="http://mock.test", transport=transport, poll_interval=0.01)
    res = client.run(plan={"mock": "plan"}, level="observe")

    assert res.passed
    assert res.exit_code == 0
    assert res.verdict == "blocked"
    assert res.without_decision_count == 2
    assert not res.failed_open


def test_client_recommend_flow_with_would_block_verdict():
    """At recommend, a would_block verdict exits 0."""
    transport = MockTransport([
        {
            "id": "job-2",
            "status": "completed",
            "verdict": "would_block",
            "paths_count": 1,
            "in_scope_count": 1,
            "accepted_count": 0,
            "without_decision_count": 1,
        },
    ])
    client = SubmitClient(server_url="http://mock.test", transport=transport)
    res = client.run(plan={"mock": "plan"}, level="recommend")

    assert res.passed
    assert res.exit_code == 0
    assert res.verdict == "would_block"


def test_client_validate_flow_blocks_on_unaccepted():
    """At validate, a blocked job verdict exits 3."""
    transport = MockTransport([
        {
            "id": "job-3",
            "status": "completed",
            "verdict": "blocked",
            "paths_count": 1,
            "in_scope_count": 1,
            "accepted_count": 0,
            "without_decision_count": 1,
        },
    ])
    client = SubmitClient(server_url="http://mock.test", transport=transport)
    res = client.run(plan={"mock": "plan"}, level="validate")

    assert res.blocked
    assert res.exit_code == 3
    assert res.verdict == "blocked"


def test_client_validate_flow_passes_on_accepted():
    """At validate, a pass verdict exits 0."""
    transport = MockTransport([
        {
            "id": "job-4",
            "status": "completed",
            "verdict": "pass",
            "paths_count": 1,
            "in_scope_count": 1,
            "accepted_count": 1,
            "without_decision_count": 0,
        },
    ])
    client = SubmitClient(server_url="http://mock.test", transport=transport)
    res = client.run(plan={"mock": "plan"}, level="validate")

    assert res.passed
    assert res.exit_code == 0
    assert res.verdict == "pass"


def test_client_prevent_flow_blocks_on_unaccepted():
    """At prevent, a blocked job verdict exits 3."""
    transport = MockTransport([
        {
            "id": "job-5",
            "status": "completed",
            "verdict": "blocked",
            "paths_count": 1,
            "in_scope_count": 1,
            "accepted_count": 0,
            "without_decision_count": 1,
        },
    ])
    client = SubmitClient(server_url="http://mock.test", transport=transport)
    res = client.run(plan={"mock": "plan"}, level="prevent")

    assert res.blocked
    assert res.exit_code == 3


def test_client_timeout_handling_across_levels():
    """Timeout passes at observe and recommend (exit 0), fails at validate and prevent (exit 1)."""
    # Transport always returns status: running (will never finish within timeout)
    transport = MockTransport([{"id": "job-timeout", "status": "running"}])
    client = SubmitClient(server_url="http://mock.test", transport=transport, timeout=0.05, poll_interval=0.01)

    # 1. Observe: timeout passes (fail-open)
    res_obs = client.run(plan={"mock": "plan"}, level="observe")
    assert res_obs.timed_out
    assert res_obs.failed_open
    assert res_obs.exit_code == 0

    # 2. Recommend: timeout passes (fail-open)
    res_rec = client.run(plan={"mock": "plan"}, level="recommend")
    assert res_rec.timed_out
    assert res_rec.failed_open
    assert res_rec.exit_code == 0

    # 3. Validate: timeout fails closed (exit 1)
    res_val = client.run(plan={"mock": "plan"}, level="validate")
    assert res_val.timed_out
    assert not res_val.failed_open
    assert res_val.exit_code == 1

    # 4. Prevent: timeout fails closed (exit 1)
    res_prv = client.run(plan={"mock": "plan"}, level="prevent")
    assert res_prv.timed_out
    assert not res_prv.failed_open
    assert res_prv.exit_code == 1


def test_client_connection_error_fail_open_and_closed():
    """Connection errors fail open at observe/recommend, fail closed at validate/prevent."""
    def failing_transport(method: str, url: str, headers: dict, body: bytes | None):
        raise ClientConnectionError("Connection refused by target server")

    client = SubmitClient(server_url="http://broken.server", transport=failing_transport)

    res_obs = client.run(plan={"mock": "plan"}, level="observe")
    assert res_obs.status == "error"
    assert res_obs.failed_open
    assert res_obs.exit_code == 0

    res_val = client.run(plan={"mock": "plan"}, level="validate")
    assert res_val.status == "error"
    assert not res_val.failed_open
    assert res_val.exit_code == 1


def test_client_downloads_artifacts(tmp_path):
    """Artifacts are saved to dest_dir when requested."""
    transport = MockTransport(
        [
            {
                "id": "job-art",
                "status": "completed",
                "verdict": "pass",
                "artifacts": ["gate.md", "gate.json", "report.md"],
            }
        ],
        artifacts={
            "gate.md": "# Gate Pass",
            "gate.json": '{"decision": "pass"}',
            "report.md": "# Attack Paths Report",
        },
    )
    client = SubmitClient(server_url="http://mock.test", transport=transport)
    out_dir = tmp_path / "downloaded"

    res = client.run(plan={"mock": "plan"}, level="observe", out_dir=out_dir)
    assert res.passed
    assert "gate.md" in res.artifacts_downloaded
    assert "gate.json" in res.artifacts_downloaded
    assert (out_dir / "gate.md").read_text() == "# Gate Pass"
    assert (out_dir / "gate.json").read_text() == '{"decision": "pass"}'


# ----------------------------------------------------------------------------- 3. Live Server Integration Tests
@pytest.fixture
def plan_cache_006() -> dict:
    """Fixture 006 pre-computed plan from plan-cache/."""
    p = PROJECT_ROOT / "plan-cache" / "23ed19c9b2746e05ce939100d8ee09831964a8b23c4fb8f11df4a2a31d9a2b8e.json"
    assert p.exists()
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def plan_cache_clean() -> dict:
    """Clean plan with 0 attack paths."""
    p = PROJECT_ROOT / "plan-cache" / "0fa1685067568ca8f232a721c30982ac7cbc5d8e6485d775293141c8636d7725.json"
    assert p.exists()
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def live_server(tmp_path):
    """Spin up an in-process AnalysisServer on ephemeral port."""
    server = create_server(
        host="127.0.0.1",
        port=0,
        token="runner-secret-token",
        data_dir=tmp_path / "server-data",
        workers=2,
        default_llm="simulated",
        default_jev="local",
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield {
        "url": f"http://127.0.0.1:{port}",
        "token": "runner-secret-token",
        "data_dir": tmp_path / "server-data",
    }

    server.job_queue.shutdown()
    server.shutdown()
    server.server_close()


def test_live_submit_observe_passes_with_paths(live_server, plan_cache_006):
    """End-to-end submit on live server at observe exits 0 even when unaccepted paths exist."""
    client = SubmitClient(server_url=live_server["url"], token=live_server["token"], poll_interval=0.1)
    res = client.run(plan=plan_cache_006, level="observe", repo="owner/repo", pr=42)

    assert res.passed
    assert res.exit_code == 0
    assert res.paths_count >= 1
    assert res.verdict == "pass"  # At observe level, gate verdict is pass


def test_live_submit_validate_blocks_unaccepted(live_server, plan_cache_006):
    """End-to-end submit on live server at validate exits 3 when unaccepted paths exist."""
    client = SubmitClient(server_url=live_server["url"], token=live_server["token"], poll_interval=0.1)
    res = client.run(plan=plan_cache_006, level="validate", repo="owner/repo", pr=42)

    assert res.blocked
    assert res.exit_code == 3
    assert res.verdict == "blocked"
    assert res.without_decision_count >= 1


def test_live_submit_validate_passes_with_exceptions(live_server, plan_cache_006):
    """End-to-end submit on live server at validate exits 0 when accepted risks cover paths."""
    import datetime as dt

    client = SubmitClient(server_url=live_server["url"], token=live_server["token"], poll_interval=0.1)
    expiry = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    exceptions_yaml = f"""
exceptions:
  - id: RISK-006-ACCEPTED
    entry: internet
    target: aws_s3_bucket.customer_data
    owner: sec-team
    reason: test acceptance
    expires: {expiry}
"""
    res = client.run(
        plan=plan_cache_006,
        level="validate",
        repo="owner/repo",
        pr=42,
        exceptions_yaml=exceptions_yaml,
    )

    assert res.passed
    assert res.exit_code == 0
    assert res.verdict == "pass"
    assert res.accepted_count >= 1
    assert res.without_decision_count == 0


def test_live_submit_validate_passes_on_clean_plan(live_server, plan_cache_clean):
    """End-to-end submit on live server with clean 0-path plan exits 0 at validate."""
    client = SubmitClient(server_url=live_server["url"], token=live_server["token"], poll_interval=0.1)
    res = client.run(plan=plan_cache_clean, level="validate", repo="owner/clean", pr=1)

    assert res.passed
    assert res.exit_code == 0
    assert res.verdict == "pass"
    assert res.paths_count == 0


def test_live_submit_download_artifacts(live_server, plan_cache_006, tmp_path):
    """End-to-end submit downloads gate artifacts to specified directory."""
    client = SubmitClient(server_url=live_server["url"], token=live_server["token"], poll_interval=0.1)
    out_dir = tmp_path / "artifacts-out"

    res = client.run(plan=plan_cache_006, level="observe", out_dir=out_dir)

    assert res.passed
    assert (out_dir / "gate.md").exists()
    assert (out_dir / "gate.json").exists()
    assert (out_dir / "attack-paths.json").exists()
    assert (out_dir / "report.md").exists()
    # Ensure raw plan was NEVER downloaded or present in artifacts
    assert not (out_dir / "plan.json").exists()
    assert not (out_dir / "terraform-plan.json").exists()


# ----------------------------------------------------------------------------- 4. CLI Execution Tests
def test_cli_submit_observe_and_validate(live_server, plan_cache_006, tmp_path, monkeypatch):
    """Test CLI invoking tapm submit with sys.exit codes."""
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan_cache_006), encoding="utf-8")

    # 1. CLI at observe exits 0
    with pytest.raises(SystemExit) as exc_info:
        main([
            "submit",
            str(plan_file),
            "--server", live_server["url"],
            "--token", live_server["token"],
            "--level", "observe",
            "--poll-interval", "0.1",
        ])
    assert exc_info.value.code == 0

    # 2. CLI at validate exits 3
    with pytest.raises(SystemExit) as exc_info:
        main([
            "submit",
            str(plan_file),
            "--server", live_server["url"],
            "--token", live_server["token"],
            "--level", "validate",
            "--poll-interval", "0.1",
        ])
    assert exc_info.value.code == 3

    # 3. CLI with --json output
    import io
    import sys
    captured = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured)

    with pytest.raises(SystemExit) as exc_info:
        main([
            "submit",
            str(plan_file),
            "--server", live_server["url"],
            "--token", live_server["token"],
            "--level", "observe",
            "--poll-interval", "0.1",
            "--json",
        ])
    assert exc_info.value.code == 0
    parsed = json.loads(captured.getvalue())
    assert parsed["verdict"] == "pass"
    assert parsed["exit_code"] == 0
    assert "job_id" in parsed
