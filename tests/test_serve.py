"""Tests for Task W1.1: tapm serve API, queue, plan deletion, token auth, per-stage logs.

Acceptance criteria:
1. End-to-end test with a plan from the plan cache;
2. Plan file is gone after the job (both temp plan and artifacts sanitized plan);
3. Plan artifacts can never be retrieved via the API (403/404);
4. Analysis artifacts (attack-paths.json, evidence.json, report.md, etc.) are present;
5. Token authentication enforces Bearer auth when configured and fails closed;
6. Status and gate verdicts correctly report pass, would_block, and blocked;
7. Metrics endpoint returns counts-only structure with runtime splits and versions;
8. Structured logs record every stage and each agent role (beat 5).
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tapm.service.auth import TokenAuth
from tapm.service.models import GateVerdict, JobStatus
from tapm.service.server import create_server
from tapm.util import PROJECT_ROOT


@pytest.fixture
def plan_cache_006() -> dict:
    """Fixture 006 pre-computed plan from plan-cache/ (has 1 high-priority attack path)."""
    p = PROJECT_ROOT / "plan-cache" / "23ed19c9b2746e05ce939100d8ee09831964a8b23c4fb8f11df4a2a31d9a2b8e.json"
    assert p.exists(), "Plan cache file for 006 must exist"
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def plan_cache_clean() -> dict:
    """Clean pre-computed plan from plan-cache/ with 0 attack paths."""
    p = PROJECT_ROOT / "plan-cache" / "0fa1685067568ca8f232a721c30982ac7cbc5d8e6485d775293141c8636d7725.json"
    assert p.exists(), "Plan cache file for clean fixture must exist"
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def test_server(tmp_path):
    """Spin up an ephemeral test server instance on a random high port."""
    server = create_server(
        host="127.0.0.1",
        port=0,  # OS assigned port
        token="test-secret-token",
        data_dir=tmp_path / "server-data",
        workers=2,
        default_llm="simulated",
        default_jev="local",
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    yield {"server": server, "url": base_url, "token": "test-secret-token", "data_dir": tmp_path / "server-data"}

    server.job_queue.shutdown()
    server.shutdown()
    server.server_close()


def _request(
    url: str,
    method: str = "GET",
    data: dict | None = None,
    token: str | None = None,
) -> tuple[int, dict | bytes, dict]:
    """Helper for sending HTTP requests to the test server."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read()
            if "json" in content_type:
                parsed = json.loads(raw.decode("utf-8"))
            else:
                parsed = raw
            return resp.status, parsed, dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            parsed = raw
        return e.code, parsed, dict(e.headers)


# ----------------------------------------------------------------------------- Tests


def test_token_auth_enforcement(test_server):
    """Requests without a token or with an invalid token receive 401 Unauthorized."""
    url = f"{test_server['url']}/v1/jobs"

    # 1. Missing Authorization header
    status, body, _ = _request(url, method="POST", data={"plan_json": {}})
    assert status == 401
    assert "Unauthorized" in body.get("error", "")

    # 2. Invalid Bearer token
    status, body, _ = _request(url, method="POST", data={"plan_json": {}}, token="wrong-token")
    assert status == 401
    assert "Unauthorized" in body.get("error", "")

    # 3. Valid Bearer token passes auth (fails on missing plan_json validation if empty)
    status, body, _ = _request(url, method="POST", data={"plan_json": {"format_version": "1.2"}}, token=test_server["token"])
    assert status in (202, 400)  # Accepted or schema validation, not 401


def test_e2e_plan_cache_analysis_and_plan_deletion(test_server, plan_cache_006):
    """End-to-end run from plan cache: plan deleted after deterministic stage, artifacts present."""
    post_url = f"{test_server['url']}/v1/jobs"
    payload = {
        "repo": "acme/web-app",
        "pr": 42,
        "sha": "a1b2c3d4e5f6",
        "root_module": "terraform/aws",
        "level": "validate",
        "plan_json": plan_cache_006,
        "fixture": "006",
        "auto_enrich": True,
    }

    status, resp, _ = _request(post_url, method="POST", data=payload, token=test_server["token"])
    assert status == 202
    assert "id" in resp
    job_id = resp["id"]
    assert resp["status"] == JobStatus.QUEUED

    # Poll until job completes
    get_url = f"{test_server['url']}/v1/jobs/{job_id}"
    completed = False
    for _ in range(50):
        time.sleep(0.15)
        status, job_doc, _ = _request(get_url, token=test_server["token"])
        assert status == 200
        if job_doc["status"] in (JobStatus.COMPLETED, JobStatus.FAILED):
            completed = True
            break

    assert completed, "Job did not complete within timeout"
    assert job_doc["status"] == JobStatus.COMPLETED
    assert job_doc["error"] is None

    # Gate verdict must be 'blocked' (fixture 006 has 1 high priority path and no exceptions at validate)
    assert job_doc["verdict"] == GateVerdict.BLOCKED
    assert job_doc["paths_count"] == 1
    assert job_doc["in_scope_count"] == 1
    assert job_doc["without_decision_count"] == 1
    assert job_doc["plan_deleted"] is True

    # ACCEPTANCE CRITERION: Plan file is completely gone from disk
    job_obj = test_server["server"].job_queue.get_job(job_id)
    assert job_obj is not None
    assert not job_obj.temp_plan_path.exists(), f"Temp plan file {job_obj.temp_plan_path} must be deleted"
    assert not (job_obj.artifacts_dir / "terraform-plan.json").exists(), "terraform-plan.json must not exist in artifacts"
    assert not (job_obj.artifacts_dir / "plan.json").exists(), "plan.json must not exist in artifacts"

    # ACCEPTANCE CRITERION: GET /v1/jobs/{id}/artifacts/terraform-plan.json is strictly refused
    art_plan_url = f"{test_server['url']}/v1/jobs/{job_id}/artifacts/terraform-plan.json"
    status, err_doc, _ = _request(art_plan_url, token=test_server["token"])
    assert status == 403
    assert "Forbidden" in err_doc.get("error", "")

    # ACCEPTANCE CRITERION: Analysis artifacts are present and readable
    for name in ("attack-paths.json", "evidence.json", "report.md", "attack-paths.sarif", "story.md", "gate.json"):
        art_url = f"{test_server['url']}/v1/jobs/{job_id}/artifacts/{name}"
        st, content, _ = _request(art_url, token=test_server["token"])
        assert st == 200, f"Artifact '{name}' should return 200 OK"
        assert content, f"Artifact '{name}' content should not be empty"

    # Verify SARIF content conforms
    sarif_url = f"{test_server['url']}/v1/jobs/{job_id}/artifacts/attack-paths.sarif"
    _, sarif_doc, _ = _request(sarif_url, token=test_server["token"])
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"]) == 1

    # Verify structured logs captured every stage and each agent role (beat 5)
    logs_url = f"{test_server['url']}/v1/jobs/{job_id}/logs"
    st, logs_doc, _ = _request(logs_url, token=test_server["token"])
    assert st == 200
    logs = logs_doc["logs"]
    stages_logged = [e["name"] for e in logs if e.get("kind") == "stage"]
    assert "receive" in stages_logged
    assert "deterministic" in stages_logged
    assert "plan_deletion" in stages_logged
    assert "gate" in stages_logged
    assert "enrichment" in stages_logged

    # Verify agent roles logged during enrichment
    roles_logged = [e["name"] for e in logs if e.get("kind") == "role"]
    assert "path_narrator" in roles_logged
    assert "plain_explainer" in roles_logged
    assert "adversarial_reviewer" in roles_logged


def test_verdicts_across_adoption_levels(test_server, plan_cache_006, plan_cache_clean):
    """Test gate verdicts: 'blocked' at validate with paths, 'would_block' at recommend, 'pass' at observe."""

    def run_level(level: str, plan: dict, exceptions: list | None = None) -> str:
        payload = {
            "repo": "acme/test-verdicts",
            "pr": 1,
            "sha": "11223344",
            "root_module": ".",
            "level": level,
            "plan_json": plan,
            "auto_enrich": False,
        }
        if exceptions:
            payload["exceptions"] = exceptions

        st, resp, _ = _request(f"{test_server['url']}/v1/jobs", method="POST", data=payload, token=test_server["token"])
        assert st == 202
        job_id = resp["id"]

        for _ in range(40):
            time.sleep(0.1)
            _, doc, _ = _request(f"{test_server['url']}/v1/jobs/{job_id}", token=test_server["token"])
            if doc["status"] in (JobStatus.COMPLETED, JobStatus.FAILED):
                return doc["verdict"]
        pytest.fail(f"Job {job_id} did not finish in time")

    # 1. Level 'validate' on plan with open path -> blocked
    assert run_level("validate", plan_cache_006) == GateVerdict.BLOCKED

    # 2. Level 'recommend' on plan with open path -> would_block
    assert run_level("recommend", plan_cache_006) == GateVerdict.WOULD_BLOCK

    # 3. Level 'observe' on plan with open path -> pass
    assert run_level("observe", plan_cache_006) == GateVerdict.PASS

    # 4. Clean plan with 0 attack paths at 'validate' -> pass
    assert run_level("validate", plan_cache_clean) == GateVerdict.PASS

    # 5. Plan with path but accepted exception at 'validate' -> pass
    valid_exception = [{
        "id": "EXC-001",
        "entry": "internet",
        "target": "aws_s3_bucket.customer_data",
        "owner": "sec-team",
        "reason": "Business requirement verified",
        "expires": "2026-12-01",
    }]
    assert run_level("validate", plan_cache_006, exceptions=valid_exception) == GateVerdict.PASS


def test_metrics_endpoint_counts_only(test_server):
    """GET /v1/metrics returns counts-only metrics, version numbers, and runtime split."""
    url = f"{test_server['url']}/v1/metrics"
    st, m, _ = _request(url, token=test_server["token"])
    assert st == 200

    assert isinstance(m["jobs_total"], int)
    assert isinstance(m["jobs_by_status"], dict)
    assert isinstance(m["jobs_by_verdict"], dict)
    assert isinstance(m["queue_depth"], int)
    assert isinstance(m["queue_wait_ms_avg"], (int, float))
    assert isinstance(m["runtime_split_ms"], dict)
    assert isinstance(m["cache_hits"], int)
    assert m["canary_status"] in ("pass", "fail", "ok")

    versions = m["versions"]
    assert "tapm" in versions
    assert "pytm" in versions
    assert "python" in versions
    assert "schema_version" in versions


def test_artifact_path_traversal_protection(test_server, plan_cache_clean):
    """Directory traversal in artifact retrieval is rejected with 400 Bad Request."""
    st, resp, _ = _request(
        f"{test_server['url']}/v1/jobs",
        method="POST",
        data={"plan_json": plan_cache_clean, "auto_enrich": False},
        token=test_server["token"],
    )
    job_id = resp["id"]
    for _ in range(30):
        time.sleep(0.1)
        _, doc, _ = _request(f"{test_server['url']}/v1/jobs/{job_id}", token=test_server["token"])
        if doc["status"] == JobStatus.COMPLETED:
            break

    # Directory traversal attempts
    for bad_path in ("../../etc/passwd", "../server.py", "/etc/passwd"):
        st, err, _ = _request(f"{test_server['url']}/v1/jobs/{job_id}/artifacts/{bad_path}", token=test_server["token"])
        assert st in (400, 404)


def test_explicit_enrich_endpoint(test_server, plan_cache_006):
    """POST /v1/jobs/{id}/enrich triggers async enrichment on an existing job."""
    # Submit job with auto_enrich=False
    st, resp, _ = _request(
        f"{test_server['url']}/v1/jobs",
        method="POST",
        data={"plan_json": plan_cache_006, "fixture": "006", "auto_enrich": False},
        token=test_server["token"],
    )
    job_id = resp["id"]

    for _ in range(40):
        time.sleep(0.1)
        _, doc, _ = _request(f"{test_server['url']}/v1/jobs/{job_id}", token=test_server["token"])
        if doc["status"] == JobStatus.COMPLETED:
            break

    assert doc["enrichment_status"] == "none"

    # Trigger enrichment explicitly via POST /v1/jobs/{id}/enrich
    enrich_url = f"{test_server['url']}/v1/jobs/{job_id}/enrich"
    st, enrich_resp, _ = _request(enrich_url, method="POST", token=test_server["token"])
    assert st == 202
    assert enrich_resp["enrichment_status"] in ("queued", "running")

    # Wait for enrichment to complete
    for _ in range(40):
        time.sleep(0.15)
        _, doc, _ = _request(f"{test_server['url']}/v1/jobs/{job_id}", token=test_server["token"])
        if doc["enrichment_status"] == "completed":
            break

    assert doc["enrichment_status"] == "completed"

    # Verify ai-annotations.json is now available via artifacts endpoint
    st, ai_doc, _ = _request(f"{test_server['url']}/v1/jobs/{job_id}/artifacts/ai-annotations.json", token=test_server["token"])
    assert st == 200
    assert len(ai_doc["annotations"]) > 0
