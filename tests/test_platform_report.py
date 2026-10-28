"""Tests for metrics endpoint enhancements and platform report generator (W1.4 / W3.3)."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from tapm import PROMPT_VERSION, SCHEMA_VERSION, __version__
from tapm.pytm_gen.generator import PYTM_VERSION
from tapm.report.platform import render_platform_report
from tapm.service.client import AnalysisClient, ClientError
from tapm.service.metrics import MetricsCollector
from tapm.service.models import GateVerdict, JobStatus
from tapm.service.server import create_server


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def plan_cache_clean():
    p = (
        Path(__file__).parent.parent
        / "plan-cache"
        / "0fa1685067568ca8f232a721c30982ac7cbc5d8e6485d775293141c8636d7725.json"
    )
    assert p.exists(), f"plan-cache fixture not found: {p}"
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def test_server(tmp_path):
    srv = create_server(
        host="127.0.0.1",
        port=0,
        token="test-metrics-token-xyz",
        data_dir=tmp_path / "service-data",
        workers=2,
        default_llm="simulated",
        default_model="test-model-v1",
    )
    host, port = srv.server_address
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield {
            "server": srv,
            "url": f"http://{host}:{port}",
            "token": "test-metrics-token-xyz",
        }
    finally:
        srv.shutdown()
        srv.server_close()


# -----------------------------------------------------------------------------
# Unit Tests: MetricsCollector
# -----------------------------------------------------------------------------


def test_metrics_collector_initial_state():
    """Verify initial state of counts-only collector."""
    mc = MetricsCollector(model="test-instruct", prompt_version="v1")
    m = mc.get_metrics()

    assert m["jobs_total"] == 0
    assert m["jobs_by_status"] == {}
    assert m["jobs_by_verdict"] == {}
    assert m["jobs_by_level"] == {}
    assert m["queue_depth"] == 0
    assert m["queue_wait_ms_avg"] == 0.0
    assert m["queue_wait_ms_max"] == 0
    assert m["runtime_split_ms"] == {}
    assert m["cache_hits"] == 0
    assert m["canary_status"] == "pass"
    assert m["canaries_total"] == 0
    assert m["canaries_failed"] == 0
    assert m["triggers"] == {}

    v = m["versions"]
    assert v["tapm"] == __version__
    assert v["pytm"] == PYTM_VERSION
    assert v["schema_version"] == SCHEMA_VERSION
    assert v["prompt_version"] == "v1"
    assert v["model"] == "test-instruct"
    assert "python" in v


def test_metrics_collector_lifecycle_tracking():
    """Verify job enqueue, start, completion, failure, and timings."""
    mc = MetricsCollector()

    # Enqueue 3 jobs
    mc.record_job_enqueued(level="observe", trigger="pr_change")
    mc.record_job_enqueued(level="recommend", trigger="exceptions_only")
    mc.record_job_enqueued(level="validate", trigger="pr_change")

    m = mc.get_metrics()
    assert m["jobs_total"] == 3
    assert m["jobs_by_status"]["queued"] == 3
    assert m["jobs_by_level"] == {"observe": 1, "recommend": 1, "validate": 1}
    assert m["triggers"] == {"pr_change": 2, "exceptions_only": 1}

    # Start 2 jobs with wait latency
    mc.record_job_started(queue_wait_ms=50)
    mc.record_job_started(queue_wait_ms=150)

    m = mc.get_metrics()
    assert m["jobs_by_status"]["queued"] == 1
    assert m["jobs_by_status"]["running"] == 2
    assert m["queue_wait_ms_avg"] == 100.0
    assert m["queue_wait_ms_max"] == 150

    # Complete 1 job
    timings_1 = {
        "plan": 200,
        "scanners": 400,
        "engine": 300,
        "ai": 1000,
        "deterministic": 300,
        "gate": 20,
    }
    mc.record_job_completed(verdict="pass", timings_ms=timings_1, level="observe")

    m = mc.get_metrics()
    assert m["jobs_by_status"]["running"] == 1
    assert m["jobs_by_status"]["completed"] == 1
    assert m["jobs_by_verdict"] == {"pass": 1}
    assert m["runtime_split_ms"]["plan"] == 200
    assert m["runtime_split_ms"]["scanners"] == 400
    assert m["runtime_split_ms"]["engine"] == 300
    assert m["runtime_split_ms"]["ai"] == 1000

    # Fail 1 job
    mc.record_job_failed(level="recommend")
    m = mc.get_metrics()
    assert m["jobs_by_status"]["running"] == 0
    assert m["jobs_by_status"]["failed"] == 1


def test_metrics_collector_canary_and_cache_tracking():
    """Verify canary execution tracking (M15) and cache hit counting."""
    mc = MetricsCollector()

    mc.record_canary_run(passed=True)
    mc.record_canary_run(passed=True)
    m = mc.get_metrics()
    assert m["canaries_total"] == 2
    assert m["canaries_failed"] == 0
    assert m["canary_status"] == "pass"

    mc.record_canary_run(passed=False)
    m = mc.get_metrics()
    assert m["canaries_total"] == 3
    assert m["canaries_failed"] == 1
    assert m["canary_status"] == "fail"

    mc.record_cache_hits(5)
    assert mc.get_metrics()["cache_hits"] == 5


def test_metrics_collector_thread_safety():
    """Verify collector remains thread-safe under concurrent mutations."""
    mc = MetricsCollector()
    threads = []

    def worker():
        for _ in range(50):
            mc.record_job_enqueued("validate", "pr_change")
            mc.record_job_started(10)
            mc.record_job_completed("pass", {"engine": 5}, "validate")
            mc.record_cache_hits(1)
            mc.record_canary_run(True)

    for _ in range(10):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    m = mc.get_metrics()
    assert m["jobs_total"] == 500
    assert m["jobs_by_status"]["completed"] == 500
    assert m["jobs_by_verdict"]["pass"] == 500
    assert m["cache_hits"] == 500
    assert m["canaries_total"] == 500


# -----------------------------------------------------------------------------
# Unit Tests: render_platform_report
# -----------------------------------------------------------------------------


def test_render_platform_report_markdown():
    """Verify markdown output of platform report."""
    sample_metrics = {
        "jobs_total": 25,
        "jobs_by_status": {"completed": 24, "failed": 1, "running": 0, "queued": 0},
        "jobs_by_verdict": {"pass": 20, "would_block": 2, "blocked": 2},
        "jobs_by_level": {"observe": 10, "recommend": 5, "validate": 8, "prevent": 2},
        "queue_depth": 0,
        "queue_wait_ms_avg": 24.5,
        "queue_wait_ms_max": 110,
        "runtime_split_ms": {
            "plan": 1500,
            "scanners": 3200,
            "engine": 850,
            "ai": 4500,
            "deterministic": 850,
            "gate": 15,
            "plan_deletion": 3,
            "enrichment": 4500,
        },
        "cache_hits": 12,
        "canary_status": "pass",
        "canaries_total": 20,
        "canaries_failed": 0,
        "triggers": {
            "pr_change": 22,
            "exceptions_only": 2,
            "nightly": 1,
        },
        "versions": {
            "tapm": "0.1.0",
            "pytm": "0.3.0",
            "python": "3.11.8",
            "schema_version": "1",
            "prompt_version": "v1",
            "model": "qwen2.5:7b",
        },
    }

    md = render_platform_report(sample_metrics, format="markdown")

    assert "# Platform Owner Report: Analysis Service Operations" in md
    assert "> **Scope**: Operational counts and capacity metrics from `/v1/metrics`." in md
    assert "Canary Health (M15)" in md
    assert "Average Queue Wait" in md
    assert "24.5 ms" in md
    assert "`tapm`" in md
    assert "`qwen2.5:7b`" in md
    assert "Runtime Split: Latency & Capacity" in md
    assert "Plan" in md
    assert "Scanners" in md
    assert "Engine" in md
    assert "AI" in md
    assert "Queue & CI Runner Capacity" in md
    assert "AI Efficiency & Caching" in md
    assert "Trigger Scope & Policy Distribution" in md
    assert "M14 Pipeline Time" in md
    assert "M15 Control Failure Rate" in md


def test_render_platform_report_text():
    """Verify plain text format of platform report."""
    sample_metrics = {
        "jobs_total": 10,
        "jobs_by_status": {"completed": 10},
        "jobs_by_verdict": {"pass": 10},
        "jobs_by_level": {"observe": 10},
        "queue_depth": 0,
        "queue_wait_ms_avg": 12.0,
        "queue_wait_ms_max": 25,
        "runtime_split_ms": {"plan": 500, "scanners": 1000, "engine": 300, "ai": 2000},
        "cache_hits": 4,
        "canary_status": "pass",
        "canaries_total": 5,
        "canaries_failed": 0,
        "triggers": {"pr_change": 10},
        "versions": {
            "tapm": "0.1.0",
            "pytm": "0.3.0",
            "python": "3.11.8",
            "schema_version": "1",
            "prompt_version": "v1",
            "model": "simulated",
        },
    }

    txt = render_platform_report(sample_metrics, format="text")
    assert "PLATFORM OWNER REPORT" in txt
    assert "[SYSTEM & VERSIONS]" in txt
    assert "[RUNTIME SPLIT: LATENCY & CAPACITY]" in txt
    assert "[QUEUE & JOBS CAPACITY]" in txt
    assert "[AI EFFICIENCY & CACHING]" in txt


def test_render_platform_report_json():
    """Verify JSON format returns valid JSON identical to metrics."""
    sample_metrics = {"jobs_total": 5, "canary_status": "pass"}
    res = render_platform_report(sample_metrics, format="json")
    parsed = json.loads(res)
    assert parsed == sample_metrics


# -----------------------------------------------------------------------------
# Integration Tests: Service API & Client
# -----------------------------------------------------------------------------


def test_client_get_metrics_live_server(test_server, plan_cache_clean):
    """Client fetches /v1/metrics over HTTP and validates structure and updates."""
    client = AnalysisClient(server_url=test_server["url"], token=test_server["token"])

    # 1. Initial metrics
    m1 = client.get_metrics()
    assert m1["jobs_total"] == 0
    assert m1["canary_status"] == "pass"
    assert m1["versions"]["prompt_version"] == PROMPT_VERSION
    assert m1["versions"]["model"] == "test-model-v1"

    # 2. Submit a job with level, trigger, and upstream timings
    sub_res = client.run(
        plan=plan_cache_clean,
        repo="owasp/demo-repo",
        pr=42,
        sha="abc1234",
        level="validate",
        trigger="pr_change",
        plan_ms=450,
        scanners_ms=850,
    )
    assert sub_res.status == JobStatus.COMPLETED

    # 3. Fetch metrics again and assert counts updated
    m2 = client.get_metrics()
    assert m2["jobs_total"] == 1
    assert m2["jobs_by_status"].get("completed") == 1
    assert m2["jobs_by_level"].get("validate") == 1
    assert m2["triggers"].get("pr_change") == 1
    assert m2["jobs_by_verdict"].get("pass") == 1

    # Check runtime split includes plan, scanners, engine
    runtime = m2["runtime_split_ms"]
    assert runtime.get("plan") == 450
    assert runtime.get("scanners") == 850
    assert runtime.get("engine", 0) > 0


def test_metrics_auth_protection(test_server):
    """Unauthenticated request to /v1/metrics is rejected when token is configured."""
    unauth_client = AnalysisClient(server_url=test_server["url"], token=None)
    with pytest.raises(ClientError) as exc_info:
        unauth_client.get_metrics()
    assert exc_info.value.status_code == 401


# -----------------------------------------------------------------------------
# CLI Tests: tapm report
# -----------------------------------------------------------------------------


def test_cli_report_from_file(tmp_path, capsys):
    """Test tapm report reading from a metrics JSON file."""
    from tapm.cli import main

    metrics_file = tmp_path / "metrics.json"
    metrics_file.write_text(
        json.dumps(
            {
                "jobs_total": 15,
                "jobs_by_status": {"completed": 15},
                "jobs_by_verdict": {"pass": 15},
                "jobs_by_level": {"observe": 15},
                "queue_depth": 0,
                "queue_wait_ms_avg": 5.0,
                "queue_wait_ms_max": 12,
                "runtime_split_ms": {"plan": 300, "scanners": 600, "engine": 250, "ai": 800},
                "cache_hits": 6,
                "canary_status": "pass",
                "canaries_total": 10,
                "canaries_failed": 0,
                "triggers": {"pr_change": 15},
                "versions": {
                    "tapm": "0.1.0",
                    "pytm": "0.3.0",
                    "python": "3.11.8",
                    "schema_version": "1",
                    "prompt_version": "v1",
                    "model": "simulated",
                },
            }
        ),
        encoding="utf-8",
    )

    out_file = tmp_path / "report-platform.md"

    # Run CLI command writing to output file
    main(["report", "--persona", "platform", "--file", str(metrics_file), "--out", str(out_file)])
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "# Platform Owner Report: Analysis Service Operations" in content
    assert "Plan" in content
    assert "Engine" in content
