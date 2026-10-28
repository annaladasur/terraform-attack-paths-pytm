"""Tests for metrics-sample.json and platform report real service run (Task A20, Findings F20, F39).

Acceptance Criteria:
/v1/metrics reports tapm, pytm, python, schema and prompt versions (no unknown);
a metrics-sample.json captured from tapm serve processing PR #42 and the canary is committed;
the report from it shows non-zero jobs and latencies; docs show --file usage. (Checks C10, C11)
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from tapm import PROMPT_VERSION, SCHEMA_VERSION, __version__
from tapm.cli import build_parser, main
from tapm.pytm_gen.generator import PYTM_VERSION
from tapm.report.platform import render_platform_report
from tapm.service.metrics import MetricsCollector
from tapm.service.server import create_server
from tapm.service.client import AnalysisClient

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATH = ROOT / "metrics-sample.json"
SNAP_SAMPLE_PATH = ROOT / "conference-snapshot" / "metrics-sample.json"


def test_metrics_sample_file_exists_and_valid():
    """Verify metrics-sample.json exists and is committed at repository root and snapshot."""
    assert SAMPLE_PATH.exists(), f"Missing {SAMPLE_PATH}"
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)

    assert SNAP_SAMPLE_PATH.exists(), f"Missing {SNAP_SAMPLE_PATH}"
    snap_data = json.loads(SNAP_SAMPLE_PATH.read_text(encoding="utf-8"))
    assert snap_data == data


def test_metrics_sample_contains_all_versions_no_unknown():
    """Verify /v1/metrics and sample report all versions with zero 'unknown' values (F20)."""
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    versions = data.get("versions", {})

    expected_keys = ["tapm", "pytm", "python", "schema_version", "prompt_version", "model"]
    for key in expected_keys:
        assert key in versions, f"Missing version key '{key}' in metrics-sample.json"
        val = str(versions[key]).strip()
        assert val != "", f"Empty version for '{key}'"
        assert val.lower() != "unknown", f"Version '{key}' must not be 'unknown' (F20)"

    # Specifically check pinned/known values
    assert versions["tapm"] == __version__
    assert versions["pytm"] == PYTM_VERSION
    assert versions["schema_version"] == SCHEMA_VERSION
    assert versions["prompt_version"] == PROMPT_VERSION


def test_metrics_sample_shows_non_zero_jobs_and_latencies():
    """Verify sample shows non-zero jobs and non-zero latencies across stages (A20 AC)."""
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))

    # Non-zero jobs
    assert data.get("jobs_total", 0) > 0, "jobs_total must be > 0"
    completed = data.get("jobs_by_status", {}).get("completed", 0)
    assert completed > 0, "completed jobs must be > 0"

    # Non-zero latencies across stages
    split = data.get("runtime_split_ms", {})
    for stage in ["plan", "scanners", "engine"]:
        assert split.get(stage, 0) > 0, f"Stage latency for '{stage}' must be > 0, got {split.get(stage)}"

    # Queue wait
    assert data.get("queue_wait_ms_avg", 0.0) > 0.0
    assert data.get("queue_wait_ms_max", 0) > 0

    # Canary runs
    assert data.get("canaries_total", 0) > 0, "canaries_total must be > 0"
    assert data.get("canaries_failed", 0) == 0, "canaries_failed should be 0 on healthy sample"
    assert data.get("canary_status") == "pass"


def test_platform_report_markdown_from_sample_has_no_unknown():
    """Verify platform markdown report rendered from sample contains no 'unknown' versions."""
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    md = render_platform_report(data, format="markdown")

    assert "# Platform Owner Report: Analysis Service Operations" in md
    assert "Canary Health (M15)" in md
    assert "Total Jobs Processed" in md
    assert "Runtime Split: Latency & Capacity" in md
    assert "`unknown`" not in md, f"Found '`unknown`' in markdown report:\n{md}"

    # Verify version table rows
    assert f"| `tapm` | `{__version__}` |" in md
    assert f"| `pytm` | `{PYTM_VERSION}` |" in md
    assert f"| `schema_version` | `{SCHEMA_VERSION}` |" in md
    assert f"| `prompt_version` | `{PROMPT_VERSION}` |" in md


def test_platform_report_text_from_sample_has_no_unknown():
    """Verify plain text platform report rendered from sample contains no 'unknown' versions."""
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    txt = render_platform_report(data, format="text")

    assert "PLATFORM OWNER REPORT" in txt
    assert "[SYSTEM & VERSIONS]" in txt
    assert "[RUNTIME SPLIT: LATENCY & CAPACITY]" in txt
    assert "unknown" not in txt.lower(), f"Found 'unknown' in text report:\n{txt}"


def test_cli_report_with_metrics_sample_file(capsys):
    """Test CLI invocation tapm report --persona platform --file metrics-sample.json (F39)."""
    # 1. Default markdown
    main(["report", "--persona", "platform", "--file", str(SAMPLE_PATH)])
    captured = capsys.readouterr()
    assert "# Platform Owner Report" in captured.out
    assert "`unknown`" not in captured.out

    # 2. Text format
    main(["report", "--persona", "platform", "--file", str(SAMPLE_PATH), "--format", "text"])
    captured = capsys.readouterr()
    assert "PLATFORM OWNER REPORT" in captured.out
    assert "unknown" not in captured.out.lower()

    # 3. JSON format
    main(["report", "--persona", "platform", "--file", str(SAMPLE_PATH), "--format", "json"])
    captured = capsys.readouterr()
    json_out = json.loads(captured.out)
    assert json_out["jobs_total"] >= 1
    assert json_out["versions"]["tapm"] == __version__


def test_live_metrics_collector_versions_no_unknown():
    """Verify live MetricsCollector initializes and exports zero 'unknown' versions."""
    mc = MetricsCollector()
    m = mc.get_metrics()
    v = m["versions"]

    assert v["tapm"] == __version__
    assert v["pytm"] == PYTM_VERSION
    assert v["schema_version"] == SCHEMA_VERSION
    assert v["prompt_version"] == PROMPT_VERSION
    assert v["model"] == "simulated"
    assert v["python"] != ""
    assert "unknown" not in [str(x).lower() for x in v.values()]
