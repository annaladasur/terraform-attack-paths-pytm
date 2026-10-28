"""Unit tests for Executive persona monthly one-pager generator (W3.4).

Verifies:
1. Executive posture scorecard with M3, M5, M6, M12, M8, M13;
2. Exposure and data store classification coverage denominator (Critic-B M6);
3. Coverage warning behavior when untagged/unclassified stores exist;
4. Review velocity and friction reduction (M1 vs M2, M7 verified-fix rate);
5. Risk governance register with owner, expiry countdown, and overdue alerts;
6. AI governance with 0 unsupported statements published (M13);
7. Financial cost model (CI compute + local/hosted model breakdown);
8. Adoption ladder progression (Levels 1-5 and next milestone);
9. Markdown, JSON, and Text formats;
10. CLI subcommand: tapm report --persona executive;
11. End-to-end pipeline generation of report-executive.md.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import pytest

from tapm import SCOPE_STATEMENT
from tapm.cli import main
from tapm.measure import summarize
from tapm.pipeline import run_deterministic
from tapm.report.executive import (
    DataStoreInfo,
    ExecutiveContext,
    ExecutiveException,
    load_executive_context,
    render_executive_json,
    render_executive_markdown,
    render_executive_report,
    render_executive_text,
)

ROOT = Path(__file__).resolve().parents[1]
CONF_SNAP = ROOT / "conference-snapshot"
TODAY = dt.date(2026, 10, 9)


def test_conference_snapshot_executive_markdown():
    """Verify all 6 Executive one-pager sections and M3 denominator in Markdown format."""
    assert CONF_SNAP.exists()
    report_md = render_executive_report(CONF_SNAP, format="markdown", today=TODAY)

    # Title & Canonical Scope Line
    assert "# Executive Monthly Security One-Pager: Attack Path & Infrastructure Risk" in report_md
    assert f"**Scope:** {SCOPE_STATEMENT}" in report_md
    assert "**Reporting Period:** October 2026" in report_md

    # Core Metric Note
    assert "**Core Executive Metric (M3 with Coverage):**" in report_md

    # Section 1: Scorecard
    assert "## 1. Security Posture & Exposure Scorecard" in report_md
    assert "| **M3: Open Attack Paths** | **1** |" in report_md
    assert "**100.0%** data stores classified (2/2)" in report_md
    assert "| **M5: Merged Without Decision** | **0** |" in report_md
    assert "| **M6: Accepted-Risk Coverage** | **100.0%** |" in report_md
    assert "| **M12: Accepted-Risk Hygiene** | **100.0%** |" in report_md
    assert "| **M8: False-Path Dispute Rate** | **0.0%** |" in report_md
    assert "| **M13: Unverified AI Statements** | **0** | **0** |" in report_md

    # Section 2: Coverage Denominator (The Critic-B Fix)
    assert "## 2. Exposure & Classification Coverage Denominator" in report_md
    assert "**100.0%** (2 of 2) of data stores have declared sensitivity levels" in report_md
    assert "| `aws_s3_bucket.customer_data` | `aws_s3_bucket` | `confidential` |" in report_md
    assert "| `aws_s3_bucket.reports` | `aws_s3_bucket` | `internal` |" in report_md
    assert "**Yes (Target)**" in report_md
    assert "100% of data stores in this workload have verified classification tags" in report_md

    # Section 3: Review Friction
    assert "## 3. Review Velocity & Developer Friction" in report_md
    assert "Pre-Pipeline Review Burden (M1):" in report_md
    assert "Curated First-Screen Items (M2):" in report_md
    assert "reduction** in review volume above the fold" in report_md
    assert "Verified Fix Rate (M7):" in report_md

    # Section 4: Risk Governance
    assert "## 4. Risk Governance & Exception Expiries" in report_md
    assert "RISK-042" in report_md
    assert "payments-platform" in report_md
    assert "2026-11-30" in report_md
    assert "Clean Exception Hygiene" in report_md

    # Section 5: AI & Financial Efficiency
    assert "## 5. AI Governance & Financial Efficiency" in report_md
    assert "Probabilistic Language, Deterministic Boundary" in report_md
    assert "Validator Integrity Audit (M13):" in report_md
    assert "**0** unverified statements published" in report_md
    assert "CI Pipeline Runtime (M14 p95):" in report_md
    assert "**$0.00 API charge** (executed on local Mac / host hardware)" in report_md
    assert "Total Monthly Projected Cost:" in report_md

    # Section 6: Adoption Ladder
    assert "## 6. Adoption Ladder Roadmap & Milestones" in report_md
    assert "**CURRENT ACTIVE LEVEL**" in report_md
    assert "**TARGET FOR NEXT SPRINT**" in report_md
    assert "Month 2 (Day 60): Promote to Level 3 (Validate)" in report_md


def test_coverage_denominator_gap_warning():
    """Verify that untagged/unclassified stores produce a prominent coverage warning."""
    ctx = ExecutiveContext(
        name="mixed-workload",
        month="October 2026",
        report_date="2026-10-09",
        m3_open_paths=1,
        total_data_stores=4,
        classified_data_stores=2,
        unclassified_data_stores=2,
        sensitive_data_stores=1,
        classification_coverage_pct=50.0,
        sensitive_coverage_pct=25.0,
        data_stores=[
            DataStoreInfo("bucket.tagged", "aws_s3_bucket", "confidential", "tag:Classification", True, True, True),
            DataStoreInfo("bucket.internal", "aws_s3_bucket", "internal", "tag:Classification", True, False, False),
            DataStoreInfo("bucket.untagged1", "aws_s3_bucket", "unclassified", "none", False, False, False),
            DataStoreInfo("bucket.untagged2", "aws_s3_bucket", "unclassified", "none", False, False, False),
        ],
    )
    md = render_executive_markdown(ctx)
    assert "**50.0%** data stores classified (2/4)" in md
    assert "Coverage Denominator Gap:" in md
    assert "2 data store(s) are currently unclassified" in md
    assert "Unclassified data stores do not trigger attack paths" in md


def test_executive_json_format():
    """Verify structured JSON output contains all scorecard, denominator, and governance keys."""
    json_str = render_executive_report(CONF_SNAP, format="json", today=TODAY)
    doc = json.loads(json_str)

    assert doc["report"] == "executive_monthly_one_pager"
    assert doc["name"] == "conference-snapshot"
    assert doc["month"] == "October 2026"
    assert doc["scope"] == SCOPE_STATEMENT

    # Scorecard
    sc = doc["scorecard"]
    assert sc["M3_open_attack_paths"] == 1
    assert sc["classification_coverage_pct"] == 100.0
    assert sc["M5_merged_without_decision"] == 0
    assert sc["M6_accepted_risk_coverage_pct"] == 100.0
    assert sc["M12_accepted_risk_hygiene_pct"] == 100.0
    assert sc["M8_false_path_rate_pct"] == 0.0
    assert sc["M13_unverified_ai_statements"] == 0

    # Denominator
    denom = doc["coverage_denominator"]
    assert denom["total_data_stores"] == 2
    assert denom["classified_data_stores"] == 2
    assert denom["unclassified_data_stores"] == 0
    assert len(denom["data_stores"]) == 2

    # Cost
    cost = doc["cost_and_efficiency"]
    assert cost["is_local_model"] is True
    assert cost["total_monthly_cost_usd"] > 0


def test_executive_text_format():
    """Verify terminal-friendly ASCII text output formatting."""
    txt = render_executive_report(CONF_SNAP, format="text", today=TODAY)

    assert "EXECUTIVE MONTHLY SECURITY ONE-PAGER" in txt
    assert "Period:  October 2026" in txt
    assert "M3 Open Attack Paths:          1" in txt
    assert "Classification Coverage (M3):  100.0% (2/2 data stores classified)" in txt
    assert "M5 Merged Without Decision:    0" in txt
    assert "M13 Unverified AI Statements:  0" in txt
    assert "STATUS:  100% of data stores classified. Denominator complete." in txt
    assert "ADOPTION LADDER: Level 2" in txt


def test_executive_report_with_summarize_dict():
    """Verify report generation when passed a tapm measure summarize dictionary."""
    summary = summarize([CONF_SNAP])
    report = render_executive_report(summary, format="markdown", today=TODAY)
    assert "# Executive Monthly Security One-Pager" in report
    assert "Pre-Pipeline Review Burden (M1):" in report
    assert "Curated First-Screen Items (M2):" in report


def test_executive_report_with_expired_and_urgent_exceptions():
    """Verify caution callouts when active exceptions are expired or expiring within 7 days."""
    ctx = ExecutiveContext(
        name="test-governance",
        month="October 2026",
        report_date="2026-10-09",
        exceptions=[
            ExecutiveException("RISK-EXP", "internet", "target.data", "sec-team", "Legacy bridge", "2026-10-01", -8, "expired", "accepted_risk"),
            ExecutiveException("RISK-SOON", "internet", "target.db", "app-team", "Migration", "2026-10-15", 6, "valid", "accepted_risk"),
        ],
        expired_exceptions_count=1,
        expiring_soon_count=1,
    )
    md = render_executive_markdown(ctx)
    assert "**Overdue Exceptions Detected:** 1 accepted risk(s) have expired" in md


def test_cli_report_persona_executive_markdown(capsys):
    """Verify tapm report --persona executive via CLI entry point."""
    main(["report", str(CONF_SNAP), "--persona", "executive"])
    out, _ = capsys.readouterr()
    assert "# Executive Monthly Security One-Pager" in out
    assert "**100.0%** data stores classified" in out


def test_cli_report_persona_executive_json(capsys):
    """Verify tapm report --persona executive --format json via CLI."""
    main(["report", str(CONF_SNAP), "--persona", "executive", "--format", "json"])
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["report"] == "executive_monthly_one_pager"
    assert doc["scorecard"]["M3_open_attack_paths"] == 1


def test_cli_report_persona_executive_out_file(tmp_path):
    """Verify tapm report --persona executive --out writes report to specified file."""
    out_file = tmp_path / "custom-executive.md"
    main(["report", str(CONF_SNAP), "--persona", "executive", "--out", str(out_file)])
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "# Executive Monthly Security One-Pager" in content


def test_pipeline_generates_report_executive(tmp_path):
    """Verify end-to-end pipeline run writes report-executive.md in out_dir."""
    from tapm.pipeline import run

    from conftest import DEMO, config_for

    cfg = config_for(DEMO, tmp_path / "exec-pipe-run")

    run(cfg)

    exec_file = Path(cfg.out_dir) / "report-executive.md"
    assert exec_file.exists(), "report-executive.md must be generated in out_dir"
    content = exec_file.read_text(encoding="utf-8")
    assert "# Executive Monthly Security One-Pager: Attack Path & Infrastructure Risk" in content
    assert "## 1. Security Posture & Exposure Scorecard" in content
    assert "## 2. Exposure & Classification Coverage Denominator" in content


def test_executive_exception_hygiene_derived_from_table():
    """Verify executive exception-hygiene note is derived from table (Task A21 / Check C13).

    Acceptance Criteria:
    - Executive exception-hygiene note derived from the table (RISK-042 has 51 days left; DISPUTE-001 never expires)
    - No hard-coded '≤ 30 days'
    """
    # On the audit date 2026-10-10: 2026-11-30 is exactly 51 days out
    audit_date = dt.date(2026, 10, 10)
    report_md = render_executive_report(CONF_SNAP, format="markdown", today=audit_date)
    assert "RISK-042 has 51 days left; DISPUTE-001 never expires" in report_md
    assert "≤ 30 days" not in report_md
    assert "<= 30 days" not in report_md

    # On snapshot date 2026-10-09: 2026-11-30 is 52 days out
    report_md_09 = render_executive_report(CONF_SNAP, format="markdown", today=TODAY)
    assert "RISK-042 has 52 days left; DISPUTE-001 never expires" in report_md_09
    assert "≤ 30 days" not in report_md_09
    assert "<= 30 days" not in report_md_09


def test_executive_exception_hygiene_injected_60_days_and_non_expiring_dispute():
    """Verify exception note dynamically derives injected 60-day exception and non-expiring dispute."""
    ctx = ExecutiveContext(
        name="custom-injection",
        month="October 2026",
        report_date="2026-10-09",
        exceptions=[
            ExecutiveException(
                id="RISK-060",
                entry="internet",
                target="aws_s3_bucket.secure_data",
                owner="payments-platform",
                reason="SDK upgrade migration window",
                expires="2026-12-08",
                days_left=60,
                state="valid",
                disposition="accepted_risk",
            ),
            ExecutiveException(
                id="DISPUTE-002",
                entry="internet",
                target="aws_s3_bucket.corp_vault",
                owner="core-infra",
                reason="Isolated VPC network without ingress route",
                expires=None,
                days_left=None,
                state="valid",
                disposition="not_reachable",
            ),
        ],
        expired_exceptions_count=0,
        expiring_soon_count=0,
    )
    md = render_executive_markdown(ctx)
    assert "RISK-060 has 60 days left; DISPUTE-002 never expires" in md
    assert "≤ 30 days" not in md
    assert "<= 30 days" not in md


def test_executive_exception_hygiene_zero_exceptions():
    """Verify clean note when zero exceptions exist."""
    ctx = ExecutiveContext(
        name="zero-exceptions",
        month="October 2026",
        report_date="2026-10-09",
        exceptions=[],
        expired_exceptions_count=0,
        expiring_soon_count=0,
    )
    md = render_executive_markdown(ctx)
    assert "No active exceptions or risk waivers on file for this workload." in md
    assert "≤ 30 days" not in md
    assert "<= 30 days" not in md

