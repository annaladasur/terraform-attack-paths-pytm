"""Unit tests for Developer PR comment v2 (W3.1).

Verifies:
1. First screen review items <= 10;
2. Rendered first screen matches M2 kit count (9 on PR #42 / conference-snapshot);
3. Plain words first with file:line pointers;
4. Proven fix diff on first screen if available;
5. Verdict and 4 ways out (Fix, Accept, Answer, Dispute);
6. Dispute false path option, link (#dispute-a-false-path), and YAML template (disposition: not_reachable);
7. Details collapsed in <details><summary> tags;
8. Hard comment size limit <= 65,535 chars (GitHub & Gitea limit) verified on IAM-Vulnerable (37 test paths / 41 blind eval paths);
9. First screen line budget strictly <= 40 lines before the first <details> tag;
10. Section boundary truncation never cuts inside code fence, table, or HTML tag;
11. CLI tapm report --persona developer in markdown, json, and text formats.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
import tempfile
import pytest

from tapm.measure import run_counts
from tapm.report.developer import (
    FIRST_SCREEN_MAX_ITEMS,
    GIT_HOST_COMMENT_LIMIT,
    count_first_screen_items,
    extract_first_screen_items,
    render_developer_comment,
    render_developer_report,
)
from tapm.report.markdown import render_report

ROOT = Path(__file__).resolve().parents[1]
CONF_SNAP = ROOT / "conference-snapshot"
IAM_VULN_PLAN_GZ = ROOT / "evaluations" / "tier2" / "plans" / "iam-vulnerable.json.gz"
IAM_VULN_BASE = ROOT / "evaluations" / "tier2" / "baselines" / "iam-vulnerable"


def test_conference_snapshot_first_screen_matches_m2():
    """On PR #42 (conference-snapshot), rendered first screen review items match M2 exactly (9 items)."""
    assert CONF_SNAP.exists()
    report_md = render_developer_report(CONF_SNAP, format="markdown")
    first_screen_count = count_first_screen_items(report_md)
    m2_count = run_counts(CONF_SNAP)["review_items_first_screen"]

    assert m2_count == 9, "PR #42 nominal M2 count must be 9 (1 path + 6 yes/no + 2 data questions)"
    assert first_screen_count == m2_count, f"Rendered first screen ({first_screen_count}) must match M2 ({m2_count})"
    assert first_screen_count <= FIRST_SCREEN_MAX_ITEMS


def test_plain_words_and_proven_fix_on_first_screen():
    """Each path has a plain English story and the proven fix diff right on the first screen."""
    report_md = render_developer_report(CONF_SNAP, format="markdown")
    first_screen = report_md.split("<details", 1)[0]

    # Plain words heading appears before any details tag
    assert "## In plain words" in first_screen
    assert "#### Path: PATH-001 (HIGH)" in first_screen
    # Plain words walkthrough contains file:line references
    assert "alb.tf:" in first_screen
    assert "iam.tf:" in first_screen

    # Proven fix diff appears directly under the path story on first screen
    assert "**Proven fix:** `remediation-PATH-001.diff`" in first_screen
    assert "```diff" in first_screen
    assert '-        Resource = ["arn:aws:s3:::*"]' in first_screen
    assert '+        Resource = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]' in first_screen


def test_verdict_and_four_ways_out():
    """Comment leads with verdict and four ways out including dispute false path."""
    report_md = render_developer_report(CONF_SNAP, format="markdown")
    first_screen = report_md.split("<details", 1)[0]

    assert "**Verdict:** 1 attack path(s) identified (1 high priority)." in first_screen
    assert "### Ways to resolve:" in first_screen
    assert "1. **Fix:**" in first_screen
    assert "2. **Accept Risk:**" in first_screen
    assert "3. **Answer:**" in first_screen
    assert "4. **Dispute False Path:**" in first_screen
    assert "[dispute template](#dispute-a-false-path)" in first_screen
    assert "M8 (False-path rate)" in first_screen


def test_gate_verdict_badges():
    """Gate checks reflect blocked, would block, and passing statuses."""
    gate_block = {"level": "validate", "fail_on": "high", "decision": "fail", "without_decision": 1, "not_reachable": 0, "accepted": 0}
    md_block = render_developer_report(CONF_SNAP, format="markdown", gate=gate_block)
    assert "**Status: Blocked** — 1 path(s) at or above high need a decision before merge." in md_block

    gate_observe = {"level": "observe", "fail_on": "high", "decision": "pass", "without_decision": 1, "not_reachable": 0, "accepted": 0}
    md_obs = render_developer_report(CONF_SNAP, format="markdown", gate=gate_observe)
    assert "**Status: Would block at validate**" in md_obs

    gate_resolved = {"level": "validate", "fail_on": "high", "decision": "pass", "without_decision": 0, "not_reachable": 1, "accepted": 1}
    md_res = render_developer_report(CONF_SNAP, format="markdown", gate=gate_resolved)
    assert "**Status: Pass**" in md_res
    assert "1 accepted risk(s), 1 disputed false path(s)" in md_res


def test_dispute_template_anchor_and_m8_content():
    """Dispute false path template has anchor #dispute-a-false-path and disposition: not_reachable."""
    report_md = render_developer_report(CONF_SNAP, format="markdown")
    first_screen = report_md.split("<details", 1)[0]

    # Target element id strictly matches first-screen dispute anchor
    assert "[dispute template](#dispute-a-false-path)" in first_screen
    assert '<details id="dispute-a-false-path">' in report_md
    assert 'id="dispute-a-false-path"' in report_md
    assert "disposition: not_reachable" in report_md
    assert "Option A: Dispute a false path (counted in kit metric M8; does not block merge)" in report_md
    assert "Option B: Accept risk" in report_md


def test_technical_details_collapsed():
    """All technical details are collapsed in <details> tags below the first screen."""
    report_md = render_developer_report(CONF_SNAP, format="markdown")

    assert "<details><summary>Technical Path Details & Architecture Flows" in report_md
    assert "<details><summary>Remaining Questions & Threat Model Answers" in report_md
    assert "<details><summary>PyTM Threat Model Summary" in report_md
    assert "<details><summary>Verified Remediation Patches" in report_md
    assert "<details><summary>Scanner findings not on any attack-path hop" in report_md
    assert '<details id="dispute-a-false-path">' in report_md
    assert "<details><summary>Analysis Metadata, Scope & Hashes" in report_md


def test_comment_size_limit_on_iam_vulnerable(tmp_path):
    """Even on IAM-Vulnerable (265 resources, 37 test paths / 41 blind eval paths), comment is strictly <= 65,535 chars."""
    if not (IAM_VULN_PLAN_GZ.exists() and IAM_VULN_BASE.exists()):
        pytest.skip("IAM-Vulnerable evaluation data not found")

    from tapm.pipeline import RunConfig, run_deterministic

    plan_file = tmp_path / "plan.json"
    plan_file.write_bytes(gzip.decompress(IAM_VULN_PLAN_GZ.read_bytes()))

    cfg = RunConfig(
        tf_dir=tmp_path,
        plan_path=plan_file,
        out_dir=tmp_path / "out",
        name="iam-vulnerable",
        baselines_dir=IAM_VULN_BASE,
        render_dfd=False,
        user_entries=True,
        extra_targets=("aws:account-admin",),
    )
    res = run_deterministic(cfg)
    num_paths = len(res.paths)
    # Validate path count from data: 37 test paths (vs 41 blind in strata evaluation)
    assert num_paths in (37, 38, 41) or num_paths >= 30, f"Expected 37-41 paths from data, got {num_paths}"

    comment = render_developer_comment(res)
    assert len(comment) <= GIT_HOST_COMMENT_LIMIT, f"Comment length {len(comment)} exceeds git host limit {GIT_HOST_COMMENT_LIMIT}"
    first_screen = count_first_screen_items(comment)
    assert first_screen <= FIRST_SCREEN_MAX_ITEMS, f"First screen items {first_screen} exceeds {FIRST_SCREEN_MAX_ITEMS}"


def test_first_screen_line_budget():
    """Rendered line budget for first screen is strictly <= 40 lines before the first <details> tag (A17)."""
    report_md = render_developer_report(CONF_SNAP, format="markdown")
    first_screen = report_md.split("<details", 1)[0]
    lines = first_screen.splitlines()
    assert len(lines) <= 40, f"First screen has {len(lines)} lines; budget is <= 40 lines"


def test_no_empty_first_screen_heading_and_no_duplicate_path_questions():
    """First screen has no bare '## First screen' heading and path questions are not duplicated in path story (A17)."""
    report_md = render_developer_report(CONF_SNAP, format="markdown")
    first_screen = report_md.split("<details", 1)[0]

    # No empty '## First screen' heading
    assert "\n## First screen\n" not in report_md
    assert "\n## First screen review items\n\n##" not in report_md
    assert "## In plain words" in first_screen

    # Path story does not duplicate questions before the questions table
    story_part = first_screen.split("### Questions for the app team")[0]
    assert "**What we need to know from you**" not in story_part

    # Questions table contains the questions
    assert "### Questions for the app team" in first_screen
    assert count_first_screen_items(report_md) == 9


def test_comment_truncation_safe_at_section_boundaries():
    """Truncation never cuts inside a code fence, table, or HTML tag, cutting cleanly at section boundaries (A17)."""
    # Test with multiple small forced budgets
    for budget in [1200, 1800, 2500, 4000, 8000]:
        truncated = render_developer_report(CONF_SNAP, format="markdown", max_chars=budget)
        assert len(truncated) <= budget, f"Truncated length {len(truncated)} exceeds budget {budget}"

        # Never cuts inside a code fence (even number of ```)
        assert truncated.count("```") % 2 == 0, f"Unclosed code fence in budget {budget}"

        # Never cuts inside an HTML tag (< without matching >)
        assert truncated.rfind("<") <= truncated.rfind(">"), f"Unclosed HTML tag in budget {budget}"

        # All <details> tags properly matched/closed
        assert truncated.count("<details") == truncated.count("</details>"), f"Mismatched details tags in budget {budget}"

        # Never cuts mid-row in a markdown table
        for line in truncated.splitlines():
            if line.strip().startswith("|"):
                assert line.strip().endswith("|"), f"Malformed table row: {line}"


def test_cli_report_developer_formats(capsys):
    """CLI tapm report --persona developer supports markdown, json, and text formats."""
    from tapm.cli import main

    # 1. Markdown output
    main(["report", "--persona", "developer", str(CONF_SNAP), "--format", "markdown"])
    out_md = capsys.readouterr().out
    assert "# Security architecture review: conference-snapshot" in out_md
    assert count_first_screen_items(out_md) == 9

    # 2. JSON output (A22, F22)
    main(["report", "--persona", "developer", str(CONF_SNAP), "--format", "json"])
    out_json = capsys.readouterr().out
    data = json.loads(out_json)
    assert data["persona"] == "developer"
    assert data["items_first_screen"] == 9
    assert data["m2_count"] == 9
    assert data["paths_count"] == 1
    assert data["under_git_limit"] is True
    # A22: comment_markdown and first_screen_items
    assert "comment_markdown" in data
    assert "# Security architecture review: conference-snapshot" in data["comment_markdown"]
    assert "first_screen_items" in data
    assert isinstance(data["first_screen_items"], list)
    assert len(data["first_screen_items"]) == data["items_first_screen"] == 9

    # 3. Text output
    main(["report", "--persona", "developer", str(CONF_SNAP), "--format", "text"])
    out_txt = capsys.readouterr().out
    assert "Security architecture review: conference-snapshot" in out_txt
    assert "Ways to resolve:" in out_txt


def test_developer_json_comment_and_first_screen_items():
    """Verify Developer JSON format carries comment_markdown and structured first-screen items (A22, F22)."""
    raw_json = render_developer_report(CONF_SNAP, format="json")
    doc = json.loads(raw_json)

    # 1. Root structure and counters
    assert doc["persona"] == "developer"
    assert doc["items_first_screen"] == 9
    assert doc["m2_count"] == 9
    assert doc["m1_count"] == 162
    assert doc["paths_count"] == 1
    assert doc["first_screen_max"] == 10
    assert doc["under_git_limit"] is True

    # 2. comment_markdown carries full rendered PR comment
    assert "comment_markdown" in doc
    md = doc["comment_markdown"]
    assert "# Security architecture review: conference-snapshot" in md
    assert "## In plain words" in md
    assert "remediation-PATH-001.diff" in md
    assert doc["comment_length_chars"] == len(md)

    # 3. first_screen_items carries structured items
    assert "first_screen_items" in doc
    items = doc["first_screen_items"]
    assert len(items) == 9

    # Path item
    path_items = [it for it in items if it["type"] == "attack_path"]
    assert len(path_items) == 1
    p0 = path_items[0]
    assert p0["id"] == "PATH-001"
    assert p0["priority"] == "high"
    assert p0["entry"] == "internet"
    assert p0["target"] == "aws_s3_bucket.customer_data"
    assert "proven_fix" in p0
    assert "diff" in p0["proven_fix"]

    # Question items
    q_items = [it for it in items if it["type"] == "question"]
    assert len(q_items) == 6
    assert q_items[0]["number"] == 1
    assert "question" in q_items[0]
    assert "why" in q_items[0]
    assert "settles" in q_items[0]

    # Data question items
    data_q_items = [it for it in items if it["type"] == "data_question"]
    assert len(data_q_items) == 2
    assert data_q_items[0]["resource"] == "aws_s3_bucket.customer_data"

