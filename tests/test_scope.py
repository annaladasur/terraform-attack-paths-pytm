"""Verification of task W0.7: scope limit line in every output artifact.

Ensures that report.md, attack-paths.json, attack-paths.sarif, story.md,
iam-relationships.json, and threat-model.py all explicitly state that
SCPs, RCPs, and session policies are out of scope, and IAM Conditions
are flagged rather than evaluated.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from tapm import SCOPE_STATEMENT
from tapm.pipeline import run
from conftest import DEMO, config_for


_JARGON = re.compile(r"aws_\w+\.\w+|\b(?:GRAPH|IAM|TF|NET|SCAN|PATH|APP)-\d+|\.tf\b")


def test_canonical_scope_statement():
    """SCOPE_STATEMENT contains the required scope exclusions and conditions handling."""
    assert "SCPs, RCPs and session policies are out of scope" in SCOPE_STATEMENT
    assert "conditions are flagged, not evaluated" in SCOPE_STATEMENT
    assert "Terraform-visible" in SCOPE_STATEMENT


def test_all_output_artifacts_include_scope_statement(tmp_path):
    """Every generated artifact contains the scope line."""
    cfg = config_for(DEMO, tmp_path, no_dfd=False)
    res = run(cfg)

    out = Path(cfg.out_dir)

    # 1. report.md
    report_text = (out / "report.md").read_text()
    assert f"**Scope:** {SCOPE_STATEMENT}" in report_text

    # 2. attack-paths.json
    paths_data = json.loads((out / "attack-paths.json").read_text())
    assert paths_data.get("scope") == SCOPE_STATEMENT

    # 3. story.md
    story_text = (out / "story.md").read_text()
    assert f"**Scope:** {SCOPE_STATEMENT}" in story_text
    assert not _JARGON.search(SCOPE_STATEMENT)

    # 4. attack-paths.sarif
    sarif_data = json.loads((out / "attack-paths.sarif").read_text())
    run_obj = sarif_data["runs"][0]
    assert run_obj.get("properties", {}).get("scope") == SCOPE_STATEMENT
    assert run_obj["tool"]["driver"].get("properties", {}).get("scope") == SCOPE_STATEMENT
    for rule in run_obj["tool"]["driver"]["rules"]:
        assert rule.get("properties", {}).get("scope") == SCOPE_STATEMENT
        assert SCOPE_STATEMENT in rule.get("fullDescription", {}).get("text", "")
    for result in run_obj.get("results", []):
        assert result.get("properties", {}).get("scope") == SCOPE_STATEMENT

    # 5. iam-relationships.json
    iam_data = json.loads((out / "iam-relationships.json").read_text())
    assert iam_data.get("scope") == SCOPE_STATEMENT

    # 6. threat-model.py
    tm_text = (out / "threat-model.py").read_text()
    assert "SCPs, RCPs and session policies are out of scope" in tm_text

    # 7. run-manifest.json
    manifest_data = json.loads((out / "run-manifest.json").read_text())
    assert manifest_data.get("scope") == SCOPE_STATEMENT


def test_zero_paths_run_still_includes_scope(tmp_path):
    """When a plan has zero paths, artifacts (including story.md) still state scope."""
    # Run with empty extra targets or clean scenario
    from tapm.pipeline import run_deterministic
    from tapm.report.markdown import render_report
    from tapm.report.sarif import to_sarif
    from tapm.report.story import render_stories

    cfg = config_for(DEMO, tmp_path, no_dfd=True)
    res = run_deterministic(cfg)
    # Clear paths to simulate 0 paths
    res.paths = []

    # report.md
    rep = render_report(res)
    assert f"**Scope:** {SCOPE_STATEMENT}" in rep

    # story.md
    story = render_stories(res, "everyone")
    assert "No way in:" in story
    assert f"**Scope:** {SCOPE_STATEMENT}" in story

    # sarif
    sarif = to_sarif(res)
    assert sarif["runs"][0]["properties"]["scope"] == SCOPE_STATEMENT
    assert sarif["runs"][0]["tool"]["driver"]["properties"]["scope"] == SCOPE_STATEMENT
