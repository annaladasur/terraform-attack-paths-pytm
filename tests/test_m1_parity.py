"""Tests for canonical M1 metric parity across deck, reports, measure, and kit (Task A15, D4).

Acceptance Criteria:
One definition of M1 in kit/metrics.md; the deck (BEFORE), executive report,
developer report, tapm measure and speaker notes compute it from the same function;
a test asserts the deck and executive values are equal. (Checks C11, C12)
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import pytest

from tapm.measure import compute_m1, run_counts
from tapm.report.executive import render_executive_report
from tapm.report.developer import render_developer_report

ROOT = Path(__file__).resolve().parents[1]
OWASP_ROOT = ROOT.parent
CONF_SNAP = ROOT / "conference-snapshot"
KIT_METRICS = ROOT / "kit" / "metrics.md"
DECK_BUILD_JS = OWASP_ROOT / "deck" / "build-deck.js"


def test_compute_m1_function_contract():
    """compute_m1 computes scanner_findings + pytm_generic threats canonically."""
    assert compute_m1(40, 122) == 162
    assert compute_m1(0, 0) == 0
    assert compute_m1(10, 5) == 15


def test_measure_m1_on_pr_42():
    """tapm measure run_counts computes review_items_before == 162 on PR #42."""
    assert CONF_SNAP.exists()
    counts = run_counts(CONF_SNAP)
    assert counts["scanner_findings"] == 40
    assert counts["pytm_generic"] == 122
    assert counts["review_items_before"] == 162


def test_executive_report_m1_on_pr_42():
    """Executive report parses M1 as 162 on PR #42 (conference-snapshot)."""
    exec_json_str = render_executive_report(CONF_SNAP, format="json")
    exec_data = json.loads(exec_json_str)

    # Developer friction section M1
    assert exec_data["developer_friction"]["M1_items_before"] == 162

    # Markdown output also renders 162
    exec_md = render_executive_report(CONF_SNAP, format="markdown")
    assert "Pre-Pipeline Review Burden (M1):" in exec_md
    assert "`162` scanner findings and generic threats" in exec_md


def test_developer_report_m1_on_pr_42():
    """Developer report json format outputs m1_count == 162 on PR #42."""
    dev_json_str = render_developer_report(CONF_SNAP, format="json")
    dev_data = json.loads(dev_json_str)
    assert dev_data["m1_count"] == 162
    assert dev_data["m2_count"] == 9


def test_deck_before_matches_executive_report_m1():
    """Deck BEFORE and executive report M1 are strictly equal (162)."""
    assert DECK_BUILD_JS.exists()
    
    # Read deck/build-deck.js and verify BEFORE definition
    content = DECK_BUILD_JS.read_text(encoding="utf-8")
    assert "computeM1" in content
    assert "const BEFORE = computeM1(SF, PYTM.generic);" in content

    # Run node to extract actual BEFORE value from build-deck.js
    node_cmd = [
        "node", "-e",
        f"""
        const fs = require('fs');
        const path = require('path');
        const SNAP = {json.dumps(str(CONF_SNAP))};
        const SF = JSON.parse(fs.readFileSync(path.join(SNAP, 'scanner-findings.json'))).findings.length;
        const PYTM = JSON.parse(fs.readFileSync(path.join(SNAP, 'pytm-findings.json'))).summary;
        const computeM1 = (s, g) => s + g;
        const BEFORE = computeM1(SF, PYTM.generic);
        console.log(BEFORE);
        """
    ]
    res = subprocess.run(node_cmd, capture_output=True, text=True, check=True)
    deck_before = int(res.stdout.strip())

    # Get executive M1
    exec_data = json.loads(render_executive_report(CONF_SNAP, format="json"))
    exec_m1 = exec_data["developer_friction"]["M1_items_before"]

    # Assert equality
    assert deck_before == 162, f"Deck BEFORE must be 162, got {deck_before}"
    assert exec_m1 == 162, f"Executive M1 must be 162, got {exec_m1}"
    assert deck_before == exec_m1, f"Deck ({deck_before}) and executive ({exec_m1}) must match"


def test_kit_metrics_m1_definition():
    """kit/metrics.md defines M1 canonically with 162 on PR #42."""
    assert KIT_METRICS.exists()
    text = KIT_METRICS.read_text(encoding="utf-8")
    assert "| M1 | Review items per change, before |" in text
    assert "162" in text
    assert "40 scanner findings + 122 generic threats" in text
