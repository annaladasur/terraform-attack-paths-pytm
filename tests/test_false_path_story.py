"""Tests for false-path story reconciliation on Slide 14 and B51 (Task A16, F13, F30, Checks C7, C12).

Acceptance Criteria:
Slide 14 and notes give blind numbers first (12.5% false paths on the first run;
medium 2/7; 13-30 band 0/6 Tier-2 blind), then held-out with its labeled n and
unadjudicated count; "7/7" never shown without "after fixes on the same set";
no "0 false paths" without its denominator.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import pytest

ROOT = Path(__file__).resolve().parents[1]
OWASP_ROOT = ROOT.parent
DECK_BUILD_JS = OWASP_ROOT / "deck" / "build-deck.js"
RESULTS_DIR = ROOT / "evaluations" / "results"
T2B_JSON = RESULTS_DIR / "tier2-first-run-combined.json"
HELDOUT_JSON = RESULTS_DIR / "tier2-heldout.json"
STRATA_JSON = RESULTS_DIR / "strata.json"


def test_blind_evaluation_baseline_numbers():
    """Verify underlying JSON data matches the expected blind story numbers."""
    assert T2B_JSON.exists()
    t2b = json.loads(T2B_JSON.read_text(encoding="utf-8"))
    summary = t2b["summary"]
    # 12.5% false paths on the first run (4 / (28 + 4) = 4 / 32 = 0.125)
    fp = summary["fp"]
    tp = summary["tp"]
    assert fp == 4
    assert tp == 28
    assert round(fp / (tp + fp), 4) == 0.125
    assert summary["reachability_precision"] == 0.875

    # Strata medium 2/7 blind and 13-30 band 0/6 Tier-2 blind
    assert STRATA_JSON.exists()
    strata = json.loads(STRATA_JSON.read_text(encoding="utf-8"))
    cg_blind = strata["by_repository"]["cloudgoat"]["blind"]
    assert cg_blind["recall"] == "2/7"
    assert cg_blind["tp"] == 2
    assert cg_blind["fn"] == 5

    band_13_30 = strata["by_resource_count"]["medium_13_to_30"]
    assert band_13_30["blind"]["tier2_only_recall"] == 0.0
    assert len(band_13_30["tier2_cases"]) == 6

    # Held-out evaluation
    assert HELDOUT_JSON.exists()
    heldout = json.loads(HELDOUT_JSON.read_text(encoding="utf-8"))
    h_sum = heldout["summary"]
    assert h_sum["labeled_valid"] == 2
    assert h_sum["tp"] == 2
    assert h_sum["fp"] == 0
    assert h_sum["paths_emitted"] == 9
    assert h_sum["paths_unadjudicated"] == 0


def test_slide_14_contains_blind_numbers_first_and_held_out():
    """Slide 14 and notes give blind numbers first, then held-out with labeled n and unadjudicated count."""
    assert DECK_BUILD_JS.exists()
    content = DECK_BUILD_JS.read_text(encoding="utf-8")

    # Locate Slide 14 block
    idx14 = content.find("// 14 ── Outline 5: measuring the results")
    assert idx14 != -1, "Could not find Slide 14 marker in build-deck.js"
    slide14_text = content[idx14:idx14 + 3500]

    # 1. Blind numbers first
    assert "12.5% false paths on the first run" in slide14_text
    assert "4/32" in slide14_text
    assert "medium" in slide14_text.lower()
    assert "2/7" in slide14_text or "${MED.tp}/${MED.tp + MED.fn}" in slide14_text
    assert "13–30 band 0/6 Tier-2 blind" in slide14_text or "13-30 band 0/6 Tier-2 blind" in slide14_text

    # 2. Held-out with labeled n and unadjudicated count
    assert "held-out" in slide14_text.lower()
    assert "labeled_valid" in slide14_text or "n = 2" in slide14_text
    assert "paths_emitted" in slide14_text or "9 emitted" in slide14_text
    assert "paths_unadjudicated" in slide14_text or "0 unadjudicated" in slide14_text

    # 3. 7/7 never shown without 'after fixes on the same set'
    assert "after fixes on the same set" in slide14_text


def test_b51_metrics_slide_reconciliation():
    """B51 gives blind numbers first, then held-out with labeled n and unadjudicated count."""
    assert DECK_BUILD_JS.exists()
    content = DECK_BUILD_JS.read_text(encoding="utf-8")

    # Locate B51 block
    idx_b51 = content.find('def("B51"')
    assert idx_b51 != -1, "Could not find B51 marker in build-deck.js"
    b51_text = content[idx_b51:idx_b51 + 3000]

    # 1. Blind numbers first
    assert "12.5% blind (4/32" in b51_text or "12.5% false paths on the first run" in b51_text
    assert "medium recall" in b51_text.lower()
    assert "13–30 band 0/6 Tier-2 blind" in b51_text or "13-30 band 0/6 Tier-2 blind" in b51_text

    # 2. Held-out with labeled n and unadjudicated count
    assert "held-out" in b51_text.lower()
    assert "labeled_valid" in b51_text or "n = 2" in b51_text
    assert "0 false among n =" in b51_text or "0 false paths among n =" in b51_text

    # 3. Table row M8 carries denominator
    assert '["M8 false-path rate (weekly sample)", "12.5% blind (4/32 real repos)", "< 10% before blocking"]' in content


def test_seven_of_seven_always_qualified_across_deck():
    """'7/7' is never shown anywhere in build-deck.js without 'after fixes on the same set'."""
    content = DECK_BUILD_JS.read_text(encoding="utf-8")

    # Check any occurrences of 7/7 or ${MED2.tp}/${MED2.tp + MED2.fn}
    matches = list(re.finditer(r"(7/7|\$\{MED2\.tp\}/\$\{MED2\.tp\s*\+\s*MED2\.fn\})", content))
    for m in matches:
        start = max(0, m.start() - 250)
        end = min(len(content), m.end() + 250)
        window = content[start:end]
        assert "after fixes on the same set" in window or "after general fixes, same set" in window, (
            f"Found unqualified 7/7 reference around position {m.start()}: {window}"
        )


def test_no_zero_false_paths_without_denominator():
    """'0 false paths' or '0 false' is never shown anywhere in build-deck.js without an explicit denominator."""
    content = DECK_BUILD_JS.read_text(encoding="utf-8")

    matches = list(re.finditer(r"0 false(?:\s+paths)?", content, re.IGNORECASE))
    for m in matches:
        start = max(0, m.start() - 100)
        end = min(len(content), m.end() + 150)
        window = content[start:end]
        has_denom = any(kw in window.lower() for kw in [
            "labeled", "records", "emitted", "denom", "among", "/"
        ])
        line_number = content[:m.start()].count("\n") + 1
        assert has_denom, f"Found '0 false paths' without denominator around line {line_number}: {window}"
