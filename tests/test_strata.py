"""Tests for E7 strata re-cut (evaluations/results/strata.json).

Verifies accuracy across tiers (simple / medium / complex) and resource count
strata, asserting exact consistency with slide 14, Backup B14, and RESULTS.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tapm.eval.report import render
from tapm.eval.strata import compute_strata, generate_strata
from tapm.util import PROJECT_ROOT


RESULTS_DIR = PROJECT_ROOT / "evaluations" / "results"
STRATA_FILE = RESULTS_DIR / "strata.json"


@pytest.fixture(scope="module")
def strata_data() -> dict:
    if not STRATA_FILE.exists():
        generate_strata()
    return json.loads(STRATA_FILE.read_text(encoding="utf-8"))


def test_strata_json_exists_and_has_required_keys(strata_data: dict):
    assert STRATA_FILE.exists()
    assert strata_data["schema_version"] == 1
    assert strata_data["task"] == "E7"
    for section in ("by_tier", "by_resource_count", "by_repository", "headline_metrics", "feeds", "source_files"):
        assert section in strata_data, f"Missing {section} in strata.json"


def test_strata_generation_is_deterministic():
    computed = compute_strata()
    assert computed["by_tier"]["simple"]["cases_count"] == 21
    assert computed["by_tier"]["medium"]["cases_count"] == 8
    assert computed["by_tier"]["complex"]["cases_count"] == 2


def test_tier_simple_synthetic(strata_data: dict):
    simple = strata_data["by_tier"]["simple"]
    assert simple["cases_count"] == 21
    assert simple["resources"]["min"] == 5
    assert simple["resources"]["max"] == 25
    assert simple["resources"]["total"] == 305
    assert simple["ground_truth_paths"] == 14

    blind = simple["blind"]
    assert blind["tp"] == 14
    assert blind["fp"] == 0
    assert blind["fn"] == 0
    assert blind["precision"] == 1.0
    assert blind["recall"] == 1.0

    second = simple["second_run"]
    assert second["tp"] == 14
    assert second["fp"] == 0
    assert second["fn"] == 0
    assert second["precision"] == 1.0
    assert second["recall"] == 1.0


def test_tier_medium_cloudgoat(strata_data: dict):
    med = strata_data["by_tier"]["medium"]
    assert med["cases_count"] == 8
    assert med["resources"]["min"] == 5
    assert med["resources"]["max"] == 27
    assert med["resources"]["total"] == 126
    assert med["ground_truth_paths"] == 7

    # Blind first run: 2/7 recall (rollback, lambda_privesc found)
    blind = med["blind"]
    assert blind["tp"] == 2
    assert blind["fn"] == 5
    assert blind["fp"] == 0
    assert blind["recall_fraction"] == "2/7"
    assert round(blind["recall"], 4) == 0.2857
    assert blind["precision"] == 1.0

    # Second run: 7/7 recall (after general engine fixes)
    second = med["second_run"]
    assert second["tp"] == 7
    assert second["fn"] == 0
    assert second["fp"] == 0
    assert second["recall_fraction"] == "7/7"
    assert second["recall"] == 1.0
    assert second["precision"] == 1.0


def test_tier_complex_iam_vulnerable_and_terragoat(strata_data: dict):
    cpx = strata_data["by_tier"]["complex"]
    assert cpx["cases_count"] == 2
    assert cpx["resources"]["min"] == 64
    assert cpx["resources"]["max"] == 265
    assert cpx["resources"]["total"] == 329

    # Blind first run
    blind_iv = cpx["blind"]["iam_vulnerable"]
    assert blind_iv["resources"] == 265
    assert blind_iv["tp"] == 26
    assert blind_iv["fp"] == 4
    assert blind_iv["fn"] == 3
    assert blind_iv["tn"] == 1
    # 26 / (26 + 4) = 86.67% -> rounds to 87%
    assert round(blind_iv["precision"] * 100) == 87
    # 26 / (26 + 3) = 89.66% -> rounds to 90%
    assert round(blind_iv["recall"] * 100) == 90

    blind_tg = cpx["blind"]["terragoat"]
    assert blind_tg["resources"] == 64
    assert blind_tg["paths"] == 0
    assert blind_tg["fp"] == 0

    # Second run (after what-if fix)
    second_iv = cpx["second_run"]["iam_vulnerable"]
    assert second_iv["resources"] == 265
    assert second_iv["tp"] == 26
    assert second_iv["fp"] == 1
    assert second_iv["fn"] == 3
    assert second_iv["tn"] == 4
    # 26 / (26 + 1) = 96.3% -> rounds to 96%
    assert round(second_iv["precision"] * 100) == 96
    # 26 / (26 + 3) = 89.66% -> rounds to 90%
    assert round(second_iv["recall"] * 100) == 90
    assert second_iv["runtime_ms"] == 982


def test_resource_count_strata_partition(strata_data: dict):
    rc = strata_data["by_resource_count"]
    simple = rc["simple_le_12"]
    med = rc["medium_13_to_30"]
    cpx = rc["complex_gt_30"]

    # Partition is exhaustive over all 21 T1 fixtures + 10 T2 cases = 31 cases
    total_cases = simple["cases_count"] + med["cases_count"] + cpx["cases_count"]
    assert total_cases == 31

    assert simple["tier1_cases"] == 12
    assert len(simple["tier2_cases"]) == 2
    assert simple["blind"]["recall"] == 1.0

    assert med["tier1_cases"] == 9
    assert len(med["tier2_cases"]) == 6
    assert med["blind"]["tier2_only_recall"] == 0.0
    assert med["second_run"]["tier2_only_recall"] == 1.0

    assert cpx["cases_count"] == 2
    assert cpx["blind"]["tp"] == 26


def test_headline_metrics_match_deck_slide_14(strata_data: dict):
    hl = strata_data["headline_metrics"]
    assert hl["cloudgoat_medium_blind_recall_fraction"] == "2/7"
    assert hl["cloudgoat_medium_blind_recall_pct"] == 28.6
    assert hl["cloudgoat_medium_second_run_recall_fraction"] == "7/7"
    assert hl["cloudgoat_medium_second_run_recall_pct"] == 100.0
    assert hl["iam_vulnerable_complex_blind_precision_pct"] == 87
    assert hl["iam_vulnerable_complex_blind_recall_pct"] == 90
    assert hl["iam_vulnerable_complex_second_run_precision_pct"] == 96
    assert hl["iam_vulnerable_complex_second_run_recall_pct"] == 90
    assert hl["iam_vulnerable_complex_second_run_runtime_ms"] == 982


def test_cli_strata_command(tmp_path: Path):
    res = subprocess.run([sys.executable, "-m", "tapm.cli", "strata", "--json"], capture_output=True, text=True, check=True)
    parsed = json.loads(res.stdout)
    assert parsed["schema_version"] == 1
    assert parsed["task"] == "E7"

    out_file = tmp_path / "strata.json"
    subprocess.run([sys.executable, "-m", "tapm.cli", "strata", "--json", "--out", str(out_file)], capture_output=True, text=True, check=True)
    assert out_file.exists()
    parsed2 = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed2["schema_version"] == 1


def test_results_md_renders_accuracy_by_tier():
    content = render()
    assert "## Accuracy by tier (strata re-cut, E7)" in content
    assert "| Simple | 21 synthetic fixtures written by the engine author | 21 | 5–25 |" in content
    assert "| Medium | 8 public multi-resource privilege-escalation scenarios | 8 | 5–27 |" in content
    assert "100.0% / 28.6% (2/7)" in content
    assert "| Complex | Large-scale privilege escalation lab (265 resources)" in content
    assert "86.7% / 89.7%" in content
    assert "96.3% / 89.7%" in content


def test_tier_heldout_cloudgoat(strata_data: dict):
    ho = strata_data["by_tier"]["heldout"]
    assert ho["cases_count"] == 5
    assert ho["resources"]["min"] == 21
    assert ho["resources"]["max"] == 43
    assert ho["resources"]["total"] == 162
    assert ho["ground_truth_paths"] == 2
    assert ho["second_run"] is None

    blind = ho["blind"]
    assert blind["tp"] == 2
    assert blind["fp"] == 0
    assert blind["fn"] == 0
    assert blind["tn"] == 0
    assert blind["precision"] == 1.0
    assert blind["recall"] == 1.0
    assert blind["recall_fraction"] == "2/2"
    assert blind["paths_emitted"] == 9
    assert blind["paths_scored"] == 2
    assert blind["paths_unadjudicated"] == 0


def test_tier_benign_realworld(strata_data: dict):
    bn = strata_data["by_tier"]["benign"]
    assert bn["cases_count"] == 5
    assert bn["resources"]["min"] == 20
    assert bn["resources"]["max"] == 70
    assert bn["resources"]["total"] == 232
    assert bn["ground_truth_paths"] == 0
    assert bn["second_run"] is None

    blind = bn["blind"]
    assert blind["tp"] == 0
    assert blind["fp"] == 0
    assert blind["fn"] == 0
    assert blind["tn"] == 5
    assert blind["precision"] is None
    assert blind["recall"] is None
    assert blind["paths_emitted"] == 0


def test_strata_by_repository_has_heldout_and_benign(strata_data: dict):
    by_repo = strata_data["by_repository"]
    assert "cloudgoat_heldout" in by_repo
    assert by_repo["cloudgoat_heldout"]["cases"] == 5
    assert by_repo["cloudgoat_heldout"]["blind"]["tp"] == 2
    assert by_repo["cloudgoat_heldout"]["blind"]["fp"] == 0
    assert by_repo["cloudgoat_heldout"]["second_run"] is None

    assert "realworld_benign" in by_repo
    assert by_repo["realworld_benign"]["cases"] == 5
    assert by_repo["realworld_benign"]["blind"]["tn"] == 5
    assert by_repo["realworld_benign"]["blind"]["fp"] == 0
    assert by_repo["realworld_benign"]["second_run"] is None


def test_source_files_includes_heldout_and_benign(strata_data: dict):
    sf = strata_data["source_files"]
    assert "evaluations/results/tier2-heldout.json" in sf
    assert "evaluations/results/realworld-benign.json" in sf


def test_results_md_renders_heldout_and_benign_rows():
    content = render()
    assert "| Held-out | 5 unseen public privilege-escalation scenarios (commit 2a199ec) | 5 | 21–43 | 100.0% / 100.0% (2/2) | n/a (blind only) | 5/5 identical |" in content
    assert "| Benign | 5 public production-grade Terraform AWS modules | 5 | 20–70 | n/a / n/a (0/0) | n/a (0 FP, 0 emitted) | 5/5 identical |" in content

