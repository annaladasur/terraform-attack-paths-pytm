"""Tests for E6: Benign real-world modules evaluation (expect 0 false paths)."""

import json
from pathlib import Path

import pytest
import yaml

from tapm.eval.realworld import run_realworld
from tapm.util import PROJECT_ROOT

REALWORLD_CASES = [
    "realworld-vpc-complete",
    "realworld-security-group-complete",
    "realworld-s3-bucket-complete",
    "realworld-rds-complete",
    "realworld-iam-role",
]


def test_realworld_manifest_and_gold_files_exist():
    manifest_path = PROJECT_ROOT / "evaluations/realworld/manifest.yaml"
    assert manifest_path.exists(), "manifest.yaml missing"
    manifest = yaml.safe_load(manifest_path.read_text())
    case_ids = [c["id"] for c in manifest["cases"]]
    assert case_ids == REALWORLD_CASES

    for case in manifest["cases"]:
        gold_path = PROJECT_ROOT / "evaluations/realworld" / case["gold"]
        assert gold_path.exists(), f"Gold file missing: {gold_path}"
        gold = yaml.safe_load(gold_path.read_text())
        assert gold["case"] == case["id"]
        assert "expected" in gold
        assert len(gold["expected"]) >= 1
        for exp in gold["expected"]:
            assert exp["label"] == "INVALID", f"Benign cases must have INVALID expected reachability: {exp}"

        plan_gz = PROJECT_ROOT / "evaluations/realworld/plans" / f"{case['id']}.json.gz"
        assert plan_gz.exists(), f"Plan archive missing: {plan_gz}"

        base_dir = PROJECT_ROOT / "evaluations/realworld/baselines" / case["id"]
        assert (base_dir / "versions.json").exists(), f"Baselines missing: {base_dir}"


def test_realworld_evaluation_offline_replay(tmp_path: Path):
    """Runs realworld evaluation offline from committed plans and verifies zero false paths."""
    res = run_realworld(tag="test", manifest_name="manifest.yaml", out_dir=tmp_path)
    test_json = tmp_path / "realworld-test.json"
    assert test_json.exists()
    summary = res["summary"]
    assert summary["cases"] == 5
    assert summary["paths_emitted"] == 0
    assert summary["paths_scored"] == 0
    assert summary["paths_unadjudicated"] == 0
    assert summary["labeled_valid"] == 0
    assert summary["labeled_invalid"] == 5
    assert summary["tp"] == 0
    assert summary["fn"] == 0
    assert summary["fp"] == 0, f"Expected 0 false paths on benign modules, got {summary['fp']}"
    assert summary["tn"] == 5
    assert summary["false_path_rate"] is None
    assert summary["reachability_precision"] is None
    assert summary["reachability_recall"] is None

    for c in res["cases"]:
        assert c["paths"] == 0, f"Expected 0 paths for {c['id']}, found {c['paths']}"
        assert c["score"]["fp"] == 0
        assert c["score"]["tn"] == 1


def test_realworld_result_artifact_committed():
    result_path = PROJECT_ROOT / "evaluations/results/realworld-benign.json"
    assert result_path.exists(), "realworld-benign.json missing"
    data = json.loads(result_path.read_text())
    assert data["summary"]["cases"] == 5
    assert data["summary"]["tag"] == "benign"
    assert data["summary"]["fp"] == 0
    assert data["summary"]["false_path_rate"] is None
    assert data["summary"]["reachability_precision"] is None
    assert data["summary"]["reachability_recall"] is None
    assert data["summary"]["tn"] == 5


def test_realworld_in_results_markdown():
    results_md = PROJECT_ROOT / "evaluations/RESULTS.md"
    assert results_md.exists(), "RESULTS.md missing"
    text = results_md.read_text(encoding="utf-8")
    assert "## Benign real-world modules evaluation (E6)" in text
    assert "realworld-vpc-complete" in text
    assert "realworld-security-group-complete" in text
    assert "realworld-s3-bucket-complete" in text
    assert "realworld-rds-complete" in text
    assert "realworld-iam-role" in text
