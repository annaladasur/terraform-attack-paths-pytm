"""Tests for E4: Held-out blind evaluation on 5 unused CloudGoat scenarios."""

import json
from pathlib import Path

import pytest
import yaml

from tapm.eval.tier2 import run_tier2
from tapm.util import PROJECT_ROOT

HELDOUT_CASES = [
    "cloudgoat-beanstalk_secrets",
    "cloudgoat-secrets_in_the_cloud",
    "cloudgoat-vpc_peering_overexposed",
    "cloudgoat-rds_snapshot",
    "cloudgoat-codebuild_secrets",
]


def test_heldout_manifest_and_gold_files_exist():
    manifest_path = PROJECT_ROOT / "evaluations/tier2/manifest-heldout.yaml"
    assert manifest_path.exists(), "manifest-heldout.yaml missing"
    manifest = yaml.safe_load(manifest_path.read_text())
    case_ids = [c["id"] for c in manifest["cases"]]
    assert case_ids == HELDOUT_CASES

    for case in manifest["cases"]:
        gold_path = PROJECT_ROOT / "evaluations/tier2" / case["gold"]
        assert gold_path.exists(), f"Gold file missing: {gold_path}"
        gold = yaml.safe_load(gold_path.read_text())
        assert gold["case"] == case["id"]
        assert "expected" in gold
        assert len(gold["expected"]) >= 1

        plan_gz = PROJECT_ROOT / "evaluations/tier2/plans" / f"{case['id']}.json.gz"
        assert plan_gz.exists(), f"Plan archive missing: {plan_gz}"

        base_dir = PROJECT_ROOT / "evaluations/tier2/baselines" / case["id"]
        assert (base_dir / "versions.json").exists(), f"Baselines missing: {base_dir}"


def test_heldout_evaluation_offline_replay(tmp_path: Path):
    """Runs tier2 on the held-out manifest offline from committed plans and verifies score."""
    res = run_tier2(tag="heldout-test", manifest_name="manifest-heldout.yaml", out_dir=tmp_path)
    test_json = tmp_path / "tier2-heldout-test.json"
    assert test_json.exists()
    summary = res["summary"]
    assert summary["cases"] == 5
    assert summary["paths_emitted"] == 9
    assert summary["paths_scored"] == 2
    assert summary["paths_unadjudicated"] == 0
    assert summary["labeled_valid"] == 2
    assert summary["labeled_invalid"] == 0
    assert summary["tp"] == 2
    assert summary["fn"] == 0
    assert summary["fp"] == 0
    assert summary["reachability_precision"] == 1.0
    assert summary["reachability_recall"] == 1.0


def test_heldout_result_artifact_committed():
    result_path = PROJECT_ROOT / "evaluations/results/tier2-heldout.json"
    assert result_path.exists(), "tier2-heldout.json missing"
    data = json.loads(result_path.read_text())
    assert data["summary"]["cases"] == 5
    assert data["summary"]["tp"] == 2
    assert data["summary"]["fp"] == 0
    assert data["summary"]["fn"] == 0
    assert data["summary"]["reachability_precision"] == 1.0
    assert data["summary"]["reachability_recall"] == 1.0
