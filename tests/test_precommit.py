"""Tests for Task A10: Pre-commitment verification for evaluation results (Check C8)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tapm.cli import build_parser
from tapm.eval.precommit import (
    verify_all_precommitments,
    verify_precommitment,
    verify_precommitment_cli,
)
from tapm.util import PROJECT_ROOT


def test_verify_precommitment_heldout():
    """Held-out results file provably satisfies all pre-commitment criteria."""
    result_path = PROJECT_ROOT / "evaluations/results/tier2-heldout.json"
    assert result_path.exists(), "tier2-heldout.json must exist"

    rep = verify_precommitment(result_path)
    _assert_history_or_snapshot(rep)
    assert rep.gold_unchanged
    assert rep.gold_commit == "2a199ec35131be87bfa0c489516aad5cb38187d4"
    assert rep.gold_files_count == 5


def test_verify_precommitment_realworld():
    """Benign real-world results file provably satisfies all pre-commitment criteria."""
    result_path = PROJECT_ROOT / "evaluations/results/realworld-benign.json"
    assert result_path.exists(), "realworld-benign.json must exist"

    rep = verify_precommitment(result_path)
    _assert_history_or_snapshot(rep)
    assert rep.gold_unchanged
    assert rep.gold_commit == "040096ad8d9bcf94563cbc7dbd29d2eb206bd067"
    assert rep.gold_files_count == 5


def test_verify_all_precommitments_default():
    """Default invocation verifies both committed evaluation results."""
    reports = verify_all_precommitments()
    assert len(reports) >= 2
    for rep in reports:
        _assert_history_or_snapshot(rep)
        assert rep.gold_unchanged


def test_verify_precommitment_detects_hash_mismatch(tmp_path: Path):
    """Tampering with gold file hash in results JSON fails verification."""
    result_path = PROJECT_ROOT / "evaluations/results/tier2-heldout.json"
    data = json.loads(result_path.read_text(encoding="utf-8"))

    # Corrupt first hash
    first_key = next(iter(data["gold_files"].keys()))
    data["gold_files"][first_key] = "0000000000000000000000000000000000000000000000000000000000000000"

    rep = verify_precommitment(data)
    assert not rep.passed
    assert not rep.gold_unchanged
    assert any("hash mismatch" in err for err in rep.errors)


def test_verify_precommitment_detects_non_ancestor(tmp_path: Path):
    """A fake or non-ancestor gold commit SHA fails verification."""
    result_path = PROJECT_ROOT / "evaluations/results/tier2-heldout.json"
    data = json.loads(result_path.read_text(encoding="utf-8"))

    # Use a dummy commit that is not an ancestor
    data["gold_commit"] = "0000000000000000000000000000000000000000"

    rep = verify_precommitment(data)
    assert not rep.passed
    assert not rep.is_ancestor
    assert any("not an ancestor" in err or "ancestry" in err for err in rep.errors)


def test_verify_precommitment_detects_impure_label_commit(tmp_path: Path):
    """If gold commit touched forbidden code files (e.g. src/), label purity check fails."""
    result_path = PROJECT_ROOT / "evaluations/results/tier2-heldout.json"
    data = json.loads(result_path.read_text(encoding="utf-8"))

    # Mock git diff-tree returning engine code touched in the label commit
    mock_files = (
        "OWASP-GLOBAL-AppSec-US-2026/terraform-attack-paths-pytm/evaluations/tier2/gold/foo.yaml\n"
        "OWASP-GLOBAL-AppSec-US-2026/terraform-attack-paths-pytm/src/tapm/engine.py\n"
    )
    with patch("subprocess.run") as mock_sub:
        def side_effect(cmd, **kwargs):
            import subprocess
            if "diff-tree" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=mock_files, stderr="")
            if "merge-base" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "diff" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_sub.side_effect = side_effect
        rep = verify_precommitment(data)
        assert not rep.passed
        assert not rep.label_commit_pure
        assert any("touched non-label path" in err for err in rep.errors)


def test_cli_verify_precommit():
    """CLI subcommands tapm eval verify-precommit and tapm verify-precommit execute successfully."""
    ret = verify_precommitment_cli(["--quiet"])
    assert ret == (1 if (PROJECT_ROOT / "release-manifest.json").exists() else 0)

    parser = build_parser()
    args_eval = parser.parse_args(["eval", "verify-precommit"])
    assert args_eval.cmd == "eval"
    assert args_eval.eval_action == "verify-precommit"

    args_direct = parser.parse_args(["verify-precommit"])
    assert args_direct.cmd == "verify-precommit"


def _assert_history_or_snapshot(rep):
    if (PROJECT_ROOT / "release-manifest.json").exists():
        assert not rep.passed
        assert not rep.is_ancestor
        assert not rep.label_commit_pure
        assert any("not an ancestor" in err for err in rep.errors)
        assert any("diff-tree failed" in err for err in rep.errors)
    else:
        assert rep.passed, rep.errors
        assert rep.is_ancestor
        assert rep.label_commit_pure
