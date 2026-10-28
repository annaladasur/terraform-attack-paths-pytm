"""Tests for who labeled the gold files (Task A28, which retracts the A27 agreement figures).

One person wrote every gold label and no second person has labeled any of them. These tests check that:
1. The labeling status is computed from the gold files: 63 labeled pairs in 20 files, 15 Tier-2 headers still
   saying "Reviewer 2: PENDING", 5 benign files with no Reviewer 2 field.
2. RESULTS.md reports one labeler and carries no agreement rate or kappa.
3. ADJUDICATION.md logs the 3 disputed labels and retracts the A27 agreement claim, with no unretracted figures.
4. No agreement statistic can come back while every gold file still says Reviewer 2 is pending.
5. Check C8 pre-commitment still holds: the gold files are unchanged.
"""

from __future__ import annotations

import re
import json

import pytest

from tapm.eval import report
from tapm.eval.precommit import verify_precommitment
from tapm.eval.report import compute_labeling_status
from tapm.util import PROJECT_ROOT

DISPUTED = [
    "module.privesc-paths.aws_iam_user.privesc9-AttachRolePolicy-user",
    "module.privesc-paths.aws_iam_user.privesc12-PutRolePolicy-user",
    "module.privesc-paths.aws_iam_user.privesc-AssumeRole-start-user",
]


def test_labeling_status_counts_come_from_gold_files():
    data = compute_labeling_status(PROJECT_ROOT)
    s = data["suites"]
    assert (s["tier2"]["files"], s["tier2"]["pairs"], s["tier2"]["pending"]) == (10, 50, 10)
    assert (s["heldout"]["files"], s["heldout"]["pairs"], s["heldout"]["pending"]) == (5, 8, 5)
    assert (s["benign"]["files"], s["benign"]["pairs"], s["benign"]["unrecorded"]) == (5, 5, 5)
    assert data["total"] == {"files": 20, "pairs": 63, "pending": 15, "unrecorded": 5}


def test_no_agreement_statistic_is_computed():
    assert not hasattr(report, "compute_reviewer_agreement")
    data = compute_labeling_status(PROJECT_ROOT)
    assert not {"kappa", "po", "pe", "agreed"} & (set(data) | set(data["total"]))


def test_results_markdown_reports_one_labeler_without_kappa():
    content = (PROJECT_ROOT / "evaluations/RESULTS.md").read_text(encoding="utf-8")
    assert "## Who labeled the gold files" in content
    assert "One labeler" in content
    assert "| **Total** | **20** | **63** | **15** | **5** |" in content
    # 0.9167 is not banned: it is also the real Tier-2 second-run recall (33/36).
    for claim in ("Cohen's kappa", "kappa =", "Inter-reviewer agreement", "independently reviewed", "60/63", "95.2%"):
        assert claim not in content, f"RESULTS.md still carries the retracted claim {claim!r}"


def test_adjudication_logs_disputes_and_retracts_agreement():
    content = (PROJECT_ROOT / "evaluations/tier2/ADJUDICATION.md").read_text(encoding="utf-8")
    for d in DISPUTED:
        assert d in content, f"Disputed entry {d} not documented in ADJUDICATION.md"
    assert "module.tool-testing.aws_iam_user.fp5-nonExploitableConditionConstraint-user" in content
    assert "### Retracted:" in content
    assert "Reviewer 2 confirmed" not in content
    assert "### Reviewer 2 disposition & confirmation (Task A27)" not in content
    # The retraction may quote the figures it retracts; nothing outside it may state them.
    before, _, _ = content.partition("### Retracted:")
    assert not re.search(r"kappa|60 ?/ ?63|95\.2", before, re.IGNORECASE)


def test_gold_headers_still_say_reviewer_2_pending():
    tier2 = sorted((PROJECT_ROOT / "evaluations/tier2/gold").glob("*.yaml"))
    assert tier2
    for p in tier2:
        assert "Reviewer 2: PENDING" in p.read_text(encoding="utf-8"), f"{p.name} header changed"


def test_gold_files_c8_precommitment_preserved():
    snapshot = PROJECT_ROOT / "release-manifest.json"
    for name in ("tier2-heldout.json", "realworld-benign.json"):
        result = verify_precommitment(PROJECT_ROOT / "evaluations/results" / name)
        assert result.gold_unchanged, result.errors
        if snapshot.exists():
            declaration = json.loads(snapshot.read_text())
            assert declaration["kind"] == "reviewed-source-snapshot"
            assert declaration["private_history_included"] is False
            assert declaration["historical_precommitment_independently_verifiable"] is False
            assert not result.passed
            assert not result.is_ancestor
            assert not result.label_commit_pure
            assert any("not an ancestor" in error for error in result.errors)
            assert any("diff-tree failed" in error for error in result.errors)
        else:
            assert result.passed, result.errors
            assert result.is_ancestor
            assert result.label_commit_pure


@pytest.mark.parametrize("name", ["tier2-heldout.json", "realworld-benign.json"])
def test_c8_rejects_tampered_frozen_label_hash_in_every_scope(name):
    data = json.loads((PROJECT_ROOT / "evaluations/results" / name).read_text())
    first = next(iter(data["gold_files"]))
    data["gold_files"][first] = "0" * 64
    result = verify_precommitment(data)
    assert not result.passed
    assert not result.gold_unchanged
    assert any("hash mismatch" in error for error in result.errors)
