"""The study's scoring and statistics (paper/study/score.py), checked against hand-computed values."""

from __future__ import annotations

import importlib.util
import math

import pytest
import yaml

from conftest import ROOT

STUDY = ROOT / "paper" / "study"


@pytest.fixture(scope="module")
def score():
    spec = importlib.util.spec_from_file_location("study_score", STUDY / "score.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sign_test_is_exact(score):
    r = score.sign_test([1, 1, 1, 1, 1, -1, 0])  # zero differences are dropped
    assert (r["n"], r["positive"]) == (6, 5)
    assert r["p"] == pytest.approx(2 * (1 + 6) / 64)


def test_wilcoxon_normal_approximation(score):
    r = score.wilcoxon([1, 2, 3, 4, 5])
    assert r["w_plus"] == 15
    z = (15 - 7.5 - 0.5) / math.sqrt(5 * 6 * 11 / 24)
    assert r["z"] == pytest.approx(z, abs=1e-4)
    assert r["p"] == pytest.approx(math.erfc(z / math.sqrt(2)), abs=1e-6)


def test_holm_kappa_and_sus(score):
    assert score.holm({"a": 0.01, "b": 0.04}) == {"a": 0.02, "b": 0.04}
    assert score.cohen_kappa(["breaks", "breaks", "none", "none"], ["breaks", "none", "none", "none"]) == 0.5
    assert score.sus({f"sus_{i}": 3 for i in range(1, 11)}) == 50.0
    assert score.sus({**{f"sus_{i}": 5 for i in (1, 3, 5, 7, 9)}, **{f"sus_{i}": 1 for i in (2, 4, 6, 8, 10)}}) == 100.0


def test_scoring_against_the_generated_key(score):
    key = yaml.safe_load((STUDY / "answer-key.yaml").read_text())
    k1 = key["plan-1"]
    good = {"participant": "P01", "task": "plan-1", "condition": "C", "q1_found": "yes", "q1_target": "customer_data bucket",
            "q2_line": "iam.tf:27", "fix_code_r1": "breaks", "fix_code_r2": "breaks", "confidence": "4", "time_s": "300"}
    s = score.score_row(good, k1)
    assert (s["found"], s["located"], s["fixed"], s["score"]) == (True, True, 1.0, 2.0 + 1.0)
    bad = {**good, "q1_target": "reports", "q2_line": "providers.tf:1", "fix_code_r2": "none"}
    s = score.score_row(bad, k1)
    assert (s["found"], s["located"], s["fixed"]) == (False, False, None)  # coders disagree: adjudicate


def test_materials_hide_fixture_names_and_share_one_plan():
    for task in ("plan-1", "plan-2", "plan-3"):
        d = STUDY / "materials" / task
        texts = [(d / f"condition-{c}.md").read_text() for c in "ABC"]
        assert not any("fixture" in t.lower() or "public-workload" in t for t in texts)
        assert sorted(p.name for p in (d / "terraform").glob("*.tf"))
