"""V2 exact pair accounting, frozen-score compatibility and sealed evaluation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tapm.eval.tier2 import prediction_accounting, score


def result(*pairs, path_analysis=None):
    return SimpleNamespace(paths=[SimpleNamespace(entry=e, target=t) for e, t in pairs], path_analysis=path_analysis)


def gold(*rows):
    return {"expected": [{"entry": e, "target": t, "label": label} for e, t, label in rows]}


def test_existing_entry_new_target_cannot_escape_inventory():
    scored = score(result(("i", "a"), ("i", "b")), gold(("i", "a", "VALID")))
    assert scored["unlabeled_paths"] == ["i -> b"]
    assert scored["prediction_accounting"]["unique_predicted_pairs"] == 2
    assert scored["prediction_accounting"]["by_label"]["UNLABELED"] == 1
    assert [scored[key] for key in ("tp", "fn", "fp", "tn")] == [1, 0, 0, 0]


def test_duplicate_routes_count_once_without_changing_legacy_score():
    scored = score(result(("i", "a"), ("i", "a"), ("i", "b")), gold(("i", "a", "VALID")))
    accounting = scored["prediction_accounting"]
    assert accounting["unique_predicted_pairs"] == 2
    assert accounting["duplicate_routes"] == 1
    assert accounting["displayed_routes"] == 3
    assert accounting["inventory"][0]["routes"] == 2
    assert scored["tp"] == 1


def test_out_of_scope_unknown_and_unmatched_predictions_stay_visible():
    scored = score(result(("i", "oos"), ("i", "unknown"), ("i", "new")), gold(("i", "oos", "OUT_OF_SCOPE")),
                   adjudications=[{"entry": "i", "target": "unknown", "label": "UNKNOWN", "reason": "Runtime input absent."}])
    accounting = scored["prediction_accounting"]
    assert accounting["by_label"] == {"VALID": 0, "INVALID": 0, "OUT_OF_SCOPE": 1, "UNKNOWN": 1, "UNLABELED": 1}
    assert accounting["unadjudicated_pairs"] == 2
    assert accounting["coverage_score"]["precision"] is None
    assert accounting["coverage_score"]["precision_denominator"] == 0
    assert accounting["coverage_score"]["recall"] is None
    assert scored["out_of_scope_found"] == 1


def test_exact_adjudication_never_matches_prefix_or_cross_pair():
    adjudications = [{"entry": "i", "target": "b", "label": "VALID", "reason": "Exact pair only."}]
    scored = score(result(("i", "b-extra"), ("prefix-i", "b")), gold(), adjudications=adjudications)
    assert scored["prediction_accounting"]["by_label"]["UNLABELED"] == 2
    assert scored["prediction_accounting"]["coverage_score"]["fn"] == 1


def test_unrecognized_gold_label_remains_an_accounted_unknown():
    scored = score(result(("i", "a")), gold(("i", "a", "PENDING_REVIEW")))
    accounting = scored["prediction_accounting"]
    assert accounting["by_label"]["UNKNOWN"] == 1
    assert accounting["inventory"][0]["original_label"] == "PENDING_REVIEW"
    assert sum(accounting["by_label"].values()) == accounting["unique_predicted_pairs"] == 1
    assert scored["out_of_scope_found"] == 1  # historical scorer's else branch retained


def test_structured_adjudication_augments_coverage_but_preserves_gold_metrics():
    scored = score(result(("i", "a"), ("i", "b"), ("i", "c")), gold(("i", "a", "VALID"), ("i", "negative", "INVALID")),
                   adjudications=[{"entry": "i", "target": "b", "label": "VALID", "reason": "Declared additional relationship."},
                                  {"entry": "i", "target": "c", "label": "INVALID", "reason": "Declared forbidden relationship."}])
    assert [scored[key] for key in ("tp", "fn", "fp", "tn")] == [1, 0, 0, 1]
    coverage = scored["prediction_accounting"]["coverage_score"]
    assert (coverage["tp"], coverage["fp"], coverage["fn"]) == (2, 1, 0)
    assert (coverage["precision_numerator"], coverage["precision_denominator"]) == (2, 3)
    assert (coverage["recall_numerator"], coverage["recall_denominator"]) == (2, 2)


@pytest.mark.parametrize("label", ["VALID", "INVALID", "UNKNOWN"])
def test_adjudication_cannot_override_frozen_out_of_scope(label):
    with pytest.raises(ValueError, match="cannot override"):
        score(result(("i", "b")), gold(("i", "b", "OUT_OF_SCOPE")), adjudications=[
            {"entry": "i", "target": "b", "label": label, "reason": "A proposal cannot rewrite gold."}])


@pytest.mark.parametrize("adjudication", [
    {"entry": "i", "target": "b", "label": "CORRECT", "reason": "Not a structured label."},
    {"entry": "i", "target": "b", "label": "VALID"},
    {"entry": "i", "label": "VALID", "reason": "No exact target."},
])
def test_malformed_adjudication_fails_loudly(adjudication):
    with pytest.raises(ValueError, match="adjudication requires"):
        score(result(("i", "b")), gold(), adjudications=[adjudication])


def test_verified_reachable_pair_is_inventoried_even_when_display_cap_hides_it():
    verification = {"reachability": {"complete": False, "pairs": [
        {"entry": "i", "target": "a", "reachable": True},
        {"entry": "i", "target": "b", "reachable": True},
        {"entry": "i", "target": "unknown", "reachable": None}]}}
    scored = score(result(("i", "a"), path_analysis=verification), gold(("i", "a", "VALID"), ("i", "b", "VALID")))
    accounting = scored["prediction_accounting"]
    assert (scored["tp"], scored["fn"]) == (1, 1)  # legacy displayed-output numerator/denominator
    assert (accounting["coverage_score"]["tp"], accounting["coverage_score"]["fn"]) == (2, 0)
    assert accounting["undisplayed_reachable_pairs"] == 1
    assert accounting["verification_complete"] is False
    assert accounting["verification_unknown_pairs"] == 1
    assert accounting["duplicate_routes"] == 0


def test_gold_duplicate_routes_do_not_duplicate_pair_coverage():
    scored = score(result(("i", "a")), gold(("i", "a", "VALID"), ("i", "a", "VALID")))
    assert scored["tp"] == 2  # compatibility with historical gold-row score
    assert scored["prediction_accounting"]["coverage_score"]["tp"] == 1


def test_tier2_ignores_prose_substrings_and_supports_exact_adjudications(tmp_path, monkeypatch):
    import tapm.eval.tier2 as tier2
    manifest = {"repos": {"fixture": {"url": "https://invalid.example/repo", "commit": "a" * 40, "license": "CC0"}},
                "cases": [{"id": "case", "repo": "fixture", "path": ".", "gold": "gold.yaml"}]}
    (tmp_path / "manifest.yaml").write_text(json.dumps(manifest))
    (tmp_path / "gold.yaml").write_text(json.dumps(gold(("i", "a", "VALID"))))
    (tmp_path / "ADJUDICATION.md").write_text("i -> b; i and b also occur separately. This prose is not an exact structured adjudication.")
    (tmp_path / "sources" / "case").mkdir(parents=True)
    base = tmp_path / "baselines" / "case"
    base.mkdir(parents=True)
    (base / "versions.json").write_text("{}")
    res = result(("i", "a"), ("i", "b"))
    res.build = SimpleNamespace(graph=SimpleNamespace(nodes={}, edges={}), unresolved_policies=[])
    res.findings = []
    monkeypatch.setattr(tier2, "T2", tmp_path)
    monkeypatch.setattr(tier2, "case_plan", lambda *args: tmp_path / "plan.json")
    monkeypatch.setattr(tier2, "validate_baseline", lambda *args: None)
    monkeypatch.setattr(tier2, "run_deterministic", lambda *args: res)
    first = tier2.run_tier2(out_dir=tmp_path / "out")
    assert first["summary"]["paths_unadjudicated"] == 1
    second = tier2.run_tier2(out_dir=tmp_path / "out", adjudications={"case": [
        {"entry": "i", "target": "b", "label": "VALID", "reason": "Exact supplemental record."}]})
    assert second["summary"]["paths_unadjudicated"] == 0
    assert first["summary"]["tp"] == second["summary"]["tp"] == 1
    assert first["summary"]["paths_scored"] == second["summary"]["paths_scored"] == 1


def runner_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "evaluate-v2.py"
    spec = importlib.util.spec_from_file_location("evaluate_v2", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_supplemental_expectations_and_inputs_match_preexecution_seal():
    protocol, checks = runner_module().verify_seal()
    assert len(checks) == 28
    assert protocol["historical_context"]["original_blind"]["precision"] == [28, 32]
    assert protocol["historical_context"]["historical_same_corpus_retest"]["precision"] == [33, 34]
    assert "known-input" in protocol["evaluation_class"]


def test_supplemental_seal_rejects_modified_input(tmp_path):
    module = runner_module()
    protocol = json.loads((module.SUITE / "protocol.json").read_text())
    protocol["sealed_files"]["scripts/evaluate-v2.py"] = "0" * 64
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(protocol))
    with pytest.raises(ValueError, match="sealed input changed"):
        module.verify_seal(path)


def test_zero_sample_wilson_interval_is_not_perfect_accuracy():
    module = runner_module()
    assert module.wilson(0, 0) is None
    lo, hi = module.wilson(2, 2)
    assert 0 < lo < 1 and hi == 1


def test_runner_rejects_frozen_output_before_executing_checks(monkeypatch):
    module = runner_module()
    monkeypatch.setattr(module, "verify_seal", lambda: pytest.fail("must reject before engine/input access"))
    with pytest.raises(ValueError, match="must not be inside frozen"):
        module.run(module.ROOT / "evaluations" / "results" / "nested")
