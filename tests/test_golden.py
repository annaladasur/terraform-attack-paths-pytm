"""Golden tests: every fixture's graph and paths against its human-written gold labels."""

import pytest
import yaml

from tapm.eval.metrics import compare_fixture
from tapm.pipeline import run_deterministic

from conftest import config_for, fixture_dirs


@pytest.mark.parametrize("fx", fixture_dirs(), ids=lambda p: p.name)
def test_fixture_matches_gold(fx, tmp_path):
    gold = yaml.safe_load((fx / "gold.yaml").read_text())
    res = run_deterministic(config_for(fx, tmp_path))
    m = compare_fixture(res, gold)
    assert m["paths"]["fn_items"] == [], f"missed expected paths: {m['paths']['fn_items']}"
    assert m["paths"]["fp_items"] == [], f"unexpected paths: {m['paths']['fp_items']}"
    assert m["false_paths_found"] == [], f"reported a path gold marks as false: {m['false_paths_found']}"
    assert m["edges"]["fn_items"] == [], f"missed expected edges: {m['edges']['fn_items']}"
    assert m["edges"]["fp_items"] == [], f"unexpected edges of labeled types: {m['edges']['fp_items']}"
    for p in m["paths"]["matched"]:
        assert p["priority_ok"] and p["preconditions_ok"], p
