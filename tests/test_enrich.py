"""Tests for Task W0.3: Model-free required check, asynchronous enrichment, AI cache, per-PR path cap.

Acceptance criteria:
1. tapm run --llm off runs the model-free required check;
2. tapm enrich <artifacts-dir> rebuilds bundles from evidence.json and attack-paths.json (never the plan);
3. Cache by bundle hash + prompt version + model;
4. Per-PR path cap enforced;
5. Gate output identical with and without enrichment;
6. Second enrichment of the same artifacts makes zero model calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tapm import PROMPT_VERSION
from tapm.ai.bundle import path_bundle, path_bundle_from_artifacts, path_bundles_from_artifacts
from tapm.ai.cache import AICache, CachedLLM
from tapm.ai.enrich import enrich_artifacts
from tapm.ai.llm import LLMResult, SimulatedLLM
from tapm.gate import evaluate, load_exceptions
from tapm.pipeline import RunConfig, run
from tapm.util import PROJECT_ROOT, dump_json


@pytest.fixture
def run_dir(tmp_path):
    fx = PROJECT_ROOT / "fixtures" / "006-public-workload-iam-sensitive-bucket"
    out = tmp_path / "artifacts"
    cfg = RunConfig(
        tf_dir=fx,
        plan_path=fx / "plan.json",
        baselines_dir=fx / "baselines",
        out_dir=out,
        name="006",
    )
    res = run(cfg)
    return out, res


def test_bundle_rebuild_from_artifacts_matches_live(run_dir):
    """Rebuilding bundle from artifacts produces identical dict and bundle_hash as live run."""
    out, res = run_dir
    live_bundle = path_bundle(res, res.paths[0], res.remedies)

    rebuilt_bundles = path_bundles_from_artifacts(out)
    assert len(rebuilt_bundles) == 1
    path_data, rebuilt_bundle = rebuilt_bundles[0]

    assert rebuilt_bundle["bundle_hash"] == live_bundle["bundle_hash"]
    assert rebuilt_bundle == live_bundle


def test_enrich_artifacts_never_reads_plan(run_dir, tmp_path):
    """enrich_artifacts works even when terraform-plan.json and plan.json do not exist."""
    out, _ = run_dir

    # Explicitly ensure no plan file exists in the artifacts directory
    if (out / "terraform-plan.json").exists():
        (out / "terraform-plan.json").unlink()
    assert not (out / "plan.json").exists()

    cache_dir = tmp_path / "cache"
    doc = enrich_artifacts(out, {"llm": "simulated", "cache_dir": str(cache_dir)})

    assert doc["manifest"]["llm_backend"] == "simulated"
    assert (out / "ai-annotations.json").exists()
    assert (out / "validation.json").exists()
    assert (out / "jev-decisions.json").exists()
    assert (out / "ai-metrics.json").exists()

    rep = (out / "report.md").read_text(encoding="utf-8")
    assert "## AI annotations (bounded, evidence-validated)" in rep
    assert doc["annotations"][0]["annotation_id"] in rep


def test_gate_output_identical_with_and_without_enrichment(run_dir, tmp_path):
    """Gate evaluation produces identical verdict and markdown/json with and without enrichment."""
    out, _ = run_dir

    ap_doc = json.loads((out / "attack-paths.json").read_text(encoding="utf-8"))
    entries, problems = load_exceptions(None)

    # Gate evaluation before enrichment
    g_before = evaluate(ap_doc["paths"], entries, level="validate", fail_on="high", file_problems=problems)
    dump_json(g_before, out / "gate.json")
    gate_json_before = (out / "gate.json").read_bytes()

    # Run asynchronous enrichment
    cache_dir = tmp_path / "cache"
    enrich_artifacts(out, {"llm": "simulated", "cache_dir": str(cache_dir)})

    # Gate evaluation after enrichment
    ap_doc_after = json.loads((out / "attack-paths.json").read_text(encoding="utf-8"))
    g_after = evaluate(ap_doc_after["paths"], entries, level="validate", fail_on="high", file_problems=problems)
    dump_json(g_after, out / "gate.json")
    gate_json_after = (out / "gate.json").read_bytes()

    assert g_before == g_after
    assert gate_json_before == gate_json_after


def test_second_enrichment_makes_zero_model_calls(run_dir, tmp_path):
    """Second enrichment of the same artifacts makes zero model calls and all cache hits."""
    out, _ = run_dir
    cache_dir = tmp_path / "ai_cache"

    # Wrap SimulatedLLM with a spy to count actual calls to the model
    base_llm = SimulatedLLM()
    spy_complete = MagicMock(side_effect=base_llm.complete)
    base_llm.complete = spy_complete

    # 1. First enrichment run
    doc1 = enrich_artifacts(out, {"cache_dir": str(cache_dir)}, llm=base_llm)
    first_model_calls = spy_complete.call_count
    assert first_model_calls > 0
    assert doc1["metrics"]["model_calls"] == first_model_calls
    assert doc1["metrics"]["cache_hits"] == 0

    # Reset spy counter
    spy_complete.reset_mock()

    # 2. Second enrichment run on the same artifacts
    doc2 = enrich_artifacts(out, {"cache_dir": str(cache_dir)}, llm=base_llm)
    second_model_calls = spy_complete.call_count
    assert second_model_calls == 0, f"Expected 0 model calls on second run, got {second_model_calls}"
    assert doc2["metrics"]["model_calls"] == 0
    assert doc2["metrics"]["cache_hits"] == first_model_calls


def test_per_pr_path_cap(run_dir, tmp_path):
    """Enrichment respects max_paths per-PR cap."""
    out, _ = run_dir

    # Duplicate path in attack-paths.json so there are 2 paths
    ap_path = out / "attack-paths.json"
    ap_doc = json.loads(ap_path.read_text(encoding="utf-8"))
    p1 = ap_doc["paths"][0]
    p2 = dict(p1)
    p2["id"] = "PATH-002"
    ap_doc["paths"].append(p2)
    ap_path.write_text(json.dumps(ap_doc, indent=2), encoding="utf-8")

    cache_dir = tmp_path / "cache_cap"

    # Test with max_paths = 1
    doc_cap1 = enrich_artifacts(out, {"llm": "simulated", "cache_dir": str(cache_dir), "max_paths": 1})
    decisions1 = doc_cap1["decisions"]
    assert len(decisions1) == 1
    assert decisions1[0]["subject"] == "PATH-001"

    # Test with max_paths = 2
    doc_cap2 = enrich_artifacts(out, {"llm": "simulated", "cache_dir": str(cache_dir), "max_paths": 2})
    decisions2 = doc_cap2["decisions"]
    assert len(decisions2) == 2


def test_ai_cache_key_invalidation(tmp_path):
    """Cache correctly keys on bundle_hash + prompt_version + model + agent."""
    cache = AICache(tmp_path / "cache")
    res = LLMResult("text", "simulated", "model-a")

    cache.put("hash1", "v1", "model-a", "path_narrator", res)

    # Exact match hits
    assert cache.get("hash1", "v1", "model-a", "path_narrator") is not None
    assert cache.hits == 1

    # Different model misses
    assert cache.get("hash1", "v1", "model-b", "path_narrator") is None
    # Different prompt version misses
    assert cache.get("hash1", "v2", "model-a", "path_narrator") is None
    # Different bundle hash misses
    assert cache.get("hash2", "v1", "model-a", "path_narrator") is None
    # Different agent misses
    assert cache.get("hash1", "v1", "model-a", "plain_explainer") is None
    assert cache.misses == 4


def test_cli_enrich_command(run_dir, tmp_path, capsys):
    """tapm enrich CLI subcommand runs cleanly and prints summary."""
    from tapm.cli import build_parser

    out, _ = run_dir
    cache_dir = tmp_path / "cli_cache"

    parser = build_parser()
    args = parser.parse_args(["enrich", str(out), "--llm", "simulated", "--cache-dir", str(cache_dir)])
    args.fn(args)

    captured = capsys.readouterr()
    assert "enriched" in captured.out
    assert "generated" in captured.out
    assert "model calls:" in captured.out


def test_enrich_missing_files_raises(tmp_path):
    """enrich_artifacts fails fast when artifacts directory is invalid."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    with pytest.raises(FileNotFoundError, match="Missing evidence.json"):
        enrich_artifacts(empty_dir)
