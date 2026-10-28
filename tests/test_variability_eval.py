"""Unit tests for AI repeated-run consistency evaluation (Task E3)."""

import json
from pathlib import Path

import pytest

from tapm.ai.llm import LLMResult, ScriptedLLM
from tapm.eval import variability

from conftest import DEMO, config_for


def test_simulated_backend_refusal():
    with pytest.raises(variability.NeedsRealModel):
        variability.make_run_llm({"llm": "simulated"}, "run00")
    # Allowed when explicitly configured
    llm = variability.make_run_llm({"llm": "simulated", "allow_simulated": True}, "run00")
    assert llm is not None


class InconsistentScriptedLLM:
    """A mock LLM that returns different statements on consecutive runs to test variability metrics."""

    def __init__(self, run_index: int):
        self.run_index = run_index
        self.name = "inconsistent-scripted"
        self.model = "test-model"

    def complete(self, agent: str, system: str, user: str, schema: dict, context: dict | None = None) -> LLMResult:
        from tapm.ai.agents import simulate

        base = json.loads(simulate(agent, context or {}))
        if agent == "path_narrator":
            base["statement"] = f"Variant {self.run_index}: " + base["statement"]
        elif agent == "framework_mapper":
            # Map subset of ground truth IDs (first 3)
            base["mappings"] = base["mappings"][:3]
            base["statement"] = f"Variant {self.run_index}: " + base["statement"]
        elif "statement" in base:
            base["statement"] = f"Variant {self.run_index}: " + base["statement"]

        text = json.dumps(base)

        return LLMResult(
            backend="scripted",
            model="test-model",
            text=text,
            latency_ms=100 + self.run_index * 10,
            input_tokens=150,
            output_tokens=50,
            stop_reason="stop",
        )


def test_variability_eval_metrics(tmp_path, monkeypatch):
    out_dir = tmp_path / "results"
    cfg = config_for(DEMO, tmp_path / "out")
    ai_cfg = {"llm": "anthropic", "jev": "local"}

    out = variability.run_variability_eval(
        DEMO,
        cfg,
        ai_cfg,
        n=3,
        out_dir=out_dir,
        tag="test",
        command="tapm variability 006 -n 3 --tag test",
        llm_factory=lambda i, s: InconsistentScriptedLLM(i),
    )

    s = out["summary"]
    assert s["runs"] == 3
    assert s["fixture"] == DEMO.name
    assert s["calls_per_path"] == 5
    assert s["cost_usd"] == 0.0
    assert s["unsupported_published"] == 0
    assert s["latency_ms"]["p50"] > 0
    assert s["latency_ms"]["p95"] >= s["latency_ms"]["p50"]

    # Verify per-annotation consistency
    per_ann = s["per_annotation"]
    assert "PATH-001:path_narrator" in per_ann
    pn = per_ann["PATH-001:path_narrator"]
    assert pn["distinct_texts"] == 3  # 3 distinct statements
    assert pn["modal_verdict"] == "accepted"
    assert pn["verdict_agreement"] == 1.0  # 100% agreement on accepted status

    # Verify framework mapping agreement vs ground truth
    assert "PATH-001:framework_mapper" in per_ann
    fm = per_ann["PATH-001:framework_mapper"]
    assert "T1190" in fm["ground_truth_ids"]
    assert "CWE-668" in fm["ground_truth_ids"]
    assert fm["mean_precision"] == 1.0  # All emitted IDs (T1190, CWE-668, SC-7) are in ground truth
    assert fm["mean_recall"] > 0.0      # Emitted 3 out of 8 ground truth IDs
    assert fm["mean_jaccard"] > 0.0

    # Verify markdown report was generated
    md_file = out_dir / "variability.md"
    assert md_file.exists()
    content = md_file.read_text(encoding="utf-8")
    assert "# AI Repeated-Run Consistency Evaluation" in content
    assert "PATH-001" in content
    assert "T1190" in content


def test_variability_write_results_and_provenance(tmp_path, monkeypatch):
    out_dir = tmp_path / "eval_results"
    cfg = config_for(DEMO, tmp_path / "out_det")
    ai_cfg = {"llm": "anthropic", "jev": "local"}

    out = variability.run_variability_eval(
        DEMO,
        cfg,
        ai_cfg,
        n=2,
        out_dir=out_dir,
        write_results=True,
        tag="prov-test",
        command="tapm variability 006 -n 2 --write-results --tag prov-test",
        llm_factory=lambda i, s: InconsistentScriptedLLM(i),
    )

    assert "metadata" in out
    assert "tool_versions" in out
    assert "git_sha" in out
    assert out["tag"] == "prov-test"

    out_file = Path(out["out_file"])
    assert out_file.exists()
    assert out_file.name == "ai-variability-prov-test.json"

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["fixture"] == DEMO.name
    assert "summary" in data
    assert "framework_mapping_agreement" in data["summary"]
