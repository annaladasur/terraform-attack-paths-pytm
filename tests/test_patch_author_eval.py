"""Unit tests for automated patch author evaluation (Task E8)."""

import json
from pathlib import Path

import pytest

from tapm.ai.llm import LLMResult
from tapm.eval import patch_author

from conftest import DEMO


def test_simulated_backend_refusal():
    with pytest.raises(patch_author.NeedsRealModel):
        patch_author.make_patch_author_llm({"llm": "simulated"}, "test-run")
    # Allowed when explicitly configured
    llm = patch_author.make_patch_author_llm({"llm": "simulated", "allow_simulated": True}, "test-run")
    assert llm is not None


class ScriptedPatchAuthorLLM:
    """Mock LLM returning deterministic patch proposals to test evaluation metrics and re-planning."""

    def __init__(self, fx_idx: int, path_idx: int):
        self.fx_idx = fx_idx
        self.path_idx = path_idx
        self.call_count = 0
        self.name = "scripted-patch-author"
        self.model = "test-qwen-model"

    def complete(self, agent: str, system: str, user: str, schema: dict, context: dict | None = None) -> LLMResult:
        self.call_count += 1
        bundle = (context or {}).get("bundle", {})
        attempts = bundle.get("previous_attempts", [])

        if self.call_count == 1:
            # First attempt: require IMDSv2 (proves downgrade)
            patch = {
                "hop": 3,
                "file": "app.tf",
                "find": '  metadata_options {\n    http_endpoint = "enabled"\n    http_tokens   = "optional"\n  }',
                "replace": '  metadata_options {\n    http_endpoint = "enabled"\n    http_tokens   = "required"\n  }',
                "rationale": "Require IMDSv2 on aws_instance.app [TF-004].",
                "evidence_refs": ["TF-004"],
                "confidence": 0.95,
            }
        else:
            # Second attempt: scope wildcard grant to non-sensitive reports bucket (proves break)
            patch = {
                "hop": 4,
                "file": "iam.tf",
                "find": '        Resource = ["arn:aws:s3:::*"]',
                "replace": '        Resource = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]',
                "rationale": "Scope wildcard grant to reports bucket only [IAM-001].",
                "evidence_refs": ["IAM-001"],
                "confidence": 0.95,
            }

        return LLMResult(
            backend="scripted",
            model="test-qwen-model",
            text=json.dumps(patch),
            latency_ms=1200 + self.call_count * 100,
            input_tokens=800,
            output_tokens=150,
            stop_reason="stop",
        )


def test_patch_author_eval_metrics(tmp_path):
    out_dir = tmp_path / "results"

    out = patch_author.run_patch_author_eval(
        fixtures=[DEMO],
        ai_cfg={"llm": "ollama", "model": "qwen3-coder:30b"},
        max_attempts=3,
        out_dir=out_dir,
        tag="test",
        command="tapm patch-author --fixtures 006 --tag test",
        llm_factory=lambda fi, pi: ScriptedPatchAuthorLLM(fi, pi),
    )

    s = out["summary"]
    assert s["fixtures_count"] == 1
    assert s["paths_attempted"] == 1
    assert s["verified_break"] == 1
    assert s["no_verified_fix"] == 0
    assert s["attempts_total"] == 2
    assert s["re_planned_proposals"] == 2
    assert s["re_planning_progressions"] == 1
    assert s["cost_usd"] == 0.0
    assert s["latency_ms"]["p50"] > 0
    assert s["latency_ms"]["p95"] >= s["latency_ms"]["p50"]

    # Verify per_fixture details
    pf = out["per_fixture"][DEMO.name]
    assert pf["paths_count"] == 1
    p0 = pf["paths"][0]
    assert p0["path"] == "PATH-001"
    assert p0["result"] == "PROVEN_BREAK"
    assert p0["recommended_attempt"] == 2
    assert len(p0["attempts"]) == 2
    assert p0["attempts"][0]["status"] == "PROVEN_DOWNGRADE"
    assert p0["attempts"][1]["status"] == "PROVEN_BREAK"

    # Verify markdown report
    md_file = out_dir / "patch-author-test.md"
    assert md_file.exists()
    content = md_file.read_text(encoding="utf-8")
    assert "# Automated Patch Author Evaluation (Local Model)" in content
    assert "PATH-001" in content
    assert "PROVEN_BREAK" in content


def test_patch_author_write_results_and_provenance(tmp_path):
    out_dir = tmp_path / "eval_results"

    out = patch_author.run_patch_author_eval(
        fixtures=[DEMO],
        ai_cfg={"llm": "ollama", "model": "qwen3-coder:30b"},
        max_attempts=2,
        out_dir=out_dir,
        write_results=True,
        tag="prov-test",
        command="tapm patch-author --fixtures 006 --write-results --tag prov-test",
        llm_factory=lambda fi, pi: ScriptedPatchAuthorLLM(fi, pi),
    )

    assert "metadata" in out
    assert "tool_versions" in out
    assert "git_sha" in out
    assert out["tag"] == "prov-test"

    out_file = Path(out["out_file"])
    assert out_file.exists()
    assert out_file.name == "patch-author-prov-test.json"

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "canonical_fixtures" in data
    assert DEMO.name in data["canonical_fixtures"]
    assert data["summary"]["verified_break"] == 1
