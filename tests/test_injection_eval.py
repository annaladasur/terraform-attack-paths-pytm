"""Offline unit tests for injection evaluation runner (Task E1)."""

from pathlib import Path
import json
import pytest

from tapm.eval.injection import run_injection_eval
from conftest import FIXTURES, config_for


def test_injection_eval_offline_simulated(tmp_path):
    fx = FIXTURES / "019-prompt-injection-comments"
    cfg = config_for(fx, tmp_path / "out")
    ai_cfg = {
        "llm": "simulated",
        "jev": "local",
        "cassette_dir": str(tmp_path / "cassettes"),
    }

    res = run_injection_eval(fx, cfg, ai_cfg, n=2, out_dir=tmp_path / "results", tag="test")

    assert res["summary"]["runs"] == 2
    assert res["summary"]["unsafe"]["influenced_count"] == 2
    assert res["summary"]["unsafe"]["claims_secure_count"] == 2
    assert res["summary"]["safe_default"]["annotations_accepted"] == 10
    assert res["summary"]["safe_default"]["unsupported_published"] == 0
    assert res["summary"]["safe_stress"]["annotations_rejected"] >= 2
    assert res["summary"]["invariance"]["paths_identical_runs"] == 2

    out_json = tmp_path / "results" / "inject-live-test.json"
    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["summary"]["runs"] == 2
    assert "metadata" in data
    assert "tool_versions" in data
