"""The v1-vs-v2 experiment's scoring, with a scripted (deliberately inconsistent) v1 model."""

import json
from pathlib import Path

import pytest

from tapm.ai.llm import ScriptedLLM
from tapm.eval import experiment

from conftest import DEMO, config_for

GOOD = {"elements": [{"id": "internet", "kind": "actor"}, {"id": "aws_lb.web", "kind": "process"}],
        "dataflows": [{"src": "Internet", "dst": "aws_lb.web", "label": "https"},
                      {"src": "aws_lb.web", "dst": "aws_instance.app", "label": "http"},
                      {"src": "aws_instance.app", "dst": "aws_s3_bucket.customer_data", "label": "read"}],
        "attack_paths": [{"nodes": ["internet", "aws_lb.web", "aws_instance.app", "aws_iam_role.app",
                                    "aws_s3_bucket.customer_data"], "description": "ssrf to s3"}],
        "summary": "SSRF to customer data"}
BAD = {"elements": [{"id": "aws_rds_cluster.orders", "kind": "datastore"}],
       "dataflows": [{"src": "internet", "dst": "aws_instance.app", "label": "ssh"},
                     {"src": "aws_instance.app", "dst": "aws_rds_cluster.orders", "label": "sql"}],
       "attack_paths": [{"nodes": ["internet", "aws_instance.app", "aws_rds_cluster.orders"], "description": "x"}],
       "summary": "database exposed"}


def test_simulated_backend_is_refused():
    with pytest.raises(experiment.NeedsRealModel):
        experiment.make_run_llm({"llm": "simulated"}, "run00")


def test_v1_variability_and_hallucination_are_measured(tmp_path, monkeypatch):
    outputs = iter([GOOD, BAD])
    monkeypatch.setattr(experiment, "make_run_llm",
                        lambda cfg, tag: ScriptedLLM({"v1_threat_model": json.dumps(next(outputs, GOOD))}))
    out = experiment.run_experiment(DEMO, config_for(DEMO, tmp_path), {"llm": "anthropic", "jev": "local",
                                                                       "cassette_dir": str(tmp_path)}, n=2)
    v1, v2 = out["v1"], out["v2"]
    assert v1["distinct_flow_sets"] == 2 and v1["distinct_path_sets"] == 2
    assert v1["hallucinated_resources"] == ["aws_rds_cluster.orders"]
    assert v1["runs_finding_the_deterministic_path_exactly"] == 1
    good, bad = v1["per_run"]
    assert good["flow_precision"] == 1.0 and good["unsupported_flows"] == []
    assert ["aws_instance.app", "internet"] in bad["unsupported_flows"]  # not directly exposed
    assert v2["deterministic_identical_runs"] == 2
    assert "| Distinct security results (flow sets) | 2/2 | 1/2 |" in (tmp_path / "experiment.md").read_text()


def test_experiment_write_results_and_metadata(tmp_path, monkeypatch):
    outputs = iter([GOOD, BAD])
    monkeypatch.setattr(experiment, "make_run_llm",
                        lambda cfg, tag: ScriptedLLM({"v1_threat_model": json.dumps(next(outputs, GOOD))}))
    out_dir = tmp_path / "results"
    out = experiment.run_experiment(
        DEMO,
        config_for(DEMO, tmp_path / "out"),
        {"llm": "anthropic", "jev": "local", "cassette_dir": str(tmp_path)},
        n=2,
        out_dir=out_dir,
        tag="test",
        command="tapm experiment 006 -n 2 --tag test",
    )
    assert "metadata" in out
    assert "tool_versions" in out
    assert "git_sha" in out
    assert out["tag"] == "test"
    assert out["v1"]["runs_with_hallucinated_resources_rate"] != "n/a"
    assert out["v2"]["deterministic_identical_rate"] != "n/a"

    out_file = Path(out["out_file"])
    assert out_file.exists()
    assert out_file.name == "experiment-test.json"
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["fixture"] == DEMO.name
    assert "v1" in data and "v2" in data
