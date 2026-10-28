"""pytm models the pipeline's own AI layer (pytm 1.4 LLM/Agent threats LLM01-LLM09)."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="module")
def ai_models(tmp_path_factory):
    from tapm.ai.self_model import run_ai_models

    return run_ai_models(tmp_path_factory.mktemp("ai-model"), "anthropic", "typesafe")


def test_this_pipeline_has_no_llm_threat_that_fires(ai_models):
    s = ai_models["summary"]["this_pipeline"]
    assert s["fires"] == 0
    by_id = {t["threat_id"]: t for t in ai_models["threats"]}
    assert set(by_id) == {f"LLM0{i}" for i in range(1, 10)}
    # the one open question is the decision provider's training, and it says so
    assert by_id["LLM04"]["this_pipeline_status"] == "depends"
    assert "provider" in by_id["LLM04"]["residual"]


def test_unsafe_design_fires_the_agency_and_injection_threats(ai_models):
    by_id = {t["threat_id"]: t for t in ai_models["threats"]}
    for tid in ("LLM01", "LLM03", "LLM05", "LLM06", "LLM09"):
        assert by_id[tid]["unsafe_design_status"] == "fires", tid


def test_every_decided_attribute_cites_what_enforces_it(ai_models):
    for t in ai_models["threats"]:
        for row in t["this_pipeline"]:
            for attr, f in row["decided"].items():
                assert f["evidence"], (t["threat_id"], attr)


def test_offering_the_model_a_tool_shows_up_as_a_threat(tmp_path):
    """A regression that gives the agents tools is a pytm finding, not just a failing boundary test."""
    from tapm.ai.self_model import _f, _this_pipeline, controls_json, explain_model, generate_model

    prof = _this_pipeline("anthropic", "local")
    for var, cls, name, facts, _ in prof["elements"]:
        if cls == "Agent":
            facts["usesExternalTools"] = _f(True, ["regression"], "an MCP server was added")
        if cls == "LLM":
            facts["hasAgentCapabilities"] = _f(True, ["regression"], "tools offered")
            facts["hasAccessToSensitiveSystems"] = _f(True, ["regression"], "the tool writes to the repository")
    (tmp_path / "threat-model.py").write_text(generate_model(prof))
    from tapm.util import dump_json

    dump_json(controls_json(prof), tmp_path / "pytm-controls.json")
    rows = explain_model(tmp_path / "threat-model.py", tmp_path / "pytm-controls.json", tmp_path / "x.json", ("LLM", "Agent"))
    status = {}
    for r in rows:
        status.setdefault(r["threat_id"], set()).add(r["status"])
    assert "depends" in status["LLM09"]  # tools, launch configuration not validated: undecided
    assert "depends" in status["LLM05"]  # agency + sensitive access; POLP undecided
    assert status["LLM01"] == {"cannot_fire"}  # filtering is unchanged


def test_self_model_is_plain_pytm_and_byte_stable(tmp_path):
    from tapm.ai.self_model import run_ai_models

    a = run_ai_models(tmp_path / "a")["hashes"]
    b = run_ai_models(tmp_path / "b")["hashes"]
    assert a == b
    src = (tmp_path / "a" / "this_pipeline" / "threat-model.py").read_text()
    assert "from pytm import" in src
    assert "import tapm" not in src and "from tapm" not in src
