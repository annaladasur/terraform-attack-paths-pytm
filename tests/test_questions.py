"""Threat modeling as a few yes/no questions; answers become attested evidence and never change a path."""

from __future__ import annotations

import json

import pytest

from conftest import DEMO, ROOT, config_for

ANSWERS = ROOT / "demo" / "answers" / "threat-answers.yaml"


def _run(tmp, answers=None):
    from tapm.pipeline import run_deterministic

    cfg = config_for(DEMO, tmp, no_dfd=False)
    if answers is not None:
        cfg.answers_file = answers
    return run_deterministic(cfg)


@pytest.fixture(scope="module")
def unanswered(tmp_path_factory):
    return _run(tmp_path_factory.mktemp("q0"))


@pytest.fixture(scope="module")
def answered(tmp_path_factory):
    return _run(tmp_path_factory.mktemp("q1"), ANSWERS)


def test_a_few_questions_settle_many_threats_on_the_path(unanswered):
    q = unanswered.pytm["questions"]
    assert q["open"] == unanswered.pytm["classification"]["summary"]["needs_app_team"]
    top = q["questions"][:6]
    assert top[-1]["cumulative"] >= 30  # six questions settle a third of the open threats
    assert all(x["settles_on_path"] == x["settles"] for x in top)  # the path's elements first
    assert [x["cumulative"] for x in q["questions"]] == sorted(x["cumulative"] for x in q["questions"])
    for x in top:
        assert x["element"] in x["question"] and x["question"].endswith(("?", "?)"))
        assert x["why"]


def test_answers_become_attested_evidence_and_settle_threats(unanswered, answered):
    recs = [r for r in answered.build.ledger.records() if r.kind == "APP"]
    assert len(recs) == 6 and all(r.trust == "attested" for r in recs)
    assert recs[0].source["file"] == "threat-answers.yaml"
    model = (answered.cfg.out_dir / "threat-model.py").read_text()
    assert "n_aws_instance_app.controls.validatesInput = True  # APP-" in model
    before = unanswered.pytm["classification"]["summary"]
    after = answered.pytm["classification"]["summary"]
    assert after["needs_app_team"] < before["needs_app_team"]
    assert after["decided_by_answers"] > 0
    assert {a["status"] for a in answered.pytm["questions"]["answers"]} == {"applied"}


def test_answers_never_change_an_attack_path(unanswered, answered):
    for k in ("attack-paths.json", "resource-graph.json", "iam-relationships.json"):
        assert unanswered.hashes[k] == answered.hashes[k], k


def test_the_plan_wins_and_bad_answers_are_reported(tmp_path):
    f = tmp_path / "threat-answers.yaml"
    f.write_text("""answers:
  - element: aws_lb.web
    control: validatesHeaders
    answer: no
    by: someone
  - element: aws_s3_bucket.nope
    control: validatesInput
    answer: yes
  - element: aws_instance.app
    control: validatesInput
    answer: maybe
""")
    res = _run(tmp_path / "out", f)
    status = {(a["element"], a["control"]): a["status"] for a in res.pytm["questions"]["answers"]}
    assert status[("aws_lb.web", "validatesHeaders")].startswith("ignored: the plan decides")
    assert status[("aws_s3_bucket.nope", "validatesInput")].startswith("unknown element")
    assert status[("aws_instance.app", "validatesInput")].startswith("malformed")
    model = (res.cfg.out_dir / "threat-model.py").read_text()
    assert "n_aws_lb_web.controls.validatesHeaders = True  # TF-" in model  # plan evidence, not the answer


def test_answered_evidence_conforms_to_the_schema(answered):
    import jsonschema

    schema = json.loads((ROOT / "schemas" / "evidence.schema.json").read_text())
    doc = json.loads((answered.cfg.out_dir / "evidence.json").read_text())
    jsonschema.validate(doc, schema)
