"""The generated model is plain pytm and runs the same on pytm 1.4.0 and on pytm's main branch.

pytm main fixes two 1.4.0 bugs the model would otherwise hit (unreleased as of 2026-09-29):
#338 out-of-scope elements inherit other elements' findings in resolve(), #339 a finding override blanks the
threat fields it doesn't set. The generator avoids both, so `python threat-model.py --json` (what the tm_skills
agent skills run) gives correct output on either version.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from conftest import DEMO, FIXTURES, config_for


def _standalone_json(fx, tmp_path) -> dict:
    from tapm.pipeline import run_deterministic

    res = run_deterministic(config_for(fx, tmp_path, no_dfd=False))
    out = tmp_path / "standalone.json"
    subprocess.run([sys.executable, "threat-model.py", "--json", str(out)], cwd=res.cfg.out_dir, check=True,
                   capture_output=True, timeout=300)
    return json.loads(out.read_text())


def test_out_of_scope_imds_element_carries_no_findings(tmp_path):
    d = _standalone_json(DEMO, tmp_path)
    imds = [e for e in d["elements"] if e["name"].startswith("IMDS of")]
    assert imds and all(e["inScope"] is False and not e.get("findings") for e in imds)


def test_mitigated_override_keeps_the_threat_fields(tmp_path):
    d = _standalone_json(FIXTURES / "002-public-s3", tmp_path)
    [f] = [f for f in d["findings"] if f.get("response") == "mitigated"]
    assert f["threat_id"] == "TAPM-S3-01"
    assert f["description"] and f["severity"] == "High" and f["mitigations"] and f["likelihood"] == "High"


def test_open_questions_are_marked_in_the_tm_skills_convention(tmp_path):
    from tapm.pipeline import run_deterministic

    res = run_deterministic(config_for(DEMO, tmp_path, no_dfd=False))
    src = (res.cfg.out_dir / "threat-model.py").read_text()
    first = res.pytm["questions"]["questions"][0]
    assert f"# n_aws_instance_app.controls.{first['control']} = ?  # TODO - find the real value for this attribute (Q1: " in src
    assert "# n_d_aws_s3_bucket_customer_data.isPII = ?  # TODO" in src
    assert src.index("# TODO") < src.index('if __name__ == "__main__":')


@pytest.mark.parametrize("fx", [DEMO, FIXTURES / "021-passrole-escalation"], ids=["006", "021"])
def test_every_flow_and_element_records_its_terraform_source(fx, tmp_path):
    d = _standalone_json(fx, tmp_path)
    for x in d["flows"] + [e for e in d["elements"] if e.get("inScope", True) and e["name"] != "Internet client"]:
        if not x["name"].startswith(("Any AWS principal",)):
            assert all(p.endswith(".tf") for p in x.get("sourceFiles") or ["?.tf"]), x["name"]
