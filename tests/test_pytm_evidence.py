"""pytm fed with plan evidence: controls with evidence, the cloud threat pack, overrides and finding classification."""

from __future__ import annotations

import pytest

from conftest import DEMO, FIXTURES, config_for

CLEAN = FIXTURES / "001-clean"
PUBLIC_S3 = FIXTURES / "002-public-s3"


@pytest.fixture(scope="module")
def pytm_runs(tmp_path_factory):
    """Full runs (pytm executed and classified) of the demo, the clean fixture and the public-bucket fixture."""
    from tapm.pipeline import run_deterministic

    out = {}
    for fx in (DEMO, CLEAN, PUBLIC_S3):
        out[fx.name[:3]] = run_deterministic(config_for(fx, tmp_path_factory.mktemp(fx.name[:3]), no_dfd=False))
    return out


def _rows(res, cls=None, threat=None):
    return [r for r in res.pytm["classification"]["findings"]
            if (cls is None or r["class"] == cls) and (threat is None or r["threat_id"] == threat)]


def test_generated_model_sets_decided_controls_with_their_evidence(demo_run):
    model = (demo_run.cfg.out_dir / "threat-model.py").read_text()
    # IMDS, the instance profile and the wildcard grant are facts from the plan, each with its evidence IDs
    assert "n_aws_instance_app.imdsV1Allowed = True  # TF-" in model
    assert "n_aws_instance_app.hasInstanceRole = True  # GRAPH-" in model
    assert "n_aws_s3_bucket_customer_data.readableViaWildcardGrant = True  # IAM-" in model
    # application-layer controls are never set: Terraform cannot decide them
    for undecidable in ("validatesInput", "sanitizesInput", "encodesOutput", "usesStrongSessionIdentifiers"):
        assert f".{undecidable} =" not in model
    # still plain pytm: no tapm import, loads the pinned library when it sits next to the file
    assert "import tapm" not in model and "from tapm" not in model
    assert "threat-library.json" in model


def test_pack_fires_on_the_demo_and_links_to_every_hop(pytm_runs):
    res = pytm_runs["006"]
    path = res.paths[0]
    confirmed = {r["threat_id"] for r in _rows(res, "confirmed")}
    assert {"TAPM-NET-01", "TAPM-EC2-01", "TAPM-IAM-01", "TAPM-IAM-02"} <= confirmed
    hops = {o["hop"] for r in _rows(res, "confirmed") for o in r.get("on_paths", []) if o["path"] == path.id}
    assert hops == set(range(1, len(path.hops) + 1))
    ec2 = _rows(res, "confirmed", "TAPM-EC2-01")[0]
    assert ec2["decided"]["imdsV1Allowed"]["evidence"] and ec2["undecided"] == []
    assert {"path": path.id, "hop": 3} in ec2["on_paths"]  # the ASSUMES hop


def test_clean_fixture_has_nothing_the_plan_confirms(pytm_runs):
    res = pytm_runs["001"]
    s = res.pytm["classification"]["summary"]
    assert s["confirmed"] == 0 and s["pack"] == 0
    assert s["ruled_out"] > 0  # the evidence disproves some generic threats


def test_block_public_access_becomes_a_mitigated_override(pytm_runs):
    res = pytm_runs["002"]
    by_bucket = {r["element"]: r["class"] for r in _rows(res, threat="TAPM-S3-01")}
    assert by_bucket["aws_s3_bucket.backups"] == "mitigated"
    assert by_bucket["aws_s3_bucket.exports"] == "confirmed"
    mitigated = _rows(res, "mitigated", "TAPM-S3-01")[0]
    assert "aws_s3_bucket_public_access_block.backups" in mitigated["override"]


@pytest.mark.parametrize("key", ["006", "001", "002"])
def test_classification_accounts_for_every_threat(pytm_runs, key):
    s = pytm_runs[key].pytm["classification"]["summary"]
    assert s["published"] == s["confirmed"] + s["mitigated"] + s["needs_app_team"]
    assert s["published"] == pytm_runs[key].pytm["threat_count"]  # pytm's own count
    # every generic threat is either still reported or ruled out; the evidence adds pack threats (and rarely others)
    assert s["published"] == s["generic"] - s["ruled_out"] + s["added_by_evidence"] + s["pack"]


def test_confirmed_means_evidence_decides_it(pytm_runs):
    for res in pytm_runs.values():
        for r in _rows(res, "confirmed"):
            assert r["decided"], r  # something from the plan
            assert all(v["evidence"] or v["basis"] for v in r["decided"].values())
        for r in _rows(res, "needs_app_team"):
            assert r["undecided"], r  # something Terraform cannot show


def test_pytm_artifacts_are_byte_stable(tmp_path):
    from tapm.pipeline import run_deterministic

    a = run_deterministic(config_for(DEMO, tmp_path / "a", no_dfd=False)).hashes
    b = run_deterministic(config_for(DEMO, tmp_path / "b", no_dfd=False)).hashes
    for k in ("threat-model.py", "pytm-controls.json", "threat-library.json", "pytm-findings.json", "seq.puml"):
        assert a[k] == b[k], k


def test_sequence_diagram_numbers_the_path_first(pytm_runs):
    seq = (pytm_runs["006"].cfg.out_dir / "seq.puml").read_text()
    assert "(1) HTTPS/443 (GRAPH-017)" in seq and "(2) HTTP/8080 (GRAPH-020)" in seq


@pytest.mark.parametrize("resource,wild", [
    ("*", True), ("arn:aws:s3:::*", True), ("arn:aws:s3:::*/*", True), ("arn:aws:s3:::data-*", True),
    ("arn:aws:s3:::customer-data/*", False), ("arn:aws:s3:::customer-data", False),
    ("arn:aws:dynamodb:us-east-1:111122223333:table/*", True),
    ("arn:aws:dynamodb:*:*:table/orders", False),
    ("tf:aws_s3_bucket.reports.arn/*", False), ("${aws_s3_bucket.reports.arn}/*", False),
])
def test_wildcard_resource(resource, wild):
    from tapm.pytm_gen.facts import wildcard_resource

    assert wildcard_resource(resource) is wild


def test_standalone_pytm_cli_gives_the_same_dfd_and_sequence(pytm_runs):
    """The pipeline renders in one interpreter; plain `python threat-model.py` must agree byte for byte."""
    import subprocess
    import sys

    from tapm.pytm_gen.runner import _portable_dot

    out = pytm_runs["006"].cfg.out_dir
    dfd = subprocess.run([sys.executable, "threat-model.py", "--dfd"], cwd=out, capture_output=True, text=True, check=True)
    seq = subprocess.run([sys.executable, "threat-model.py", "--seq"], cwd=out, capture_output=True, text=True, check=True)
    assert _portable_dot(dfd.stdout) == (out / "dfd.dot").read_text()
    assert seq.stdout == (out / "seq.puml").read_text()


def test_data_objects_carry_classification_and_credentials(pytm_runs):
    model = (pytm_runs["006"].cfg.out_dir / "threat-model.py").read_text()
    assert "Data('aws_s3_bucket.customer_data contents')" in model
    assert ".classification = Classification.SENSITIVE  # TF-" in model  # from the DataClassification tag
    assert ".credentialsLife = Lifetime.SHORT  # GRAPH-" in model  # instance-profile credentials
    assert "isPII: undecided from Terraform" in model  # never guessed


def test_the_credential_hop_is_drawn_and_numbered_in_path_order(pytm_runs):
    out = pytm_runs["006"].cfg.out_dir
    seq = (out / "seq.puml").read_text()
    assert "(3) role credentials for aws_iam_role.app (GRAPH-003)" in seq
    unwrap = lambda t: t.replace("\\n", "").replace("\n", "")  # noqa: E731 (pytm wraps long labels)
    overview = unwrap((out / "dfd-overview.dot").read_text())
    assert "IMDS ofaws_instance.app" in overview or "IMDS of aws_instance.app" in overview
    assert "aws_s3_bucket.customer_data" in overview
    assert "aws_s3_bucket.reports" not in overview  # level 0 is the attack path only
    assert "aws_s3_bucket.reports" in unwrap((out / "dfd.dot").read_text())
    assert "fillcolor" in (out / "dfd-risk.dot").read_text()  # pytm --colormap


def test_link_local_imds_is_not_a_network_sniffing_finding(pytm_runs):
    for key in ("006", "001"):
        rows = pytm_runs[key].pytm["classification"]["findings"]
        imds = [r for r in rows if r["element"].startswith("role credentials for")]
        assert imds and all(r["class"] != "confirmed" for r in imds if r["threat_id"] in ("DE03", "DE01"))
        assert any(r.get("assumption", "").startswith("IMDS is link-local") for r in imds)


def test_the_data_owner_gets_a_plain_question_and_the_answer_counts(tmp_path, pytm_runs):
    from tapm.pipeline import run_deterministic

    q = pytm_runs["006"].pytm["questions"]
    pii = [x for x in q["data_questions"] if x["control"] == "storesPII"]
    assert pii and pii[0]["element"] == "aws_s3_bucket.customer_data" and "personal data" in pii[0]["question"]
    f = tmp_path / "threat-answers.yaml"
    f.write_text("answers:\n  - element: aws_s3_bucket.customer_data\n    control: storesPII\n    answer: yes\n    by: data-owner\n")
    cfg = config_for(DEMO, tmp_path / "out", no_dfd=False)
    cfg.answers_file = f
    res = run_deterministic(cfg)
    model = (res.cfg.out_dir / "threat-model.py").read_text()
    assert "n_d_aws_s3_bucket_customer_data.isPII = True  # APP-001: answered by data-owner" in model
    assert [a["status"] for a in res.pytm["questions"]["answers"]] == ["applied"]
