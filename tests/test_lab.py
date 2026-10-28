"""Audience lab: every named edit is pre-computed, and the re-planned result matches the what-if."""

import shutil

import pytest

from tapm import lab
from tapm.terraform.offline_plan import CACHE_DIR, plan_fixture, source_key

from conftest import DEMO, config_for


def workspace(tmp_path, *edits):
    d = tmp_path / "ws"
    d.mkdir(parents=True)
    for f in lab.tf_files(DEMO):
        shutil.copyfile(f, d / f.name)
    for e in edits:
        lab.apply_edit(d, e)
    return d


@pytest.mark.parametrize("edits", lab.variants(), ids=lambda v: "+".join(v))
def test_every_named_edit_is_precomputed(tmp_path, edits):
    d = workspace(tmp_path, *edits)
    key = source_key(d)
    assert (CACHE_DIR / f"{key}.json").exists() or (CACHE_DIR / f"{key}.json.gz").exists(), "run: tapm lab precompute"
    assert (lab.BASELINE_CACHE / f"{lab.raw_key(d)}.json.gz").exists(), "run: tapm lab precompute"


def test_cache_key_ignores_comments_formatting_and_trailing_commas(tmp_path):
    a = workspace(tmp_path / "a", "cidr=10.0.0.0/8", "policy=narrow")
    b = workspace(tmp_path / "b")
    net = (b / "network.tf").read_text()
    (b / "network.tf").write_text(net.replace('cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = [ "10.0.0.0/8" ]  # tightened', 1))
    iam = (b / "iam.tf").read_text()
    (b / "iam.tf").write_text(iam.replace('Resource = ["arn:aws:s3:::*"]',
                                          'Resource = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]'))
    assert source_key(a) == source_key(b)
    assert lab.raw_key(a) != lab.raw_key(b)


@pytest.mark.parametrize("edit,priority,pres", [
    ("imds=required", "medium", ["workload_rce"]),
    ("cidr=203.0.113.0/24", "medium", ["source_ip_allowed", "workload_ssrf"]),
    ("cidr=10.0.0.0/8", None, None),
    ("policy=narrow", None, None),
    ("alb=internal", None, None),
    ("classification=internal", None, None),
])
def test_replanned_edit_changes_the_path(tmp_path, edit, priority, pres):
    from tapm.pipeline import run_deterministic

    d = workspace(tmp_path, edit)
    info = plan_fixture(d, d / "plan.json", write_cache=False)
    assert info["source"] == "plan-cache"
    res = run_deterministic(config_for(d, tmp_path / "out"))
    if priority is None:
        assert res.paths == []
    else:
        assert [(p.priority, sorted(p.preconditions)) for p in res.paths] == [(priority, pres)]


def test_suppression_comments_silence_scanners_not_paths(tmp_path):
    from tapm.pipeline import run_deterministic

    d = workspace(tmp_path, "suppress")
    lab._restore_bundle(lab.BASELINE_CACHE / f"{lab.raw_key(d)}.json.gz", d / "baselines")
    plan_fixture(d, d / "plan.json", write_cache=False)
    res = run_deterministic(config_for(d, tmp_path / "out"))
    assert len(res.paths) == 1 and res.paths[0].priority == "high"
    assert res.paths[0].findings == []  # all seven causal findings suppressed
