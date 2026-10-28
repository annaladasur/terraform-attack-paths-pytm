"""Terraform parsing: plan loading, reference resolution, source locations, comments."""

from tapm.terraform.offline_plan import source_key, strip_comments
from tapm.terraform.plan import load_plan
from tapm.terraform.sanitize import REDACTED, sanitize_plan
from tapm.terraform.source import SourceIndex, scan_text

from conftest import DEMO, FIXTURES


def test_plan_references_resolved_from_configuration():
    plan = load_plan(DEMO / "plan.json")
    inst = plan.get("aws_instance.app")
    assert inst.references["iam_instance_profile"] == ["aws_iam_instance_profile.app"]
    assert inst.references["vpc_security_group_ids"] == ["aws_security_group.app"]
    # security group -> security group reference exists only in configuration (unknown id at plan time)
    assert plan.get("aws_security_group.app").references["ingress"] == ["aws_security_group.alb"]


def test_unknown_values_are_recorded_not_guessed():
    plan = load_plan(DEMO / "plan.json")
    inst = plan.get("aws_instance.app")
    assert inst.is_unknown("arn") and inst.is_unknown("id")
    assert inst.values["metadata_options"][0]["http_tokens"] == "optional"


def test_source_locations():
    idx = SourceIndex.build(DEMO)
    assert idx.locate("aws_instance.app") == {"file": "app.tf", "start_line": 1, "end_line": 23}
    assert idx.locate_member("aws_security_group.alb", "ingress", "0.0.0.0/0") == {"file": "network.tf", "start_line": 72, "end_line": 78}
    assert idx.locate_member("aws_instance.app", "metadata_options")["start_line"] == 10


def test_scanner_handles_strings_heredocs_and_comments():
    src = '''# top
resource "aws_s3_bucket" "b" { # inline
  bucket = "a{b}#c" // not a comment start inside string? it is after the string
  policy = <<EOF
{ "x": "}" }
EOF
  /* block
     comment */
  tags = { Name = "${var.x}-{y}" }
}
'''
    sf = scan_text(src, "t.tf")
    assert [b.address for b in sf.blocks] == ["aws_s3_bucket.b"]
    assert sf.blocks[0].start == 2 and sf.blocks[0].end == 10
    texts = [c.text for c in sf.comments]
    assert "top" in texts and "inline" in texts and any("block" in t for t in texts)
    assert sf.comments[0].precedes == "aws_s3_bucket.b"


def test_comments_do_not_change_the_plan_cache_key():
    assert source_key(DEMO) == source_key(FIXTURES / "019-prompt-injection-comments")
    assert strip_comments('a = "x#y" # c\nb = 1 // d') == 'a = "x#y"\nb = 1'


def test_sanitizer_redacts_sensitive_values():
    raw = {
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_db_instance.d", "values": {"password": "hunter2", "port": 5432},
             "sensitive_values": {"password": True}}]}},
        "resource_changes": [{"address": "aws_db_instance.d", "change": {"after": {"password": "hunter2"},
                                                                          "after_sensitive": {"password": True}}}],
        "prior_state": {"values": {"secret": "x"}},
        "configuration": {"provider_config": {"aws": {"expressions": {"access_key": {"constant_value": "AKIA"}}}},
                          "root_module": {"variables": {"db_pw": {"sensitive": True, "default": "p"}}}},
        "variables": {"db_pw": {"value": "p"}},
    }
    s = sanitize_plan(raw)
    text = str(s)
    assert "hunter2" not in text and "AKIA" not in text and "prior_state" not in s
    assert s["planned_values"]["root_module"]["resources"][0]["values"]["password"] == REDACTED
    assert s["variables"]["db_pw"]["value"] == REDACTED


def test_committed_plans_match_their_sources():
    """Every fixture's plan.json was produced from its current sources, and the plan cache can serve it."""
    from tapm.terraform.offline_plan import CACHE_DIR

    for d in sorted(p for p in FIXTURES.iterdir() if (p / "plan.json").exists()) + [DEMO.parents[1] / "demo" / "base"]:
        key = source_key(d)
        assert (d / ".plan-source-key").read_text().strip() == key, f"{d.name}: stale .plan-source-key (tapm plan {d.name})"
        assert (CACHE_DIR / f"{key}.json").exists(), f"{d.name}: plan-cache entry missing"
