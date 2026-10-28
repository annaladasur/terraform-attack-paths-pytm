"""Attack-path engine: the canonical demo path, labels, priority and computed remediation."""


def test_demo_has_exactly_one_high_priority_plausible_path(demo_run):
    [p] = demo_run.paths
    assert p.id == "PATH-001"
    assert p.nodes == ["internet", "aws_lb.web", "aws_instance.app", "aws_iam_role.app", "aws_s3_bucket.customer_data"]
    assert [h.status for h in p.hops] == ["FACT", "FACT", "ASSUMPTION", "FACT"]
    assert p.preconditions == ["workload_ssrf"]
    assert (p.priority, p.status) == ("high", "plausible")


def test_internal_bucket_is_not_a_target(demo_run):
    assert all(p.target != "aws_s3_bucket.reports" for p in demo_run.paths)


def test_what_if_is_computed_by_rerunning_the_engine(demo_run):
    eff = {r.hop: (r.effect, r.after) for r in demo_run.remedies}
    assert eff[1] == ("breaks_path", None)
    assert eff[3] == ("downgrades_path", "medium")
    assert eff[4] == ("breaks_path", None)


def test_scanner_findings_join_causal_hops(demo_run):
    p = demo_run.paths[0]
    causal = {f.rule_id for f in demo_run.findings if p.id in f.causal_paths}
    assert {"aws-ec2-no-public-ingress-sgr", "aws-ec2-enforce-http-token-imds", "aws-iam-no-policy-wildcards", "CKV_AWS_79"} <= causal
    # hygiene findings on the same resources are on the path but not causal
    assert "CKV_AWS_21" not in causal
