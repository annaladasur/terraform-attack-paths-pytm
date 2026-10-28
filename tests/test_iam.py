"""IAM policy semantics (the stated subset) and IAM-derived graph edges."""

from tapm.iam.policy import UNKNOWN, arn_matches, concretize, parse_document


def test_action_globs_are_case_insensitive():
    st = parse_document({"Statement": [{"Effect": "Allow", "Action": "S3:Get*", "Resource": "*"}]}).statements[0]
    assert st.matches_action("s3:GetObject") and not st.matches_action("s3:PutObject")


def test_not_action():
    st = parse_document({"Statement": [{"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}]}).statements[0]
    assert st.matches_action("s3:GetObject") and not st.matches_action("iam:PassRole")


def test_arn_matching_with_unknown_account_and_objects():
    assert arn_matches("arn:aws:s3:::*", "arn:aws:s3:::b/\x03object")
    assert arn_matches("arn:aws:s3:::b/*", "arn:aws:s3:::b/\x03object")
    assert not arn_matches("arn:aws:s3:::b", "arn:aws:s3:::b/\x03object")
    assert arn_matches("arn:aws:iam::111122223333:role/x", f"arn:aws:iam::{UNKNOWN}:role/x")
    assert not arn_matches("arn:aws:iam::111122223333:role/y", f"arn:aws:iam::{UNKNOWN}:role/x")


def test_symbolic_tokens_only_match_their_own_resource():
    assert concretize("tf:aws_s3_bucket.a.arn/*", "aws_s3_bucket.a", "name-a", "arn:aws:s3:::name-a") == "arn:aws:s3:::name-a/*"
    assert "\x01" in concretize("tf:aws_s3_bucket.a.arn", "aws_s3_bucket.b", "name-b", "arn:aws:s3:::name-b")


def test_demo_allows_edges_match_gold(demo_run):
    g = demo_run.build.graph
    allows = {(e.src, e.dst): e for e in g.edges_of("ALLOWS")}
    assert set(allows) == {("aws_iam_role.app", "aws_s3_bucket.customer_data"), ("aws_iam_role.app", "aws_s3_bucket.reports")}
    e = allows[("aws_iam_role.app", "aws_s3_bucket.customer_data")]
    assert e.data["actions"] == ["s3:GetObject", "s3:ListBucket"]
    assert e.data["access"] == ["list", "read"]


def test_instance_profile_role_is_assumable_with_imds_precondition(demo_run):
    [a] = demo_run.build.graph.edges_of("ASSUMES")
    assert (a.src, a.dst, a.precondition) == ("aws_instance.app", "aws_iam_role.app", "workload_ssrf")


def test_every_semantic_edge_cites_source_located_evidence(demo_run):
    recs = demo_run.build.ledger.by_id()
    for e in demo_run.build.graph.edges.values():
        if e.type == "DEPENDS_ON":
            continue
        assert e.evidence, e.key
        assert all(x in recs for x in e.evidence)
        assert any(recs[x].source for x in e.evidence), e.key
