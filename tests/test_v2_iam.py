"""V2 IAM adversarial cases, kept separate from the frozen evaluation corpus.

Expected outcomes follow AWS explicit Deny precedence and permissions-boundary
intersection rules, not the previous engine output:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
"""

import json

import pytest

from tapm.graph.build import build_graph
from tapm.graph.model import ANY_PRINCIPAL
from tapm.paths.engine import PathOptions, analyze_paths, find_paths
from tapm.gate import evaluate as evaluate_gate
from tapm.terraform.plan import parse_plan


BUCKET = "aws_s3_bucket.data"
USER = "aws_iam_user.actor"
OBJECTS = "arn:aws:s3:::v2-confidential-data/*"
BOUNDARY = "arn:aws:iam::123456789012:policy/boundary"
CONDITION = {"Bool": {"aws:SecureTransport": "false"}}


def resource(address, **values):
    kind, name = address.split(".")
    return {"address": address, "mode": "managed", "type": kind, "name": name, "values": values}


def document(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def statement(effect="Allow", action="s3:GetObject", **extra):
    return {"Effect": effect, "Action": action, "Resource": OBJECTS, **extra}


def build(tmp_path, identity=(), boundary=None, public=(), principal=USER, unknown_boundary=False,
          resources=(), reverse_resources=False):
    values = {"name": "actor"}
    if boundary is not None or unknown_boundary:
        values["permissions_boundary"] = None if unknown_boundary else BOUNDARY
    rs = [resource(BUCKET, bucket="v2-confidential-data", tags={"DataClassification": "confidential"}),
          resource(principal, **values)]
    if identity:
        kind = "aws_iam_role_policy" if principal.startswith("aws_iam_role.") else "aws_iam_user_policy"
        member = "role" if kind == "aws_iam_role_policy" else "user"
        rs.append(resource(f"{kind}.actor", **{member: "actor", "policy": document(identity)}))
    if boundary is not None:
        rs.append(resource("aws_iam_policy.boundary", name="boundary", policy=document(boundary)))
    if public:
        rs.append(resource("aws_s3_bucket_policy.data", bucket="v2-confidential-data", policy=document(public)))
    rs.extend(resources)
    raw = {"planned_values": {"root_module": {"resources": list(reversed(rs)) if reverse_resources else rs}}}
    if unknown_boundary:
        raw["resource_changes"] = [{**resource(principal), "change": {
            "actions": ["create"], "after_unknown": {"permissions_boundary": True}}}]
    return build_graph(parse_plan(raw), tmp_path)


def grants(result, principal=USER):
    return [e for e in result.graph.edges_of("ALLOWS") if e.src == principal and e.dst == BUCKET]


def assert_review(result, principal=USER):
    [edge] = grants(result, principal)
    assert edge.conditional
    evidence = result.ledger.by_id()
    assert any(evidence[h].data.get("conditional_decision") for h in edge.evidence)
    paths = [p for p in find_paths(result, PathOptions(user_entries=True))
             if p.target == BUCKET and principal in p.nodes]
    assert paths and all(p.status == "review" for p in paths)
    assert all(next(h for h in p.hops if h.type == "ALLOWS").status == "ASSUMPTION" for p in paths)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("reverse_resources", [False, True])
def test_public_explicit_deny_wins_in_all_orders(tmp_path, reverse, reverse_resources):
    statements = [statement(Principal="*"), statement("Deny", Principal="*")]
    result = build(tmp_path, public=list(reversed(statements)) if reverse else statements,
                   reverse_resources=reverse_resources)
    assert not grants(result, ANY_PRINCIPAL)
    assert not find_paths(result)
    assert {"principal": ANY_PRINCIPAL, "actions": ["s3:GetObject"]} in result.graph.nodes[BUCKET].flags["explicit_denies"]


def test_public_unconditional_grant_remains_factual(tmp_path):
    result = build(tmp_path, public=[statement(Principal="*")])
    [edge] = grants(result, ANY_PRINCIPAL)
    assert not edge.conditional
    [path] = find_paths(result)
    assert path.status == "direct"
    assert all(h.status == "FACT" for h in path.hops)


@pytest.mark.parametrize("kind", ["identity", "boundary", "resource"])
@pytest.mark.parametrize("reverse", [False, True])
def test_explicit_deny_overrides_grant_per_supported_policy_type(tmp_path, kind, reverse):
    st = [statement(), statement("Deny")]
    if reverse:
        st.reverse()
    options = {"identity": [statement()]}
    if kind == "identity":
        options["identity"] = st
    elif kind == "boundary":
        options["boundary"] = st
    else:
        options["public"] = [{**s, "Principal": {"AWS": "arn:aws:iam::123456789012:user/actor"}} for s in st]
    result = build(tmp_path, **options)
    assert not grants(result)
    assert not find_paths(result, PathOptions(user_entries=True))


@pytest.mark.parametrize("kind", ["identity", "boundary", "resource", "public"])
def test_conditional_deny_requires_review_not_fact_or_clearance(tmp_path, kind):
    deny = statement("Deny", Condition=CONDITION)
    options = {"identity": [statement()]}
    principal = USER
    if kind == "identity":
        options["identity"].append(deny)
    elif kind == "boundary":
        options["boundary"] = [statement(), deny]
    else:
        options["public"] = [statement(Principal="*"), {**deny, "Principal": "*"}]
        if kind == "public":
            principal = ANY_PRINCIPAL
    result = build(tmp_path, **options)
    assert_review(result, principal)


def test_boundary_allow_is_an_intersection_not_a_grant(tmp_path):
    assert not grants(build(tmp_path, boundary=[statement()]))
    assert not grants(build(tmp_path, identity=[statement()], boundary=[statement(action="s3:PutObject")]))
    [edge] = grants(build(tmp_path, identity=[statement()], boundary=[statement()]))
    assert not edge.conditional


def test_conditional_boundary_cannot_be_discharged_by_unconditional_identity_allow(tmp_path):
    assert_review(build(tmp_path, identity=[statement()], boundary=[statement(Condition=CONDITION)]))


@pytest.mark.parametrize("unknown_arn", [False, True])
def test_unresolved_boundary_is_visible_and_requires_review(tmp_path, unknown_arn):
    if unknown_arn:
        result = build(tmp_path, identity=[statement()], unknown_boundary=True)
    else:
        unresolved = resource(USER, name="actor", permissions_boundary=BOUNDARY)
        result = build(tmp_path, identity=[statement()], resources=[unresolved])
    assert_review(result)
    assert result.unresolved_policies
    assert result.graph.nodes[USER].flags["unresolved_boundary"]
    assert any("unresolved boundary" in reason for item in result.graph.nodes[USER].flags["iam_uncertainties"]
               for reason in item["reasons"])


@pytest.mark.parametrize("principal,expected", [(USER, True), ("aws_iam_role.actor", False)])
def test_direct_user_and_role_resource_grants_have_distinct_implicit_boundary_rules(tmp_path, principal, expected):
    arn = f"arn:aws:iam::123456789012:{'user' if principal == USER else 'role'}/actor"
    result = build(tmp_path, principal=principal, boundary=[statement(action="s3:PutObject")],
                   public=[statement(Principal={"AWS": arn})])
    assert bool(grants(result, principal)) is expected
    if expected:
        assert not grants(result, principal)[0].conditional


@pytest.mark.parametrize("principal", [USER, "aws_iam_role.actor"])
def test_explicit_boundary_deny_overrides_direct_resource_grants(tmp_path, principal):
    arn = f"arn:aws:iam::123456789012:{'user' if principal == USER else 'role'}/actor"
    result = build(tmp_path, principal=principal, boundary=[statement(), statement("Deny")],
                   public=[statement(Principal={"AWS": arn})])
    assert not grants(result, principal)


def test_role_session_arn_is_not_silently_treated_as_role_arn(tmp_path):
    principal = "aws_iam_role.actor"
    result = build(tmp_path, principal=principal,
                   public=[statement(Principal={"AWS": "arn:aws:sts::123456789012:assumed-role/actor/session"})])
    assert not grants(result, principal)


def test_unconditional_alternative_grant_wins_over_conditional_allow(tmp_path):
    result = build(tmp_path, identity=[statement(Condition=CONDITION), statement()])
    assert not grants(result)[0].conditional


def test_supported_conditional_grant_is_distinct_from_unresolved_restrictions(tmp_path):
    result = build(tmp_path, identity=[statement(Condition=CONDITION)])
    assert_review(result)
    assert not result.graph.nodes[USER].flags.get("iam_uncertainties")
    assert not result.unresolved_policies


def test_conditional_read_not_hidden_by_factual_list_action(tmp_path):
    result = build(tmp_path, identity=[statement(Condition=CONDITION),
                   statement(action="s3:ListBucket", Resource="arn:aws:s3:::v2-confidential-data")])
    assert_review(result)
    assert grants(result)[0].data["actions"] == ["s3:GetObject", "s3:ListBucket"]


def test_deny_is_action_and_resource_scoped(tmp_path):
    result = build(tmp_path, identity=[statement(), statement("Deny", action="s3:PutObject"),
                   statement("Deny", Resource="arn:aws:s3:::other-bucket/*")])
    assert not grants(result)[0].conditional
    assert grants(result)[0].data["actions"] == ["s3:GetObject"]


def test_notaction_and_notresource_denies_apply(tmp_path):
    deny = {"Effect": "Deny", "NotAction": "s3:PutObject", "NotResource": "arn:aws:s3:::other-bucket/*"}
    assert not grants(build(tmp_path, identity=[statement(), deny]))


def test_unresolved_attached_identity_can_contain_a_deny(tmp_path):
    att = resource("aws_iam_user_policy_attachment.unknown", user="actor",
                   policy_arn="arn:aws:iam::123456789012:policy/not-visible")
    assert_review(build(tmp_path, identity=[statement()], resources=[att]))


def test_boundary_uncertainty_survives_self_admin_derivation(tmp_path):
    result = build(tmp_path, identity=[statement(action="iam:PutUserPolicy", Resource="*")],
                   boundary=[statement(action="iam:PutUserPolicy", Resource="*", Condition=CONDITION)])
    edges = [e for e in result.graph.edges_of("ESCALATES") if e.src == USER]
    assert edges and all(e.conditional for e in edges)
    assert not result.graph.nodes[USER].flags.get("admin_equivalent")


def test_boundary_denial_blocks_self_admin_derivation(tmp_path):
    result = build(tmp_path, identity=[statement(action="iam:PutUserPolicy", Resource="*")],
                   boundary=[statement(action="s3:GetObject", Resource="*")])
    assert not [e for e in result.graph.edges_of("ESCALATES") if e.src == USER]


@pytest.mark.parametrize("action", ["iam:CreatePolicyVersion", "iam:AddUserToGroup"])
def test_wildcard_escalation_fallback_preserves_conditional_boundary_evidence(tmp_path, action):
    result = build(tmp_path, identity=[statement(action=action, Resource="*")],
                   boundary=[statement(action=action, Resource="*", Condition=CONDITION)])
    edges = [e for e in result.graph.edges_of("ESCALATES") if e.src == USER]
    assert edges and all(e.conditional for e in edges)


def test_wildcard_boundary_cannot_supply_missing_wildcard_identity_grant(tmp_path):
    result = build(tmp_path, identity=[statement(action="iam:CreatePolicyVersion", Resource="arn:aws:iam::123456789012:policy/scoped")],
                   boundary=[statement(action="iam:CreatePolicyVersion", Resource="*")])
    assert not [e for e in result.graph.edges_of("ESCALATES") if e.src == USER]


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("kind,ident", [("AWS", "*"), ("Service", "ec2.amazonaws.com"),
                                       ("Federated", "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com")])
def test_trust_explicit_deny_overrides_each_supported_subject(tmp_path, reverse, kind, ident):
    action = "sts:AssumeRoleWithWebIdentity" if kind == "Federated" else "sts:AssumeRole"
    grant = {"Effect": "Allow", "Action": action, "Principal": {kind: ident}}
    statements = [grant, {**grant, "Effect": "Deny"}]
    if reverse:
        statements.reverse()
    target = resource("aws_iam_role.target", name="target", assume_role_policy=document(statements))
    result = build(tmp_path, resources=[target])
    assert not [e for e in result.graph.edges_of("TRUSTS") if e.src == target["address"]]
    assert not [e for e in result.graph.edges_of("ASSUMES") if e.dst == target["address"]]


def test_conditional_trust_deny_keeps_reviewable_possible_assumption(tmp_path):
    grant = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}
    target = resource("aws_iam_role.target", name="target", assume_role_policy=document(
        [grant, {**grant, "Effect": "Deny", "Condition": CONDITION}]))
    result = build(tmp_path, resources=[target])
    edges = [e for e in result.graph.edges_of("ASSUMES") if e.dst == target["address"]]
    assert edges and all(e.conditional for e in edges)


@pytest.mark.parametrize("restrictor", ["identity", "boundary", "trust"])
def test_direct_known_principal_trust_respects_explicit_denies(tmp_path, restrictor):
    grant = {"Effect": "Allow", "Action": "sts:AssumeRole",
             "Principal": {"AWS": "arn:aws:iam::123456789012:user/actor"}}
    trust = [grant, {**grant, "Effect": "Deny"}] if restrictor == "trust" else [grant]
    target = resource("aws_iam_role.target", name="target", assume_role_policy=document(trust))
    options = {"resources": [target]}
    if restrictor == "identity":
        options["identity"] = [statement("Deny", action="sts:AssumeRole", Resource="*")]
    elif restrictor == "boundary":
        options["boundary"] = [statement("Deny", action="sts:AssumeRole", Resource="*")]
    result = build(tmp_path, **options)
    assert not [e for e in result.graph.edges_of("ASSUMES") if e.src == USER and e.dst == target["address"]]


def test_direct_user_trust_can_grant_without_identity_allow(tmp_path):
    grant = {"Effect": "Allow", "Action": "sts:AssumeRole",
             "Principal": {"AWS": "arn:aws:iam::123456789012:user/actor"}}
    target = resource("aws_iam_role.target", name="target", assume_role_policy=document([grant]))
    result = build(tmp_path, resources=[target])
    edges = [e for e in result.graph.edges_of("ASSUMES") if e.src == USER and e.dst == target["address"]]
    assert edges and all(not e.conditional for e in edges)


def test_notprincipal_is_visible_unsupported_analysis_not_factual_permission(tmp_path):
    deny = statement("Deny", NotPrincipal={"AWS": "arn:aws:iam::123456789012:user/actor"})
    result = build(tmp_path, public=[statement(Principal="*"), deny])
    assert_review(result, ANY_PRINCIPAL)
    assert any(d.get("reason") == "NotPrincipal is not evaluated" for d in result.unresolved_policies)


def test_unresolved_resource_policy_cannot_hide_possible_explicit_denial(tmp_path):
    unresolved = resource("aws_s3_bucket_policy.unknown", bucket="v2-confidential-data", policy="unparseable")
    result = build(tmp_path, identity=[statement()], resources=[unresolved])
    assert_review(result)
    assert any(d.get("target") == BUCKET for d in result.unresolved_policies)


@pytest.mark.parametrize("conditional", [False, True])
def test_later_acl_grant_cannot_bypass_resource_policy_restrictions(tmp_path, conditional):
    acl = resource("aws_s3_bucket_acl.data", acl="public-read")
    deny = statement("Deny", action="s3:*", Resource="*", Principal="*")
    if conditional:
        deny["Condition"] = CONDITION
    # ACL attachment uses the actual Terraform reference path, not inferred names.
    plan = parse_plan({"planned_values": {"root_module": {"resources": [
        resource(BUCKET, bucket="v2-confidential-data", tags={"DataClassification": "confidential"}),
        acl, resource("aws_s3_bucket_policy.data", bucket="v2-confidential-data", policy=document([deny]))]}}})
    plan.resources[acl["address"]].references = {"bucket": [BUCKET]}
    result = build_graph(plan, tmp_path)
    if conditional:
        assert_review(result, ANY_PRINCIPAL)
    else:
        assert not grants(result, ANY_PRINCIPAL)
        assert not find_paths(result)


def test_acl_keeps_only_actions_not_explicitly_denied(tmp_path):
    acl = resource("aws_s3_bucket_acl.data", acl="public-read")
    plan = parse_plan({"planned_values": {"root_module": {"resources": [
        resource(BUCKET, bucket="v2-confidential-data"), acl,
        resource("aws_s3_bucket_policy.data", bucket="v2-confidential-data",
                 policy=document([statement("Deny", Principal="*")]))]}}})
    plan.resources[acl["address"]].references = {"bucket": [BUCKET]}
    [edge] = grants(build_graph(plan, tmp_path), ANY_PRINCIPAL)
    assert edge.data["actions"] == ["s3:ListBucket"]
    assert edge.data["access"] == ["list"]
    assert "s3:GetObject" in edge.data["denied"]
    assert not edge.conditional


def unknown_build(tmp_path, resources, unknowns, configuration=None):
    raw = {"planned_values": {"root_module": {"resources": resources}}, "resource_changes": [
        {**resource(address), "change": {"actions": ["create"], "after_unknown": attributes}}
        for address, attributes in unknowns.items()]}
    if configuration is not None:
        raw["configuration"] = {"root_module": {"resources": configuration}}
    return build_graph(parse_plan(raw), tmp_path)


def assert_no_policy_clearance(result):
    analysis = analyze_paths(result, PathOptions(user_entries=True))
    assert not analysis.complete
    assert not analysis.to_json()["policy_complete"]
    assert evaluate_gate([], [], level="validate", analysis=analysis.to_json())["decision"] == "fail"


@pytest.mark.parametrize("principal", [USER, "aws_iam_role.actor"])
@pytest.mark.parametrize("attribute,unknown", [("inline_policy", True), ("inline_policy", [{"policy": True}]),
                                             ("managed_policy_arns", True), ("managed_policy_arns", [True])])
def test_cc2_unknown_embedded_policy_sets_taint_known_allow(tmp_path, principal, attribute, unknown):
    policy_type = "aws_iam_user_policy" if principal == USER else "aws_iam_role_policy"
    owner = "user" if principal == USER else "role"
    result = unknown_build(tmp_path, [resource(BUCKET, bucket="v2-confidential-data"),
        resource(principal, name="actor", **{attribute: None}),
        resource(f"{policy_type}.grant", policy=document([statement()]), **{owner: "actor"})],
        {principal: {attribute: unknown}})
    [edge] = grants(result, principal)
    assert edge.conditional
    assert result.unresolved_policies
    assert_no_policy_clearance(result)


@pytest.mark.parametrize("kind,attribute", [("aws_iam_user", "inline_policy"), ("aws_iam_role", "managed_policy_arns"),
                                          ("aws_iam_group", "inline_policy"), ("aws_iam_policy", "policy"),
                                          ("aws_iam_role", "assume_role_policy"), ("aws_iam_group_policy", "policy")])
def test_cc2_unknown_policy_without_emitted_path_still_blocks_clearance(tmp_path, kind, attribute):
    address = f"{kind}.unknown"
    result = unknown_build(tmp_path, [resource(address, name="unknown", **{attribute: None})],
                           {address: {attribute: True}})
    assert not find_paths(result)
    assert result.unresolved_policies
    assert_no_policy_clearance(result)


def test_cc2_unknown_group_inline_document_taints_member(tmp_path):
    result = unknown_build(tmp_path, [resource(BUCKET, bucket="v2-confidential-data"), resource(USER, name="actor"),
        resource("aws_iam_user_policy.grant", user="actor", policy=document([statement()])),
        resource("aws_iam_group.staff", name="staff"),
        resource("aws_iam_group_policy.unknown", group="staff", policy=None),
        resource("aws_iam_user_group_membership.staff", user="actor", groups=["staff"])],
        {"aws_iam_group_policy.unknown": {"policy": True}})
    assert grants(result)[0].conditional
    assert_no_policy_clearance(result)


@pytest.mark.parametrize("kind,action", [("aws_s3_bucket", "s3:GetObject"), ("aws_kms_key", "kms:Decrypt")])
def test_cc2_unknown_embedded_resource_policy_taints_known_allow(tmp_path, kind, action):
    address = f"{kind}.data"
    result = unknown_build(tmp_path, [resource(address, policy=None, bucket="v2-confidential-data"), resource(USER, name="actor"),
        resource("aws_iam_user_policy.grant", user="actor", policy=document([statement(action=action, Resource="*")]))],
        {address: {"policy": True}})
    edges = [edge for edge in result.graph.edges_of("ALLOWS") if edge.src == USER and edge.dst == address]
    assert edges and all(edge.conditional for edge in edges)
    assert_no_policy_clearance(result)


def test_cc2_unknown_attachment_owner_taints_possible_recipient(tmp_path):
    result = unknown_build(tmp_path, [resource(BUCKET, bucket="v2-confidential-data"), resource(USER, name="actor"),
        resource("aws_iam_user_policy.grant", user="actor", policy=document([statement()])),
        resource("aws_iam_user_policy.unknown", user=None, policy=document([statement("Deny")]))],
        {"aws_iam_user_policy.unknown": {"user": True}})
    assert grants(result)[0].conditional
    assert_no_policy_clearance(result)


@pytest.mark.parametrize("evidence", ["both", "source_only", "config_only", "neither"])
def test_cc2_computed_readback_requires_parsed_source_and_configuration_omission(tmp_path, evidence):
    role = "aws_iam_role.actor"
    if evidence in ("both", "source_only"):
        (tmp_path / "main.tf").write_text('resource "aws_iam_role" "actor" {\n name = "actor"\n}\n')
    config = [{**resource(role), "expressions": {"name": {"constant_value": "actor"}}}] if evidence in ("both", "config_only") else None
    result = unknown_build(tmp_path, [resource(BUCKET, bucket="v2-confidential-data"), resource(role, name="actor"),
        resource("aws_iam_role_policy.grant", role="actor", policy=document([statement()]))],
        {role: {"inline_policy": True, "managed_policy_arns": True}}, config)
    [edge] = grants(result, role)
    if evidence == "both":
        assert not edge.conditional
        assert not result.unresolved_policies
        assert sum(bool(rec.data.get("computed_readback")) for rec in result.ledger.records()) == 2
    else:
        assert edge.conditional
        assert_no_policy_clearance(result)


@pytest.mark.parametrize("source_member", ['managed_policy_arns = var.policies',
                                          'dynamic "inline_policy" {\n for_each = var.policies\n content { policy = inline_policy.value }\n }'])
def test_cc2_source_config_mismatch_cannot_hide_unknown_configured_policy(tmp_path, source_member):
    role = "aws_iam_role.actor"
    (tmp_path / "main.tf").write_text('resource "aws_iam_role" "actor" {\n name = "actor"\n' + source_member + '\n}\n')
    config = [{**resource(role), "expressions": {"name": {"constant_value": "actor"}}}]
    result = unknown_build(tmp_path, [resource(role, name="actor")],
        {role: {"inline_policy": True, "managed_policy_arns": True}}, config)
    assert result.unresolved_policies
    assert_no_policy_clearance(result)


def test_cc2_boundary_limited_selfgrant_does_not_prove_account_admin(tmp_path):
    action = "iam:PutUserPolicy"
    result = build(tmp_path, identity=[statement(action=action, Resource="*")],
                   boundary=[statement(action=action, Resource="*")])
    edges = [edge for edge in result.graph.edges_of("ESCALATES") if edge.src == USER]
    assert edges and all(edge.conditional for edge in edges)
    assert any("new grants remain subject" in reason for detail in result.graph.nodes[USER].flags["iam_uncertainties"]
               for reason in detail["reasons"])
    assert_no_policy_clearance(result)


@pytest.mark.parametrize("bounded", [False, True])
def test_cc2_policy_on_assumable_role_checks_destination_boundary(tmp_path, bounded):
    role = resource("aws_iam_role.target", name="target", assume_role_policy=document([
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::123456789012:user/actor"}}]))
    if bounded:
        role["values"]["permissions_boundary"] = BOUNDARY
    result = build(tmp_path, identity=[statement(action="iam:PutRolePolicy", Resource="*")], resources=[role,
        resource("aws_iam_policy.boundary", name="boundary", policy=document([
            statement(action="s3:GetObject", Resource="*")]))])
    edges = [edge for edge in result.graph.edges_of("ESCALATES") if edge.label.startswith("PE-POLICY-ON-ASSUMABLE-ROLE")]
    assert edges and all(edge.conditional is bounded for edge in edges)
    if bounded:
        assert_no_policy_clearance(result)


@pytest.mark.parametrize("field,value", [("Effect", "var.effect"), ("Action", "var.action"),
    ("NotAction", "var.action"), ("Resource", "var.scope"), ("NotResource", "var.scope"),
    ("Statement", "var.statements"), ("Statement", "[]"), ("Statement", '["unexpected"]')])
def test_cc2_partial_symbolic_source_cannot_discharge_unknown_restriction(tmp_path, field, value):
    fields = {"Effect": '"Deny"', "Action": '"s3:GetObject"', "Resource": '"*"'}
    if field == "Statement":
        statements = value
    else:
        if field == "NotAction":
            fields.pop("Action")
        if field == "NotResource":
            fields.pop("Resource")
        fields[field] = value
        statements = "[{" + ", ".join(f"{key} = {item}" for key, item in fields.items()) + "}]"
    (tmp_path / "main.tf").write_text('resource "aws_iam_user_policy" "unknown" {\n user = "actor"\n'
        + ' policy = jsonencode({\n Statement = ' + statements + '\n })\n}\n')
    result = unknown_build(tmp_path, [resource(BUCKET, bucket="v2-confidential-data"), resource(USER, name="actor"),
        resource("aws_iam_user_policy.grant", user="actor", policy=document([statement()])),
        resource("aws_iam_user_policy.unknown", user="actor", policy=None)],
        {"aws_iam_user_policy.unknown": {"policy": True}})
    assert grants(result)[0].conditional
    assert_no_policy_clearance(result)


@pytest.mark.parametrize("bad", [{"Statement": []}, {"Statement": False}, {"Statement": [False]},
    {"Statement": [{"Effect": "Deny", "Action": True, "Resource": "*"}]},
    {"Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": {"unknown": "*"}}]},
    {"Statement": [{"Action": "s3:GetObject", "Resource": "*"}]},
    {"Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "NotAction": "iam:*", "Resource": "*"}]}])
def test_cc2_malformed_policy_is_not_silently_treated_as_complete(tmp_path, bad):
    result = build(tmp_path, identity=[statement()], resources=[
        resource("aws_iam_user_policy.unknown", user="actor", policy=json.dumps(bad))])
    assert grants(result)[0].conditional
    assert_no_policy_clearance(result)


@pytest.mark.parametrize("unsupported", ["not_principals", "unknown_effect", "unknown_principal_type", "source_policy_documents",
                                        "malformed_action", "malformed_resource", "malformed_principal"])
def test_cc2_document_config_cannot_drop_unknown_or_unsupported_restrictions(tmp_path, unsupported):
    data = "data.aws_iam_policy_document.unknown"
    st = {"effect": {"constant_value": "Deny"}, "actions": {"constant_value": ["s3:GetObject"]},
          "resources": {"constant_value": ["*"]},
          "principals": [{"type": {"constant_value": "AWS"}, "identifiers": {"constant_value": ["*"]}}]}
    expressions = {"statement": [st]}
    if unsupported == "not_principals":
        st["not_principals"] = st.pop("principals")
    elif unsupported == "unknown_effect":
        st["effect"] = {"references": ["var.effect"]}
    elif unsupported == "unknown_principal_type":
        st["principals"][0]["type"] = {"references": ["var.type"]}
    elif unsupported == "malformed_action":
        st["actions"] = {"constant_value": True}
    elif unsupported == "malformed_resource":
        st["resources"] = {"constant_value": [True]}
    elif unsupported == "malformed_principal":
        st["principals"][0]["identifiers"] = {"constant_value": [True]}
    else:
        expressions["source_policy_documents"] = {"references": ["var.policies"]}
    resources = [resource(BUCKET, bucket="v2-confidential-data"), resource(USER, name="actor"),
        resource("aws_iam_user_policy.grant", user="actor", policy=document([statement()])),
        resource("aws_s3_bucket_policy.unknown", bucket="v2-confidential-data", policy=None),
        {"address": data, "mode": "data", "type": "aws_iam_policy_document", "name": "unknown", "values": {"json": None}}]
    raw = {"planned_values": {"root_module": {"resources": resources}}, "configuration": {"root_module": {"resources": [
        {"address": data, "mode": "data", "type": "aws_iam_policy_document", "name": "unknown", "expressions": expressions},
        {**resource("aws_s3_bucket_policy.unknown"), "expressions": {"policy": {"references": [data + ".json"]}}}]}},
        "resource_changes": [{**resource("aws_s3_bucket_policy.unknown"), "change": {"actions": ["create"], "after_unknown": {"policy": True}}}]}
    result = build_graph(parse_plan(raw), tmp_path)
    assert grants(result)[0].conditional
    assert_no_policy_clearance(result)


def test_cc2_complete_known_resource_symbolic_recovery_remains_supported(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_iam_user_policy" "known" {\n user = "actor"\n'
        ' policy = jsonencode({\n Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.data.arn}/*" }]\n })\n}\n')
    result = unknown_build(tmp_path, [resource(BUCKET, bucket="v2-confidential-data"), resource(USER, name="actor"),
        resource("aws_iam_user_policy.known", user="actor", policy=None)],
        {"aws_iam_user_policy.known": {"policy": True}})
    assert grants(result) and not grants(result)[0].conditional
    assert not result.unresolved_policies


@pytest.mark.parametrize("inline", [False, [{"policy": False}], [{}]])
def test_cc2_malformed_embedded_inline_policy_cannot_be_ignored(tmp_path, inline):
    actor = resource(USER, name="actor", inline_policy=inline)
    result = build(tmp_path, identity=[statement()], resources=[actor])
    assert grants(result)[0].conditional
    assert_no_policy_clearance(result)


def test_cc2_malformed_boundary_cannot_be_ignored_as_falsy(tmp_path):
    actor = resource(USER, name="actor", permissions_boundary=False)
    result = build(tmp_path, identity=[statement()], resources=[actor])
    assert grants(result)[0].conditional
    assert_no_policy_clearance(result)
