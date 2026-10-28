"""Engine rules added after the TerrARA benchmark's first run: API Gateway entries, ECS task and host roles,
Glue job PassRole, a policy written onto a role the principal can take over, and quoted policy keys.

Most use the committed benchmark plans (evaluations/terrara/plans), which need no Terraform source.
"""

from __future__ import annotations

import gzip
import json

import pytest

from conftest import ROOT

PLANS = ROOT / "evaluations" / "terrara" / "plans"


def _graph(name, tmp_path):
    from tapm.graph.build import BuildOptions, build_graph
    from tapm.terraform.plan import parse_plan

    raw = json.loads(gzip.decompress((PLANS / f"{name}.json.gz").read_bytes()))
    return build_graph(parse_plan(raw), tmp_path, BuildOptions()).graph


def _edges(g, type_, **kw):
    return [e for e in g.edges.values() if e.type == type_ and all(getattr(e, k) == v for k, v in kw.items())]


def test_public_api_gateway_is_an_entry_that_routes_to_its_lambda(tmp_path):
    g = _graph("awsgoat-module-1", tmp_path)
    assert _edges(g, "EXPOSES", src="internet", dst="aws_api_gateway_rest_api.apiLambda_ba")
    r = _edges(g, "ROUTES_TO", src="aws_api_gateway_rest_api.apiLambda_ba", dst="aws_lambda_function.lambda_ba_data")
    assert r and not r[0].conditional  # an aws_lambda_permission lets API Gateway invoke it


def test_ecs_service_behind_a_load_balancer_gets_task_and_host_roles(tmp_path):
    g = _graph("awsgoat-module-2", tmp_path)
    assert _edges(g, "ROUTES_TO", src="aws_alb.application_load_balancer", dst="aws_ecs_service.worker")
    task = _edges(g, "ASSUMES", src="aws_ecs_service.worker", dst="aws_iam_role.ecs-task-role")
    assert task and task[0].label == "task_role" and task[0].precondition == "workload_rce"
    host = _edges(g, "ASSUMES", src="aws_ecs_service.worker", dst="aws_iam_role.ecs-instance-role")
    # the host's user data drops container traffic to 169.254.169.254: reaching the host role needs an escape
    assert host and host[0].label == "ecs_host_role" and host[0].precondition == "container_escape"


def test_container_imds_precondition():
    from tapm.graph.ecs import container_imds
    from tapm.terraform.plan import PlanResource

    def lt(mo=None, ud=""):
        return PlanResource("aws_launch_template.x", "managed", "aws_launch_template", "x", None, "", "aws",
                            {"metadata_options": [mo] if mo else [], "user_data": ud})

    assert container_imds(lt())[0] == "workload_ssrf"
    assert container_imds(lt({"http_tokens": "required", "http_put_response_hop_limit": 1}))[0] == "container_escape"
    assert container_imds(lt({"http_tokens": "required", "http_put_response_hop_limit": 2}))[0] == "workload_rce"
    assert container_imds(lt({"http_endpoint": "disabled"}))[0] is None
    assert container_imds(lt(ud="echo ECS_AWSVPC_BLOCK_IMDS=true >> /etc/ecs/ecs.config"))[0] == "container_escape"


def test_glue_job_passrole_with_quoted_policy_keys():
    """tests/data/glue-job-passrole: the user's policy is unknown at plan time and written with quoted keys."""
    from tapm.graph.build import BuildOptions, build_graph
    from tapm.paths.engine import PathOptions, find_paths
    from tapm.terraform.plan import load_plan

    d = ROOT / "tests" / "data" / "glue-job-passrole"
    b = build_graph(load_plan(d / "plan.json"), d, BuildOptions())
    [e] = _edges(b.graph, "ASSUMES", src="aws_iam_user.etl", dst="aws_iam_role.job", label="PE-PASSROLE-GLUE-JOB")
    [p] = find_paths(b, PathOptions(user_entries=True))
    assert p.nodes == ["aws_iam_user.etl", "aws_iam_role.job", "aws_ssm_parameter.db_password"]


def test_quoted_policy_keys_are_recovered():
    from tapm.terraform.symbolic import _symbolise

    doc = _symbolise({'"Statement"': [{'"Action"': ['"iam:AttachRolePolicy"'], '"Resource"': '"${aws_iam_role.r.arn}"'}]}, "")
    assert doc == {"Statement": [{"Action": ["iam:AttachRolePolicy"], "Resource": "tf:aws_iam_role.r.arn"}]}


def test_a_policy_written_onto_a_role_you_can_act_as_is_escalation(tmp_path):
    g = _graph("awsgoat-module-2", tmp_path)  # IAMFullAccess + PassRole to an EC2 role
    labels = {e.label for e in _edges(g, "ESCALATES", src="aws_iam_role.ecs-instance-role")}
    assert "PE-POLICY-ON-ASSUMABLE-ROLE(aws_iam_role.ec2-deployer-role)" in labels
