"""ECS on EC2: which hosts run a cluster's tasks, and can a container reach the host's role credentials?

A container instance joins a cluster through ``ECS_CLUSTER=<name>`` in its user data (the ECS agent's
documented configuration); that is the only link the plan shows between a launch template or instance and
a cluster, so it is the one we follow. Fargate tasks have no host role.
"""

from __future__ import annotations

import base64
import binascii
import re

from ..terraform.plan import Plan, PlanResource
from ..util import as_list

# The ECS-documented ways to keep containers away from the host's metadata service
_BLOCKS_IMDS = (re.compile(r"169\.254\.169\.254(/32)?\s+-j\s+(DROP|REJECT)"), re.compile(r"ECS_AWSVPC_BLOCK_IMDS\s*=\s*true", re.I))


def user_data(r: PlanResource) -> str:
    raw = r.values.get("user_data") or r.values.get("user_data_base64") or ""
    if not isinstance(raw, str):
        return ""
    if raw and re.fullmatch(r"[A-Za-z0-9+/=\s]+", raw) and len(raw.strip()) % 4 == 0:
        try:
            return base64.b64decode(raw).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return raw
    return raw


def cluster_of(plan: Plan, svc: PlanResource) -> PlanResource | None:
    return next((c for ref in svc.references.get("cluster", []) for c in plan.instances_of(ref)
                 if c.type == "aws_ecs_cluster"), None)


def task_definition_of(plan: Plan, svc: PlanResource) -> PlanResource | None:
    return next((t for ref in svc.references.get("task_definition", []) for t in plan.instances_of(ref)
                 if t.type == "aws_ecs_task_definition"), None)


def is_fargate(svc: PlanResource, td: PlanResource | None) -> bool:
    if svc.values.get("launch_type") == "FARGATE":
        return True
    return td is not None and "FARGATE" in (td.values.get("requires_compatibilities") or []) \
        and "EC2" not in (td.values.get("requires_compatibilities") or [])


def hosts(plan: Plan, cluster: PlanResource | None) -> list[PlanResource]:
    """Launch templates and instances whose user data joins ``cluster``."""
    name = (cluster.values.get("name") if cluster is not None else None) or ""
    if not name:
        return []
    pat = re.compile(r"ECS_CLUSTER\s*=\s*[\"']?" + re.escape(name) + r"[\"']?(\s|$)")
    return [r for r in plan.by_type("aws_launch_template", "aws_instance") if pat.search(user_data(r))]


def container_imds(host: PlanResource) -> tuple[str | None, str]:
    """Precondition for a container to obtain the host role's credentials, and why."""
    mo = (as_list(host.values.get("metadata_options")) or [{}])[0] or {}
    if mo.get("http_endpoint") == "disabled":
        return None, "metadata endpoint disabled on the host"
    if any(p.search(user_data(host)) for p in _BLOCKS_IMDS):
        return "container_escape", "host user data blocks containers from the metadata service"
    hop = mo.get("http_put_response_hop_limit")
    if mo.get("http_tokens") == "required":
        if hop in (None, 1):
            return "container_escape", "IMDSv2 required with hop limit 1: a bridged container cannot fetch a token"
        return "workload_rce", "IMDSv2 required; a container can still fetch a token (hop limit > 1)"
    return "workload_ssrf", "IMDSv1 allowed on the host and nothing blocks containers from it"


def escape_aids(td: PlanResource | None) -> list[str]:
    """Task settings that make leaving the container easy (reported, not scored)."""
    if td is None:
        return []
    out = []
    if td.values.get("pid_mode") == "host":
        out.append("pid_mode = host")
    cd = str(td.values.get("container_definitions") or "")
    for cap in ("SYS_PTRACE", "SYS_ADMIN", "SYS_MODULE"):
        if cap in cd:
            out.append(f"capability {cap}")
    if re.search(r'"privileged"\s*:\s*true', cd):
        out.append("privileged container")
    return out
