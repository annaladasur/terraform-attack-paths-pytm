"""Deterministic what-if: which single change breaks or downgrades a path?

For each hop we apply the corresponding fix to a *copy* of the graph and rerun the
path engine. The effect in the report is therefore computed, not predicted by a
model. Fixes are expressed in Terraform terms using the hop's own evidence.
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass

from ..graph.build import BuildResult
from ..graph.model import Graph
from .engine import AttackPath, PathOptions, route_path, verify_reachability


@dataclass
class Remedy:
    path: str
    hop: int
    edge: str
    change: str
    effect: str  # breaks_path | downgrades_path | no_effect | breaks_path_but_alternative_exists | inconclusive
    before: str
    after: str | None
    remaining_paths_to_target: int
    evidence: list[str]
    analysis_complete: bool = True
    target_reachable: bool | None = None
    remaining_paths_complete: bool = False  # count is a witnessed lower bound, not exhaustive routes

    def to_json(self) -> dict:
        return self.__dict__.copy()


def _describe(result: BuildResult, hop) -> str | None:
    recs = result.ledger.by_id()
    ev = [recs[e] for e in hop.evidence if e in recs]
    locs = [f"{r.source['file']}:{r.source['start_line']}" + (f"-{r.source['end_line']}" if r.source['end_line'] != r.source['start_line'] else "")
            for r in ev if r.source and r.kind in ("NET", "IAM") and r.source.get("file")]
    where = f" ({', '.join(sorted(set(locs)))})" if locs else ""
    if hop.type == "EXPOSES":
        node = result.graph.nodes.get(hop.dst)
        if node is not None and node.type in ("aws_lb", "aws_alb"):
            return f"Remove internet reachability of {hop.dst}: restrict the 0.0.0.0/0 ingress rule to known client CIDRs or set internal = true{where}"
        return f"Remove internet reachability of {hop.dst}{where}"
    if hop.type == "ASSUMES" and hop.precondition == "workload_ssrf":
        return f"Require IMDSv2 on {hop.src}: metadata_options {{ http_tokens = \"required\" }}"
    if hop.type == "ASSUMES":
        return f"Remove {hop.src}'s ability to obtain {hop.dst} credentials ({hop.label}){where}"
    if hop.type == "ALLOWS":
        return f"Scope {hop.src}'s policy so it no longer grants {hop.label} on {hop.dst}{where}"
    if hop.type == "ESCALATES":
        return f"Remove the escalation primitive {hop.label} from {hop.src}{where}"
    return None


def what_if(result: BuildResult, paths: list[AttackPath], opts: PathOptions | None = None) -> list[Remedy]:
    opts = opts or PathOptions()
    policy_complete = not getattr(result, "unresolved_policies", []) and not any(
        node.flags.get("iam_uncertainties") for node in result.graph.nodes.values())
    out: list[Remedy] = []
    for p in paths:
        for i, hop in enumerate(p.hops, start=1):
            change = _describe(result, hop)
            if not change:
                continue
            # shallow copy: a new edge dict, and a new Edge object where one changes; the original graph is untouched
            g: Graph = copy.copy(result.graph)
            g.edges = dict(result.graph.edges)
            key = next(k for k, e in g.edges.items() if e.id == hop.edge)
            if hop.type == "ASSUMES" and hop.precondition == "workload_ssrf":
                g.edges[key] = dataclasses.replace(g.edges[key], precondition="workload_rce")
            else:
                del g.edges[key]
            verification = verify_reachability(result, opts, graph=g, only_entry=p.entry, only_target=p.target)
            pair = next((q for q in verification.pairs if q.target == p.target), None)
            same = route_path(result, p, opts, graph=g)
            reachable = pair.reachable if pair else None
            if reachable is None or not policy_complete:
                effect, after = "inconclusive", same.priority if same else None
            elif not reachable:
                effect, after = "breaks_path", None
            elif same and _rank(same.priority) < _rank(p.priority):
                effect, after = "downgrades_path", same.priority
            elif same:
                effect, after = "no_effect", same.priority
            else:
                effect, after = "breaks_path_but_alternative_exists", pair.witness.priority
            out.append(Remedy(p.id, i, hop.edge, change, effect, p.priority, after,
                              1 if reachable else 0, hop.evidence,
                              verification.complete and policy_complete, reachable, reachable is False))
    return out


def _rank(p: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(p, 0)
