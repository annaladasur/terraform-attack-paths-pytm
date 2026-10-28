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
from .engine import AttackPath, PathOptions, find_paths


@dataclass
class Remedy:
    path: str
    hop: int
    edge: str
    change: str
    effect: str  # breaks_path | downgrades_path | no_effect
    before: str
    after: str | None
    remaining_paths_to_target: int
    evidence: list[str]

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
            new = [q for q in find_paths(result, opts, graph=g, only_entry=p.entry) if q.target == p.target]
            same = [q for q in new if q.nodes == p.nodes]
            if not new:
                effect, after = "breaks_path", None
            elif same and same[0].priority != p.priority:
                effect, after = "downgrades_path", same[0].priority
            elif same:
                effect, after = "no_effect", same[0].priority
            else:
                effect, after = "breaks_path_but_alternative_exists", max((q.priority for q in new), key=_rank)
            out.append(Remedy(p.id, i, hop.edge, change, effect, p.priority, after, len(new), hop.evidence))
    return out


def _rank(p: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(p, 0)
