"""Attack-path engine.

Definition (docs/methodology.md#attack-path):

    An attack path is a sequence of typed graph relationships connecting an
    attacker-controlled entry condition to a security-relevant asset, where every
    edge is supported by deterministic evidence and any non-deterministic
    assumption is explicitly labeled.

* Entry conditions: ``internet`` (and nodes it EXPOSES), plus optional
  ``credential_compromise`` of IAM users.
* Assets: data stores classified confidential/restricted, secrets, and
  ``aws:account-admin``.
* Traversal: EXPOSES, ROUTES_TO, ASSUMES, ALLOWS (terminal only), ESCALATES.
* Each hop is a FACT (the edge alone is enough) or an ASSUMPTION (the edge exists,
  but crossing it requires a precondition such as workload compromise, or a
  policy Condition being satisfied).

The engine never calls a model and has no randomness: identical graphs produce
identical path lists, IDs and ordering.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ..graph.build import LEVEL_ORDER, BuildResult
from ..graph.model import ACCOUNT_ADMIN, INTERNET, Edge, Graph
from ..util import digest

PRECONDITIONS = {
    "workload_ssrf": "Attacker can make the workload issue HTTP requests (SSRF) or execute code (RCE); IMDSv1 is allowed.",
    "workload_rce": "Attacker can execute code in the workload (RCE); credentials are not reachable by SSRF alone.",
    "container_escape": "Attacker can execute code in the container and break out to its host; the host blocks containers from its metadata service.",
    "credential_compromise": "Attacker holds credentials for this IAM user.",
    "condition_satisfied": "An IAM policy Condition on this grant evaluates true for the attacker's request.",
    "unresolved_value": "A value unknown at plan time resolves in the attacker's favour.",
    "source_ip_allowed": "Attacker's traffic originates from a public address range the security group admits (not 0.0.0.0/0).",
}


@dataclass
class PathOptions:
    max_depth: int = 8
    max_paths_per_pair: int = 3
    max_paths: int = 200
    user_entries: bool = False  # treat IAM users as compromised-credential entries
    min_level: str = "confidential"
    extra_targets: tuple[str, ...] = ()  # assets declared by a scenario (e.g. CloudGoat goals), in addition to classified data


@dataclass
class Hop:
    edge: str  # GRAPH-###
    type: str
    src: str
    dst: str
    label: str
    status: str  # FACT | ASSUMPTION
    precondition: str | None
    evidence: list[str]

    def to_json(self) -> dict:
        return self.__dict__.copy()


@dataclass
class AttackPath:
    id: str
    key: str
    entry: str
    target: str
    nodes: list[str]
    hops: list[Hop]
    preconditions: list[str]
    status: str  # direct | plausible | review
    priority: str
    score: int
    evidence: list[str]
    target_sensitivity: str
    findings: list[str] = field(default_factory=list)  # SCAN ids joined later

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "entry": self.entry,
            "target": self.target,
            "nodes": self.nodes,
            "hops": [h.to_json() for h in self.hops],
            "preconditions": self.preconditions,
            "status": self.status,
            "priority": self.priority,
            "score": self.score,
            "target_sensitivity": self.target_sensitivity,
            "evidence": self.evidence,
            "findings": self.findings,
            "summary": self.summary(),
        }

    def summary(self) -> str:
        chain = " -> ".join(self.nodes)
        pre = f"; requires: {', '.join(self.preconditions)}" if self.preconditions else ""
        return f"{self.status} path from {self.entry} to {self.target_sensitivity} asset {self.target}: {chain}{pre}"


def targets(g: Graph, opts: PathOptions) -> list[str]:
    floor = LEVEL_ORDER[opts.min_level]
    out = []
    for nid, n in sorted(g.nodes.items()):
        if nid == ACCOUNT_ADMIN:
            out.append(nid)
        elif n.category == "data" and LEVEL_ORDER.get(n.sensitivity.get("level", "unclassified"), 0) >= floor:
            out.append(nid)
        elif nid in opts.extra_targets:
            out.append(nid)
    return out


def entries(g: Graph, opts: PathOptions) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = [(INTERNET, None)]
    if opts.user_entries:
        out += [(nid, "credential_compromise") for nid, n in sorted(g.nodes.items()) if n.type == "aws_iam_user"]
    return out


def _hop(e: Edge) -> Hop:
    pre = e.precondition
    if pre is None and e.conditional:
        pre = "condition_satisfied"
    if pre is None and e.data.get("symbolic"):
        pre = None  # symbolic policy recovery is provenance, not an attacker precondition
    return Hop(e.id or "", e.type, e.src, e.dst, e.label, "ASSUMPTION" if pre else "FACT", pre, list(e.evidence))


TRAVERSE = ("EXPOSES", "ROUTES_TO", "ASSUMES", "ALLOWS", "ESCALATES")


def find_paths(result: BuildResult, opts: PathOptions | None = None, graph: Graph | None = None,
               only_entry: str | None = None) -> list[AttackPath]:
    """``only_entry`` restricts the search to one entry (what-if re-runs); results for that entry are unchanged."""
    opts = opts or PathOptions()
    g = graph or result.graph
    goal = set(targets(g, opts))
    found: list[tuple] = []
    # adjacency built once, in the same order as Graph.out_edges
    adj: dict[str, list[Edge]] = {}
    for e in g.edges.values():
        if e.type in TRAVERSE:
            adj.setdefault(e.src, []).append(e)
    for lst in adj.values():
        lst.sort(key=lambda e: (e.type, e.dst, e.label))

    for entry, entry_pre in entries(g, opts):
        if only_entry is not None and entry != only_entry:
            continue
        # BFS over simple paths so shorter paths come first; deterministic neighbour order.
        per_pair: dict[str, int] = {}
        q = deque([(entry, [entry], [])])
        while q:
            node, nodes, edges = q.popleft()
            if len(edges) >= opts.max_depth:
                continue
            for e in adj.get(node, ()):
                if e.dst in nodes:
                    continue
                if e.type == "ALLOWS" and e.dst not in goal:
                    continue  # ALLOWS only terminates at an asset
                nn, ne = nodes + [e.dst], edges + [e]
                if e.dst in goal:
                    if per_pair.get(e.dst, 0) < opts.max_paths_per_pair:
                        per_pair[e.dst] = per_pair.get(e.dst, 0) + 1
                        found.append((entry, entry_pre, nn, ne))
                    continue
                q.append((e.dst, nn, ne))

    paths: list[AttackPath] = []
    for entry, entry_pre, nodes, edges in found:
        hops = [_hop(e) for e in edges]
        pres = ([entry_pre] if entry_pre else []) + [h.precondition for h in hops if h.precondition]
        if any(e.conditional for e in edges):
            pres.append("condition_satisfied")
        pres = list(dict.fromkeys(pres))
        target = nodes[-1]
        level = g.nodes[target].sensitivity.get("level", "unclassified")
        if level == "unclassified" and target in opts.extra_targets:
            level = "confidential"  # declared goal of the scenario
        heuristic = str(g.nodes[target].sensitivity.get("basis", "")).startswith("heuristic")
        review = any(e.conditional for e in edges) or heuristic
        status = "review" if review else ("plausible" if pres else "direct")
        score, priority = _priority(entry, pres, level, review)
        ev = sorted({x for e in edges for x in ([e.id] if e.id else []) + e.evidence})
        key = digest([nodes, [e.id for e in edges]])
        paths.append(AttackPath("", key, entry, target, nodes, hops, pres, status, priority, score, ev, level))

    paths.sort(key=lambda p: (-p.score, p.target, len(p.nodes), p.nodes))
    paths = paths[: opts.max_paths]
    for i, p in enumerate(paths, start=1):
        p.id = f"PATH-{i:03d}"
    return paths


def _priority(entry: str, pres: list[str], level: str, review: bool) -> tuple[int, str]:
    """Deterministic, documented scoring (docs/methodology.md#priority)."""
    base = {"restricted": 3, "confidential": 2}.get(level, 1)
    ent = 2 if entry == INTERNET else 1
    penalty = 0
    for p in pres:
        penalty += {"workload_ssrf": 0, "workload_rce": 1, "container_escape": 2, "credential_compromise": 0, "condition_satisfied": 1,
                    "unresolved_value": 1, "source_ip_allowed": 1}.get(p, 1)
    penalty += 1 if review and "condition_satisfied" not in pres else 0  # heuristic classification
    score = base + ent - penalty
    priority = "high" if score >= 4 else "medium" if score == 3 else "low"
    return score, priority


def register_paths(result: BuildResult, paths: list[AttackPath]) -> None:
    """Add PATH records to the finalized ledger, in path order, so PATH-### IDs match."""
    for p in paths:
        rid = result.ledger.append("PATH", (p.key,), p.summary(),
                                   data={"priority": p.priority, "status": p.status, "preconditions": p.preconditions,
                                         "nodes": p.nodes, "target": p.target},
                                   refs=[h.edge for h in p.hops] + p.findings)
        assert rid == p.id, (rid, p.id)
