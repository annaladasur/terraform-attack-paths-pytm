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
    "condition_satisfied": "IAM grant and restriction conditions permit the attacker's request; unresolved policy restrictions require verification.",
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
    max_expansions: int = 50_000  # hard work/queue bound for displayed simple paths
    max_verification_steps: int = 100_000  # separate edge-work bound for reachability


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


@dataclass
class PairReachability:
    entry: str
    target: str
    reachable: bool | None
    witness: AttackPath | None = None

    def to_json(self) -> dict:
        return {"entry": self.entry, "target": self.target, "reachable": self.reachable,
                "status": "unknown" if self.reachable is None else "reachable" if self.reachable else "unreachable",
                "witness": self.witness.to_json() if self.witness else None}


@dataclass
class ReachabilityAnalysis:
    pairs: list[PairReachability]
    complete: bool
    steps: int
    max_steps: int
    truncated_by: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"complete": self.complete, "steps": self.steps, "max_steps": self.max_steps,
                "truncated_by": self.truncated_by, "pairs": [p.to_json() for p in self.pairs]}


@dataclass
class PathAnalysis:
    paths: list[AttackPath]
    reachability: ReachabilityAnalysis
    enumeration: dict
    policy_uncertainties: list[dict] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.reachability.complete and self.enumeration["complete"] and not self.policy_uncertainties

    def to_json(self) -> dict:
        return {"complete": self.complete,
                "enumeration": self.enumeration, "reachability": self.reachability.to_json(),
                "policy_complete": not self.policy_uncertainties, "policy_uncertainties": self.policy_uncertainties}


def _validate_options(opts: PathOptions) -> None:
    for name in ("max_depth", "max_paths_per_pair", "max_paths", "max_expansions", "max_verification_steps"):
        value = getattr(opts, name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")


def _adjacency(g: Graph) -> dict[str, list[Edge]]:
    adj: dict[str, list[Edge]] = {}
    for e in g.edges.values():
        if e.type in TRAVERSE:
            adj.setdefault(e.src, []).append(e)
    for edges in adj.values():
        edges.sort(key=lambda e: (e.type, e.dst, e.label))
    return adj


def _make_path(g: Graph, opts: PathOptions, entry: str, entry_pre: str | None,
               nodes: list[str], edges: list[Edge]) -> AttackPath:
    hops = [_hop(e) for e in edges]
    pres = ([entry_pre] if entry_pre else []) + [h.precondition for h in hops if h.precondition]
    if any(e.conditional for e in edges):
        pres.append("condition_satisfied")
    pres = list(dict.fromkeys(pres))
    target = nodes[-1]
    level = g.nodes[target].sensitivity.get("level", "unclassified")
    if level == "unclassified" and target in opts.extra_targets:
        level = "confidential"
    heuristic = str(g.nodes[target].sensitivity.get("basis", "")).startswith("heuristic")
    review = any(e.conditional for e in edges) or heuristic
    status = "review" if review else ("plausible" if pres else "direct")
    score, priority = _priority(entry, pres, level, review)
    ev = sorted({x for e in edges for x in ([e.id] if e.id else []) + e.evidence})
    key = digest([nodes, [e.id for e in edges]])
    return AttackPath("", key, entry, target, nodes, hops, pres, status, priority, score, ev, level)


def verify_reachability(result: BuildResult, opts: PathOptions | None = None, graph: Graph | None = None,
                        only_entry: str | None = None, only_target: str | None = None) -> ReachabilityAnalysis:
    """Verify entry/target existence independently of display caps and depth.

    A node-visited BFS is sufficient for existence: a reachable walk always has a
    simple path. Targets are terminal, and ALLOWS only terminates at a target,
    exactly as in display traversal. The deterministic edge-work budget bounds
    all entries together. An unfinished search can establish presence, never
    absence; every unestablished pair is explicitly unknown.
    """
    opts = opts or PathOptions()
    _validate_options(opts)
    g = graph or result.graph
    goals = set(targets(g, opts))
    selected = sorted(goals if only_target is None else {only_target})
    adj = _adjacency(g)
    pairs: list[PairReachability] = []
    steps = 0
    for entry, entry_pre in entries(g, opts):
        if only_entry is not None and entry != only_entry:
            continue
        parent: dict[str, Edge | None] = {entry: None}
        q = deque([entry])
        witnesses: dict[str, AttackPath] = {}
        exhausted = True
        while q:
            node = q.popleft()
            for e in adj.get(node, ()):
                if steps >= opts.max_verification_steps:
                    exhausted = False
                    break
                steps += 1
                if e.type == "ALLOWS" and e.dst not in goals:
                    continue
                if e.dst in parent:
                    continue
                parent[e.dst] = e
                if e.dst in goals:
                    if e.dst in selected:
                        chain: list[Edge] = []
                        cursor = e.dst
                        while parent[cursor] is not None:
                            previous = parent[cursor]
                            chain.append(previous)
                            cursor = previous.src
                        chain.reverse()
                        witnesses[e.dst] = _make_path(g, opts, entry, entry_pre,
                                                     [entry] + [h.dst for h in chain], chain)
                    continue
                q.append(e.dst)
            if not exhausted:
                break
        pairs.extend(PairReachability(entry, target, True if target in witnesses else False if exhausted else None,
                                      witnesses.get(target)) for target in selected)
    complete = all(p.reachable is not None for p in pairs)
    return ReachabilityAnalysis(pairs, complete, steps, opts.max_verification_steps,
                                [] if complete else ["max_verification_steps"])


def route_path(result: BuildResult, original: AttackPath, opts: PathOptions | None = None,
               graph: Graph | None = None) -> AttackPath | None:
    """Check the supplied route's relationships directly, without an enumeration cap.

    GRAPH IDs can change on re-planning, so relationship identity uses type,
    endpoints and label. This is a route check, not proof of target absence.
    """
    opts = opts or PathOptions()
    g = graph or result.graph
    if not original.hops or original.target not in g.nodes:
        return None
    by_key = {e.key: e for e in g.edges.values()}
    edges: list[Edge] = []
    goals = set(targets(g, opts))
    for i, hop in enumerate(original.hops):
        edge = by_key.get((hop.type, hop.src, hop.dst, hop.label))
        if edge is None or edge.type not in TRAVERSE or edge.dst not in g.nodes:
            return None
        if edge.type == "ALLOWS" and edge.dst not in goals:
            return None
        if edge.dst in goals and i != len(original.hops) - 1:
            return None
        edges.append(edge)
    entry_pre = "credential_compromise" if original.entry != INTERNET else None
    return _make_path(g, opts, original.entry, entry_pre, list(original.nodes), edges)


def analyze_paths(result: BuildResult, opts: PathOptions | None = None, graph: Graph | None = None,
                  only_entry: str | None = None) -> PathAnalysis:
    """Enumerate display routes with explicit limits, and separately verify pairs."""
    opts = opts or PathOptions()
    _validate_options(opts)
    g = graph or result.graph
    goals = set(targets(g, opts))
    adj = _adjacency(g)
    found: list[AttackPath] = []
    truncated: set[str] = set()
    expansions = 0
    budget_exhausted = False
    for entry, entry_pre in entries(g, opts):
        if only_entry is not None and entry != only_entry:
            continue
        per_pair: dict[str, int] = {}
        q = deque([(entry, [entry], [])])
        while q:
            node, nodes, edges = q.popleft()
            for e in adj.get(node, ()):
                if expansions >= opts.max_expansions:
                    truncated.add("max_expansions")
                    budget_exhausted = True
                    break
                expansions += 1
                if e.dst in nodes or e.type == "ALLOWS" and e.dst not in goals:
                    continue
                if len(edges) >= opts.max_depth:
                    truncated.add("max_depth")
                    continue
                nn, ne = nodes + [e.dst], edges + [e]
                if e.dst in goals:
                    if per_pair.get(e.dst, 0) < opts.max_paths_per_pair:
                        per_pair[e.dst] = per_pair.get(e.dst, 0) + 1
                        found.append(_make_path(g, opts, entry, entry_pre, nn, ne))
                    else:
                        truncated.add("max_paths_per_pair")
                    continue
                q.append((e.dst, nn, ne))
            if budget_exhausted:
                break
        if budget_exhausted:
            break
    found.sort(key=lambda p: (-p.score, p.target, len(p.nodes), p.nodes))
    if len(found) > opts.max_paths:
        truncated.add("max_paths")
    paths = found[:opts.max_paths]
    for i, p in enumerate(paths, start=1):
        p.id = f"PATH-{i:03d}"
    enumeration = {"complete": not truncated, "truncated_by": sorted(truncated), "expansions": expansions,
                   "max_expansions": opts.max_expansions, "max_depth": opts.max_depth,
                   "max_paths": opts.max_paths, "max_paths_per_pair": opts.max_paths_per_pair}
    verification = verify_reachability(result, opts, graph=g, only_entry=only_entry)
    uncertainties = [{"resource": nid, "restrictions": node.flags["iam_uncertainties"]}
                     for nid, node in sorted(g.nodes.items()) if node.flags.get("iam_uncertainties")]
    uncertainties += list(getattr(result, "unresolved_policies", []))
    return PathAnalysis(paths, verification, enumeration, uncertainties)


def find_paths(result: BuildResult, opts: PathOptions | None = None, graph: Graph | None = None,
               only_entry: str | None = None) -> list[AttackPath]:
    """Compatibility display API. Absence from this bounded list proves nothing.

    Use analyze_paths for completeness and verify_reachability for security
    decisions. only_entry preserves the historical display selection behavior.
    """
    return analyze_paths(result, opts, graph, only_entry).paths


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
