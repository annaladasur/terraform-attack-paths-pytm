"""Terraform plan -> typed security graph (Plane 2), with the evidence ledger (Plane 4)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..evidence.ledger import Ledger, handle
from ..iam.evaluator import IamEvaluator
from ..terraform.plan import Plan
from ..terraform.source import SourceIndex, locals_from_source, module_sources_from_plan
from ..util import as_list
from .kinds import ASSET_TYPES, kind_of
from .model import ANY_PRINCIPAL, INTERNET, Edge, Graph, Node
from .network import Network

_LEVELS = {
    "public": "public", "internal": "internal",
    "confidential": "confidential", "sensitive": "confidential", "pii": "confidential",
    "restricted": "restricted", "secret": "restricted", "highly-confidential": "restricted",
}
_CLASS_KEYS = ("dataclassification", "data_classification", "data-classification", "classification", "sensitivity")
_HEURISTIC = re.compile(r"(customer|pii|payment|card|ssn|secret|credential|patient|billing|finance|payroll|backup)", re.I)
LEVEL_ORDER = {"unclassified": 0, "public": 0, "internal": 1, "confidential": 2, "restricted": 3}


@dataclass
class BuildOptions:
    heuristic_sensitivity: bool = False
    include_unmodeled: bool = True


@dataclass
class BuildResult:
    plan: Plan
    source: SourceIndex
    graph: Graph
    ledger: Ledger
    tf: dict[str, str]
    notes: list[dict] = field(default_factory=list)
    unresolved_policies: list[dict] = field(default_factory=list)


def build_graph(plan: Plan, source_dir: str | Path, options: BuildOptions | None = None) -> BuildResult:
    options = options or BuildOptions()
    msrc = module_sources_from_plan(plan.raw)
    src = SourceIndex.build(source_dir, msrc)
    plan.apply_locals(locals_from_source(source_dir, msrc))
    g = Graph()
    ledger = Ledger()
    tf: dict[str, str] = {}

    g.add_node(Node(INTERNET, "external", "Internet", "external", "Internet (untrusted clients)", synthetic=True,
                    flags={"entry": "internet"}))

    for r in plan.resources.values():
        if r.mode != "managed" or "delete" in r.actions and "create" not in r.actions:
            continue
        aws_type, category, attrs, modeled = kind_of(r.type)
        loc = src.locate(r.base)
        attributes = {}
        for a in attrs:
            if r.is_unknown(a):
                attributes[a] = "(known after apply)"
            elif a in r.values and r.values[a] not in (None, "", []):
                attributes[a] = r.values[a]
        tf[r.address] = ledger.add(
            "TF", (r.address,), f"{r.address} ({aws_type}) planned: {'/'.join(r.actions) or 'no-op'}",
            source=loc, data={"type": r.type, "module": r.module, "actions": r.actions},
        )
        node = Node(r.address, r.type, aws_type, category, r.address, address=r.address, module=r.module,
                    source=loc, attributes=attributes, modeled=modeled, evidence=tf[r.address])
        node.sensitivity = _sensitivity(r, options, src, ledger, tf[r.address])
        g.add_node(node)

    # data sources that hold policy documents get TF records too (for citations)
    for r in plan.resources.values():
        if r.mode == "data" and r.address not in tf:
            tf[r.address] = ledger.add("TF", (r.address,), f"{r.address} (data source)", source=src.locate(r.base),
                                       data={"type": r.type, "module": r.module})

    # raw configuration references
    for r in plan.resources.values():
        if r.address not in g.nodes:
            continue
        for ref in r.all_references():
            for dep in plan.instances_of(ref):
                if dep.address in g.nodes and dep.address != r.address:
                    g.add_edge(Edge("DEPENDS_ON", r.address, dep.address, evidence=[tf[r.address], tf[dep.address]]))

    net = Network(plan, src, g, ledger, tf)
    net.run()
    iam = IamEvaluator(plan, src, g, ledger, tf)
    iam.run()
    _suppress_blocked_public_access(plan, g, ledger, tf, src)
    _derive_dataflows(g)

    # any-principal is reachable by anyone on the internet
    if ANY_PRINCIPAL in g.nodes and g.out_edges(ANY_PRINCIPAL, ("ALLOWS", "ASSUMES")):
        g.add_edge(Edge("EXPOSES", INTERNET, ANY_PRINCIPAL, label="any AWS principal / anonymous",
                        evidence=[e for x in g.out_edges(ANY_PRINCIPAL) for e in x.evidence][:1]))
    for nid, n in sorted(g.nodes.items()):
        if n.flags.get("entry") == "federated_identity":
            g.add_edge(Edge("EXPOSES", INTERNET, nid, label="federated identity without subject restriction",
                            evidence=[e for x in g.out_edges(nid) for e in x.evidence][:1]))

    # every semantic edge becomes a GRAPH record; its evidence stays as refs
    for e in sorted(g.edges.values(), key=lambda e: e.key):
        if e.type == "DEPENDS_ON":
            continue
        summary = f"{e.src} --{e.type}{'(' + e.label + ')' if e.label else ''}--> {e.dst}"
        if e.precondition:
            summary += f" [precondition: {e.precondition}]"
        if e.conditional:
            summary += " [conditional]"
        e.id = ledger.add("GRAPH", (e.type, e.src, e.dst, e.label), summary, data={
            "type": e.type, "src": e.src, "dst": e.dst, "label": e.label, "precondition": e.precondition,
            "conditional": e.conditional, **{k: v for k, v in e.data.items() if k in ("actions", "access", "ports", "denied", "symbolic")}},
            refs=e.evidence)

    ledger_ids = ledger.finalize()
    for e in g.edges.values():
        e.evidence = sorted({ledger_ids[h] for h in e.evidence if h in ledger_ids})
        if e.id:
            e.id = ledger_ids[e.id]
    for n in g.nodes.values():
        if n.evidence:
            n.evidence = ledger_ids.get(n.evidence, n.evidence)
        if n.sensitivity.get("evidence"):
            n.sensitivity["evidence"] = ledger_ids.get(n.sensitivity["evidence"], n.sensitivity["evidence"])
    return BuildResult(plan, src, g, ledger, tf, notes=net.notes, unresolved_policies=iam.unresolved)


def _sensitivity(r, options: BuildOptions, src: SourceIndex, ledger: Ledger, tf_handle: str) -> dict:
    if r.type not in ASSET_TYPES:
        return {"level": "unclassified", "basis": "not-an-asset"}
    tags = {}
    for key in ("tags", "tags_all"):
        v = r.values.get(key)
        if isinstance(v, dict):
            tags.update({str(k): str(val) for k, val in v.items()})
    for k, v in sorted(tags.items()):
        if k.lower() in _CLASS_KEYS and v.lower() in _LEVELS:
            level = _LEVELS[v.lower()]
            loc = src.locate_text(r.base, k) or src.locate(r.base)
            h = ledger.add("TF", (r.address, "classification"), f"{r.address} tagged {k} = {v}", source=loc,
                           data={"tag": k, "value": v, "level": level}, refs=[tf_handle])
            return {"level": level, "basis": f"tag:{k}", "evidence": h}
    if r.type == "aws_secretsmanager_secret":
        return {"level": "confidential", "basis": "type:secret"}
    if r.type == "aws_ssm_parameter" and r.values.get("type") == "SecureString":
        return {"level": "confidential", "basis": "type:securestring"}
    if options.heuristic_sensitivity:
        name = " ".join(str(r.values.get(a, "")) for a in ("bucket", "name", "identifier")) + " " + r.name
        if _HEURISTIC.search(name):
            return {"level": "confidential", "basis": "heuristic:name"}
    return {"level": "unclassified", "basis": "none"}


def _suppress_blocked_public_access(plan: Plan, g: Graph, ledger: Ledger, tf: dict[str, str], src: SourceIndex) -> None:
    """Public bucket grants are neutralised by S3 Block Public Access settings in the plan."""
    account_pab = plan.by_type("aws_s3_account_public_access_block")
    for key, e in list(g.edges.items()):
        if e.type != "ALLOWS" or e.src != ANY_PRINCIPAL:
            continue
        bucket = plan.resources.get(e.dst)
        if bucket is None or bucket.type != "aws_s3_bucket":
            continue
        pabs = [p for p in plan.by_type("aws_s3_bucket_public_access_block") if bucket.base in p.references.get("bucket", [])]
        via_acl = e.data.get("via") == "acl"
        flags = ("block_public_acls", "ignore_public_acls") if via_acl else ("block_public_policy", "restrict_public_buckets")
        for p in pabs + account_pab:
            on = [f for f in flags if p.values.get(f) is True]
            if on:
                h = ledger.add("NET", ("public_access_block", p.address), f"{p.address}: {', '.join(on)} = true",
                               source=src.locate(p.base), refs=[tf[p.address]])
                g.nodes[bucket.address].flags["public_access_blocked"] = {"by": p.address, "settings": on}
                del g.edges[key]
                break

    # ACL-based public read (aws_s3_bucket_acl)
    for acl in plan.by_type("aws_s3_bucket_acl"):
        value = acl.values.get("acl")
        if value not in ("public-read", "public-read-write"):
            continue
        for ref in acl.references.get("bucket", []):
            for bucket in plan.instances_of(ref):
                pabs = [p for p in plan.by_type("aws_s3_bucket_public_access_block") if bucket.base in p.references.get("bucket", [])]
                if any(p.values.get("block_public_acls") is True or p.values.get("ignore_public_acls") is True for p in pabs + account_pab):
                    g.nodes[bucket.address].flags["public_access_blocked"] = {"by": "public_access_block", "settings": ["acl"]}
                    continue
                g.add_node(Node(ANY_PRINCIPAL, "external", "AWS::IAM::AnyPrincipal", "external", "Any AWS principal", synthetic=True))
                acts = ["s3:ListBucket", "s3:GetObject"] + (["s3:PutObject"] if value == "public-read-write" else [])
                h = ledger.add("NET", ("public_acl", acl.address), f"{acl.address}: acl = {value}",
                               source=src.locate(acl.base), refs=[tf[acl.address]])
                g.nodes[bucket.address].flags["public_acl"] = value
                g.add_edge(Edge("ALLOWS", ANY_PRINCIPAL, bucket.address,
                                label="list,read" + (",write" if value == "public-read-write" else ""),
                                data={"actions": acts, "access": sorted({"list", "read"} | ({"write"} if "write" in value else set())),
                                      "via": "acl", "denied": [], "symbolic": False},
                                evidence=[h, tf[bucket.address]]))


def _derive_dataflows(g: Graph) -> None:
    """compute ASSUMES role ALLOWS asset  =>  compute READS/WRITES asset (for the DFD)."""
    for a in g.edges_of("ASSUMES"):
        src = g.nodes.get(a.src)
        if not src or src.category != "compute":
            continue
        for al in g.out_edges(a.dst, ("ALLOWS",)):
            access = set(al.data.get("access", []))
            ev = sorted(set(a.evidence) | set(al.evidence))
            if access & {"read", "list"}:
                g.add_edge(Edge("READS", a.src, al.dst, label=f"via {a.dst}",
                                data={"actions": [x for x in al.data.get("actions", []) if not _is_write(x)], "role": a.dst},
                                evidence=ev, conditional=al.conditional))
            if access & {"write", "admin"}:
                g.add_edge(Edge("WRITES", a.src, al.dst, label=f"via {a.dst}",
                                data={"actions": [x for x in al.data.get("actions", []) if _is_write(x)], "role": a.dst},
                                evidence=ev, conditional=al.conditional))


def _is_write(action: str) -> bool:
    from ..iam.evaluator import action_catalog

    for actions in action_catalog().values():
        if action in actions:
            return actions[action]["class"] in ("write", "admin")
    return False
