"""Typed security graph: nodes are resources (or synthetic principals), edges are
typed relationships, and every semantic edge carries evidence handles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Relationship vocabulary (see docs/architecture.md#relationship-types).
EDGE_TYPES = (
    "DEPENDS_ON",   # raw configuration reference (structural, never traversed)
    "CONTAINS",     # vpc -> subnet -> workload
    "ATTACHES",     # X ATTACHES Y  ==  "Y is attached to X" (sg, instance profile, role, policy)
    "EXPOSES",      # internet / any-principal -> reachable resource
    "ROUTES_TO",    # load balancer -> registered target
    "TRUSTS",       # role -> principal named in its trust policy
    "ASSUMES",      # workload / principal -> role whose credentials it can obtain
    "ALLOWS",       # principal -> resource, with the evaluated actions
    "READS",        # compute -> datastore (derived, for the DFD)
    "WRITES",       # compute -> datastore (derived, for the DFD)
    "ESCALATES",    # principal -> account admin through an IAM escalation primitive
    "RESOLVES_TO",  # DNS name -> target
)

TRAVERSABLE = ("EXPOSES", "ROUTES_TO", "ASSUMES", "ALLOWS", "ESCALATES")

INTERNET = "internet"
ANY_PRINCIPAL = "principal:any"
ACCOUNT_ADMIN = "aws:account-admin"


@dataclass
class Node:
    id: str
    type: str
    aws_type: str
    category: str  # external | network | compute | identity | data | other
    label: str
    address: str | None = None
    module: str = ""
    source: dict | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    sensitivity: dict[str, Any] = field(default_factory=lambda: {"level": "unclassified", "basis": "none"})
    flags: dict[str, Any] = field(default_factory=dict)
    evidence: str | None = None  # TF handle / id
    synthetic: bool = False
    modeled: bool = True

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "aws_type": self.aws_type,
            "category": self.category,
            "label": self.label,
            "address": self.address,
            "module": self.module,
            "source": self.source,
            "attributes": self.attributes,
            "sensitivity": self.sensitivity,
            "flags": self.flags,
            "evidence": self.evidence,
            "synthetic": self.synthetic,
            "modeled": self.modeled,
        }


@dataclass
class Edge:
    type: str
    src: str
    dst: str
    label: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)  # supporting handles, then IDs
    precondition: str | None = None
    conditional: bool = False
    id: str | None = None  # GRAPH-### once finalized

    @property
    def key(self) -> tuple:
        return (self.type, self.src, self.dst, self.label)

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "src": self.src,
            "dst": self.dst,
            "label": self.label,
            "data": self.data,
            "evidence": self.evidence,
            "precondition": self.precondition,
            "conditional": self.conditional,
        }


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple, Edge] = {}

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing:
            return existing
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> Edge:
        assert edge.type in EDGE_TYPES, edge.type
        existing = self.edges.get(edge.key)
        if existing:
            existing.evidence = sorted(set(existing.evidence) | set(edge.evidence))
            existing.conditional = existing.conditional or edge.conditional
            for k, v in edge.data.items():
                if isinstance(v, list) and isinstance(existing.data.get(k), list):
                    existing.data[k] = sorted(set(existing.data[k]) | set(v))
                else:
                    existing.data.setdefault(k, v)
            return existing
        edge.evidence = sorted(set(edge.evidence))
        self.edges[edge.key] = edge
        return edge

    def out_edges(self, node_id: str, types: tuple[str, ...] | None = None) -> list[Edge]:
        return sorted(
            (e for e in self.edges.values() if e.src == node_id and (types is None or e.type in types)),
            key=lambda e: (e.type, e.dst, e.label),
        )

    def in_edges(self, node_id: str, types: tuple[str, ...] | None = None) -> list[Edge]:
        return sorted(
            (e for e in self.edges.values() if e.dst == node_id and (types is None or e.type in types)),
            key=lambda e: (e.type, e.src, e.label),
        )

    def edges_of(self, *types: str) -> list[Edge]:
        return sorted((e for e in self.edges.values() if e.type in types), key=lambda e: e.key)

    def to_json(self) -> dict:
        return {
            "nodes": [n.to_json() for _, n in sorted(self.nodes.items())],
            "edges": [e.to_json() for e in sorted(self.edges.values(), key=lambda e: e.key)],
        }
