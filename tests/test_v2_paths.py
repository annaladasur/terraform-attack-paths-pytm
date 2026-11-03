"""Adverse V2 checks: displayed paths cannot prove target absence or clearance."""

from __future__ import annotations

import copy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tapm.ai.remediate import compare
from tapm.gate import evaluate
from tapm.graph.model import Edge, Graph, Node
from tapm.paths.engine import PathOptions, analyze_paths, find_paths, verify_reachability
from tapm.paths.whatif import what_if


def build(edges, targets=("z",), reverse=False, padding=0):
    graph = Graph()
    names = {"internet"} | set(targets) | {n for _, src, dst, *_ in edges for n in (src, dst)}
    for name in sorted(names, reverse=reverse):
        graph.add_node(Node(name, "test", "Test", "data" if name in targets else "compute", name,
                            sensitivity={"level": "confidential" if name in targets else "unclassified"}))
    for kind, src, dst, *pre in reversed(edges) if reverse else edges:
        graph.add_edge(Edge(kind, src, dst, label=kind, precondition=pre[0] if pre else None))
    for i in range(padding):
        graph.add_node(Node(f"pad-{i}", "test", "Test", "compute", f"pad-{i}"))
        graph.add_edge(Edge("ROUTES_TO", f"pad-{i}", f"pad-{(i + 1) % padding}"))
    for i, edge in enumerate(sorted(graph.edges.values(), key=lambda e: e.key), 1):
        edge.id = f"GRAPH-{i:03d}"
    return SimpleNamespace(graph=graph, ledger=SimpleNamespace(by_id=lambda: {}),
                           plan=SimpleNamespace(resources={n: None for n in names}), unresolved_policies=[])


def result(b, opts=PathOptions()):
    analysis = analyze_paths(b, opts)
    return SimpleNamespace(build=b, paths=analysis.paths, path_analysis=analysis.to_json(), pytm={},
                           cfg=SimpleNamespace(path_options=opts))


def two_targets():
    return [("EXPOSES", "internet", "wz"), ("ASSUMES", "wz", "rz", "workload_ssrf"),
            ("ALLOWS", "rz", "z"), ("EXPOSES", "internet", "wa"),
            ("ASSUMES", "wa", "ra", "workload_rce"), ("ALLOWS", "ra", "a")]


def test_cap_downgrade_checks_the_target_even_when_global_ranking_hides_it():
    b = build(two_targets(), targets=("z", "a"))
    opts = PathOptions(max_paths=1)
    [path] = find_paths(b, opts)
    assert (path.target, path.priority) == ("z", "high")
    remedy = next(r for r in what_if(b, [path], opts) if r.hop == 2)
    assert (remedy.effect, remedy.after, remedy.target_reachable) == ("downgrades_path", "medium", True)
    assert remedy.analysis_complete and remedy.remaining_paths_to_target >= 1
    assert not remedy.remaining_paths_complete
    assert next(e for e in b.graph.edges.values() if e.src == "wz").precondition == "workload_ssrf"
    inventory = analyze_paths(b, opts)
    assert {(p.target, p.reachable) for p in inventory.reachability.pairs} == {("a", True), ("z", True)}
    assert not inventory.to_json()["complete"]
    assert inventory.enumeration["truncated_by"] == ["max_paths"]


def test_remediation_cannot_accept_a_capped_run_as_a_proven_break():
    b = build(two_targets(), targets=("z", "a"))
    before = result(b, PathOptions(max_paths=1))
    changed = copy.deepcopy(b)
    for key, edge in changed.graph.edges.items():
        if edge.src == "wz" and edge.type == "ASSUMES":
            changed.graph.edges[key] = replace(edge, precondition="workload_rce")
    after = result(changed, PathOptions(max_paths=1))
    assert after.paths[0].target == "a"  # the old emitted-list-only comparison said PROVEN_BREAK
    compared = compare(before, after, before.paths[0])
    assert compared["status"] == "UNVERIFIED"
    assert compared["effect"] == "downgrades_path"
    assert compared["target_reachable"] is True


def alternative_graph():
    # The first route has three edges. Its alternate has nine, beyond display depth eight.
    edges = [("EXPOSES", "internet", "short"), ("ASSUMES", "short", "role", "workload_ssrf"),
             ("ALLOWS", "role", "z"), ("EXPOSES", "internet", "long-0")]
    edges += [("ROUTES_TO", f"long-{i}", f"long-{i + 1}") for i in range(7)]
    edges += [("ALLOWS", "long-7", "z")]
    return build(edges)


def test_depth_hidden_alternative_prevents_break_claim_and_clearance():
    b = alternative_graph()
    before = result(b)
    [path] = before.paths
    remedy = next(r for r in what_if(b, [path]) if r.hop == 3)
    assert remedy.effect == "breaks_path_but_alternative_exists"
    assert remedy.target_reachable is True
    changed = copy.deepcopy(b)
    changed.graph.edges = {k: e for k, e in changed.graph.edges.items() if not (e.src == "role" and e.dst == "z")}
    after = result(changed)
    assert after.paths == []
    [pair] = after.path_analysis["reachability"]["pairs"]
    assert pair["reachable"] and len(pair["witness"]["hops"]) == 9
    assert compare(before, after, path)["status"] == "UNVERIFIED"
    assert evaluate([], [], level="validate", analysis=after.path_analysis)["decision"] == "fail"


def test_depth_boundary_is_complete_at_exactly_eight_edges():
    edges = [("EXPOSES", "internet", "n0")]
    edges += [("ROUTES_TO", f"n{i}", f"n{i + 1}") for i in range(6)]
    edges += [("ALLOWS", "n6", "z")]
    analysis = analyze_paths(build(edges))
    assert analysis.to_json()["complete"]
    assert len(analysis.paths[0].hops) == 8
    assert analyze_paths(build(edges), PathOptions(max_depth=7)).paths == []
    assert not analyze_paths(build(edges), PathOptions(max_depth=7)).to_json()["complete"]


def test_hard_budget_bounds_exploding_prefixes_and_preserves_unknown_absence():
    # Many distinct simple prefixes reach shared nodes; verification visits each node once.
    edges = [("EXPOSES", "internet", f"layer0-{i}") for i in range(5)]
    for layer in range(5):
        edges += [("ROUTES_TO", f"layer{layer}-{i}", f"layer{layer + 1}-{j}")
                  for i in range(5) for j in range(5)]
    edges += [("ALLOWS", "layer5-4", "z")]
    b = build(edges)
    analysis = analyze_paths(b, PathOptions(max_expansions=40))
    assert analysis.enumeration["expansions"] == 40
    assert "max_expansions" in analysis.enumeration["truncated_by"]
    assert analysis.reachability.pairs[0].reachable is True
    assert analysis.reachability.steps <= len(edges)
    interrupted = verify_reachability(b, PathOptions(max_verification_steps=3))
    assert interrupted.steps == 3 and not interrupted.complete
    assert interrupted.pairs[0].reachable is None
    assert evaluate([], [], level="prevent", analysis=analysis.to_json())["decision"] == "fail"
    assert evaluate([], [], level="validate", analysis={"complete": False, "reachability": interrupted.to_json()})["decision"] == "fail"


@pytest.mark.parametrize("reverse,padding", [(False, 0), (True, 0), (False, 200), (True, 200)])
def test_order_and_disconnected_padding_do_not_change_semantic_pairs(reverse, padding):
    b = build(two_targets(), targets=("z", "a", "unreachable"), reverse=reverse, padding=padding)
    analysis = analyze_paths(b, PathOptions(max_paths=1))
    assert [(p.entry, p.target, p.reachable) for p in analysis.reachability.pairs] == [
        ("internet", "a", True), ("internet", "unreachable", False), ("internet", "z", True)]
    assert analysis.paths[0].nodes == ["internet", "wz", "rz", "z"]
    assert analysis.reachability.steps == 6


def test_terminal_allows_and_intermediate_assets_match_display_semantics():
    edges = [("EXPOSES", "internet", "w"), ("ALLOWS", "w", "not-asset"),
             ("ROUTES_TO", "not-asset", "z"), ("EXPOSES", "internet", "a"), ("ROUTES_TO", "a", "z")]
    analysis = analyze_paths(build(edges, targets=("a", "z")))
    assert [(p.target, p.reachable) for p in analysis.reachability.pairs] == [("a", True), ("z", False)]
    assert [p.target for p in analysis.paths] == ["a"]


def test_unknown_policy_restrictions_prevent_gate_and_remediation_success():
    b = build([("EXPOSES", "internet", "w"), ("ALLOWS", "w", "z")])
    before = result(b)
    changed = copy.deepcopy(b)
    changed.graph.edges = {k: e for k, e in changed.graph.edges.items() if e.type != "ALLOWS"}
    changed.graph.nodes["w"].flags["iam_uncertainties"] = [{"reasons": ["unresolved permissions boundary"]}]
    after = result(changed)
    assert after.path_analysis["policy_complete"] is False
    assert evaluate([], [], level="validate", analysis=after.path_analysis)["decision"] == "fail"
    assert compare(before, after, before.paths[0])["status"] == "UNVERIFIED"


def test_zero_display_cap_does_not_change_verified_reachability():
    analysis = analyze_paths(build(two_targets(), targets=("z", "a")), PathOptions(max_paths=0))
    assert analysis.paths == [] and analysis.reachability.complete
    assert all(p.reachable for p in analysis.reachability.pairs)
    assert evaluate([], [], level="validate", analysis=analysis.to_json())["decision"] == "fail"


def test_interrupted_target_search_makes_what_if_inconclusive():
    b = build([("EXPOSES", "internet", "w"), ("ALLOWS", "w", "z")])
    [path] = find_paths(b)
    remedy = next(r for r in what_if(b, [path], PathOptions(max_verification_steps=0)) if r.hop == 2)
    assert remedy.effect == "inconclusive"
    assert remedy.target_reachable is None and not remedy.analysis_complete


def test_reachability_inventory_keeps_each_user_entry_and_global_budget_unknowns():
    b = build([("EXPOSES", "internet", "w"), ("ALLOWS", "w", "z"), ("ALLOWS", "user", "z")])
    b.graph.nodes["user"].type = "aws_iam_user"
    analysis = analyze_paths(b, PathOptions(user_entries=True, max_verification_steps=2))
    assert [(p.entry, p.target, p.reachable) for p in analysis.reachability.pairs] == [
        ("internet", "z", True), ("user", "z", None)]
    assert not analysis.reachability.complete
    uncapped = verify_reachability(b, PathOptions(user_entries=True), only_entry="user")
    assert uncapped.complete and uncapped.pairs[0].reachable
    assert uncapped.pairs[0].witness.preconditions == ["credential_compromise"]
