"""Compare a pipeline run with a fixture's gold labels (docs/methodology.md#metrics)."""

from __future__ import annotations

from collections import defaultdict

CONCERN_HOP = {"public_ingress": "EXPOSES", "public_lb": "EXPOSES", "public_ip": "EXPOSES", "public_db": "EXPOSES",
               "public_function": "EXPOSES", "imds": "ASSUMES", "iam_trust": "ASSUMES", "iam_wildcard": "ALLOWS",
               "public_bucket": "ALLOWS"}


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r}


def compare_fixture(res, gold: dict) -> dict:
    g = res.build.graph
    types = set(gold.get("labeled_edge_types") or [])
    predicted_edges = {(e.type, e.src, e.dst) for e in g.edges.values() if e.type in types}
    expected_edges = {(e["type"], e["src"], e["dst"]) for e in gold.get("expected_edges") or []}
    e_tp = predicted_edges & expected_edges

    expected_paths = [p for p in gold.get("expected_paths") or [] if p.get("label", "VALID") in ("VALID", "PARTIALLY VALID")]
    pred = {tuple(p.nodes): p for p in res.paths}
    exp = {tuple(p["hops"]): p for p in expected_paths}
    matched = []
    for k in exp.keys() & pred.keys():
        gp, pp = exp[k], pred[k]
        matched.append({"nodes": list(k), "path_id": pp.id,
                        "priority_ok": gp.get("priority") in (None, pp.priority),
                        "preconditions_ok": sorted(gp.get("preconditions") or []) == sorted(pp.preconditions),
                        "gold_priority": gp.get("priority"), "priority": pp.priority,
                        "gold_preconditions": gp.get("preconditions") or [], "preconditions": pp.preconditions})
    false_found = [fp["hops"] for fp in gold.get("expected_false_paths") or [] if tuple(fp["hops"]) in pred]

    iam_exp = {(i["principal"], i["resource"]): sorted(i["access"]) for i in gold.get("expected_iam") or []}
    iam_pred = {(e.src, e.dst): sorted(e.data.get("access", [])) for e in g.edges_of("ALLOWS")
                if not e.src.startswith("principal:")}
    iam_correct = sum(1 for k, v in iam_exp.items() if iam_pred.get(k) == v)
    iam_universe = set(iam_exp) | (set(iam_pred) if gold.get("expected_iam") is not None else set())

    # scanner hop coverage on gold paths (per tool): which hops have at least one causal finding
    coverage: dict[str, dict] = {}
    tools = sorted({f.tool for f in res.findings})
    for m in matched:
        pp = pred[tuple(m["nodes"])]
        hop_types = [h.type for h in pp.hops]
        for tool in tools:
            covered = set()
            for f in res.findings:
                if f.tool == tool and pp.id in f.causal_paths and f.concern in CONCERN_HOP:
                    covered.add(CONCERN_HOP[f.concern])
            n_cov = sum(1 for t in hop_types if t in covered)
            coverage.setdefault(tool, {"hops": 0, "covered": 0})
            coverage[tool]["hops"] += len(hop_types)
            coverage[tool]["covered"] += n_cov

    # the same measure for pytm fed with plan evidence: hops that carry a threat the plan decides (confirmed or
    # mitigated), from pytm's own library, and with the cloud threat pack. Not independent of the path engine: the
    # pack's attributes are derived from the same graph (docs/evaluation.md#pytm-fed-with-evidence).
    pytm_cov = {"builtin": {"hops": 0, "covered": 0}, "with_pack": {"hops": 0, "covered": 0}}
    cls = (getattr(res, "pytm", None) or {}).get("classification")
    if cls:
        for m in matched:
            pp = pred[tuple(m["nodes"])]
            for key, sources in (("builtin", ("pytm",)), ("with_pack", ("pytm", "pack"))):
                hops = {o["hop"] for r in cls["findings"] if r["class"] in ("confirmed", "mitigated") and r["source"] in sources
                        for o in r.get("on_paths", []) if o["path"] == pp.id}
                pytm_cov[key]["hops"] += len(pp.hops)
                pytm_cov[key]["covered"] += len(hops)

    real = [n for n in g.nodes.values() if not n.synthetic]
    return {
        "edges": {**_prf(len(e_tp), len(predicted_edges - expected_edges), len(expected_edges - predicted_edges)),
                  "fp_items": sorted(predicted_edges - expected_edges), "fn_items": sorted(expected_edges - predicted_edges)},
        "paths": {**_prf(len(matched), len(pred.keys() - exp.keys()), len(exp.keys() - pred.keys())),
                  "matched": matched, "fp_items": [list(k) for k in sorted(pred.keys() - exp.keys())],
                  "fn_items": [list(k) for k in sorted(exp.keys() - pred.keys())]},
        "false_paths_found": false_found,
        "iam": {"expected": len(iam_exp), "correct": iam_correct,
                "accuracy": iam_correct / len(iam_universe) if iam_universe else None,
                "mismatches": sorted(str(k) for k in iam_universe if iam_exp.get(k) != iam_pred.get(k))},
        "resources": {"total": len(real), "modeled": sum(1 for n in real if n.modeled),
                      "with_source_location": sum(1 for n in real if n.source)},
        "scanner_hop_coverage": coverage,
        "pytm_hop_coverage": pytm_cov if cls else None,
    }
