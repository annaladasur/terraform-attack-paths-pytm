#!/usr/bin/env python3
"""Sealed V2 regression/known-input evaluation; never writes frozen results.

Expected outcomes are deliberately external to the runner. Verify the protocol
and all declared inputs before importing or executing the engine.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "evaluations" / "v2"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_seal(protocol_path=SUITE / "protocol.json"):
    protocol = json.loads(Path(protocol_path).read_text())
    for relative, expected in protocol["sealed_files"].items():
        if sha256(ROOT / relative) != expected:
            raise ValueError(f"sealed input changed: {relative}")
    checks = json.loads((SUITE / "expected-checks.json").read_text())["checks"]
    if len({check["id"] for check in checks}) != len(checks):
        raise ValueError("duplicate supplemental check id")
    if {check["id"]: canonical_hash(check["input"]) for check in checks} != protocol["check_input_sha256"]:
        raise ValueError("supplemental input inventory changed")
    return protocol, checks


def resource(kind, name, values):
    return {"address": f"{kind}.{name}", "mode": "managed", "type": kind, "name": name, "values": values}


def iam_plan(spec):
    kind = spec.get("principal_type", "aws_iam_user")
    pvalues = {"name": "tester", "arn": f"arn:aws:iam::111122223333:{'role' if kind == 'aws_iam_role' else 'user'}/tester"}
    if kind == "aws_iam_role":
        pvalues["assume_role_policy"] = json.dumps({"Statement": []})
    resources = [resource(kind, "tester", pvalues), resource("aws_s3_bucket", "asset", {
        "bucket": "v2-sealed-asset", "arn": "arn:aws:s3:::v2-sealed-asset", "tags": {"DataClassification": "confidential"}})]
    if "identity" in spec:
        policy_type, attr = ("aws_iam_role_policy", "role") if kind == "aws_iam_role" else ("aws_iam_user_policy", "user")
        resources.append(resource(policy_type, "identity", {attr: "tester", "policy": json.dumps({"Statement": spec["identity"]})}))
    if "boundary" in spec:
        pvalues["permissions_boundary"] = "arn:aws:iam::111122223333:policy/limit"
        resources.append(resource("aws_iam_policy", "limit", {"name": "limit", "policy": json.dumps({"Statement": spec["boundary"]})}))
    if spec.get("unresolved_boundary"):
        pvalues["permissions_boundary"] = "arn:aws:iam::111122223333:policy/not-in-plan"
    if "resource_policy" in spec:
        resources.append(resource("aws_s3_bucket_policy", "asset", {"bucket": "v2-sealed-asset", "policy": json.dumps({"Statement": spec["resource_policy"]})}))
    raw = {"format_version": "1.2", "terraform_version": "1.16.4", "planned_values": {"root_module": {"resources": resources}}}
    if spec.get("unknown_boundary"):
        raw["resource_changes"] = [{"address": f"{kind}.tester", "type": kind, "name": "tester", "change": {
            "actions": ["create"], "after": pvalues, "after_unknown": {"permissions_boundary": True}}}]
    return raw


def synthetic_graph(spec):
    from tapm.graph.model import Edge, Graph, Node
    graph = Graph()
    nodes = [Node("internet", "external", "Internet", "external", "Internet", synthetic=True)]
    for name in spec["targets"]:
        nodes.append(Node(name, "aws_s3_bucket", "AWS::S3::Bucket", "data", name,
                          sensitivity={"level": "confidential", "basis": "tag"}))
    mids = {name for edge in spec["edges"] for name in edge[:2]} - {"internet", *spec["targets"]}
    nodes.extend(Node(name, "aws_instance", "AWS::EC2::Instance", "compute", name) for name in sorted(mids))
    nodes.extend(Node(f"padding-{i:03d}", "aws_instance", "AWS::EC2::Instance", "compute", "padding") for i in range(spec.get("padding", 0)))
    if spec.get("reverse"):
        nodes.reverse()
    for node in nodes:
        graph.add_node(node)
    edges = [Edge(kind, src, dst, id=f"SEALED-{i}") for i, (src, dst, kind) in enumerate(spec["edges"])]
    if spec.get("reverse"):
        edges.reverse()
    for edge in edges:
        graph.add_edge(edge)
    return SimpleNamespace(graph=graph, ledger=SimpleNamespace(by_id=lambda: {}))


def execute_check(check, tmp):
    from tapm.eval.tier2 import score
    from tapm.graph.build import build_graph
    from tapm.paths.engine import PathOptions, analyze_paths
    from tapm.terraform.plan import parse_plan

    spec, expected = check["input"], check["expected"]
    if check["kind"] == "iam":
        build = build_graph(parse_plan(iam_plan(spec)), tmp)
        principal = spec.get("principal_type", "aws_iam_user") + ".tester"
        action = spec.get("inspect_action", "s3:GetObject")
        grants = [edge for edge in build.graph.edges_of("ALLOWS") if edge.src == principal and edge.dst == "aws_s3_bucket.asset" and action in edge.data.get("actions", [])]
        public = [edge for edge in build.graph.edges_of("ALLOWS") if edge.src == "principal:any" and edge.dst == "aws_s3_bucket.asset" and action in edge.data.get("actions", [])]
        observed = {"allowed": bool(grants), "conditional": bool(grants and grants[0].conditional), "public_allowed": bool(public)}
        if "unknown_visible" in expected:
            observed["unknown_visible"] = bool(build.unresolved_policies or build.graph.nodes[principal].flags.get("iam_uncertainties"))
        analysis = analyze_paths(build, PathOptions(user_entries=True))
        truth = [{"entry": principal, "target": "aws_s3_bucket.asset", "label": "UNKNOWN" if expected.get("conditional") else ("VALID" if expected["allowed"] else "INVALID")},
                 {"entry": "internet", "target": "aws_s3_bucket.asset", "label": "UNKNOWN" if spec.get("public_unknown") else ("VALID" if expected["public_allowed"] else "INVALID")}]
        inventory = score(SimpleNamespace(paths=analysis.paths, path_analysis=analysis.to_json()), {"expected": truth})["prediction_accounting"]
        return observed, {"input_plan_sha256": canonical_hash(iam_plan(spec)), "pair_inventory": inventory,
                          "predeclared_pair_labels": truth, "path_analysis": analysis.to_json()}
    if check["kind"] == "accounting":
        paths = [SimpleNamespace(entry=e, target=t) for e, t in spec["predictions"]]
        result = score(SimpleNamespace(paths=paths), {"expected": spec["gold"]}, adjudications=spec.get("adjudications"))
        acct = result["prediction_accounting"]
        observed = {"unlabeled_paths": result["unlabeled_paths"], "unique_predicted_pairs": acct["unique_predicted_pairs"],
                    "duplicate_routes": acct["duplicate_routes"], "unadjudicated_pairs": acct["unadjudicated_pairs"],
                    "legacy_counts": [result[key] for key in ("tp", "fn", "fp", "tn")], "by_label": acct["by_label"]}
        return observed, {"score": result}
    if check["kind"] == "paths":
        build = synthetic_graph(spec)
        analysis = analyze_paths(build, PathOptions(**spec.get("options", {})))
        metadata = analysis.to_json()
        verified = metadata["reachability"]
        observed = {"displayed": len(analysis.paths), "reachable_pairs": sorted([[p["entry"], p["target"]] for p in verified["pairs"] if p["reachable"] is True]),
                    "verification_complete": verified["complete"], "unknown_pairs": sum(p["reachable"] is None for p in verified["pairs"])}
        if spec.get("compare_reversed_padding"):
            other_spec = {**spec, "reverse": True, "padding": 40}
            other = analyze_paths(synthetic_graph(other_spec), PathOptions(**spec.get("options", {}))).to_json()["reachability"]
            observed["invariant_under_order_and_padding"] = {(p["entry"], p["target"], p["reachable"]) for p in other["pairs"]} == {(p["entry"], p["target"], p["reachable"]) for p in verified["pairs"]}
        if spec.get("what_if_alternative"):
            from tapm.paths.whatif import what_if
            visible = analyze_paths(build, PathOptions(max_paths=100)).paths
            target = next(path for path in visible if path.target == "z")
            remedies = what_if(build, [target], PathOptions(max_paths=1))
            observed["alternative_preserved"] = all(remedy.effect == "breaks_path_but_alternative_exists" for remedy in remedies)
        inventory = score(SimpleNamespace(paths=analysis.paths, path_analysis=metadata), {"expected": spec["truth_pairs"]})["prediction_accounting"]
        return observed, {"path_analysis": metadata, "pair_inventory": inventory}
    if check["kind"] == "known_plan":
        import yaml
        plan = parse_plan(json.loads(gzip.decompress((ROOT / spec["plan"]).read_bytes())))
        build = build_graph(plan, ROOT / spec["source"])
        analysis = analyze_paths(build, PathOptions(user_entries=True, extra_targets=tuple(spec["targets"])))
        pairs = {(pair["entry"], pair["target"]): pair["reachable"] for pair in analysis.to_json()["reachability"]["pairs"]}
        observed = {"pairs": [{"entry": row["entry"], "target": row["target"], "reachable": pairs.get((row["entry"], row["target"]), False)} for row in spec["pairs"]],
                    "verification_complete": analysis.to_json()["reachability"]["complete"]}
        gold = yaml.safe_load((ROOT / spec["gold"]).read_text())
        result = score(SimpleNamespace(paths=analysis.paths, path_analysis=analysis.to_json()), gold, adjudications=spec["pairs"])
        return observed, {"score": result, "path_analysis": analysis.to_json(), "notes": build.notes}
    raise ValueError(f"unknown supplemental kind: {check['kind']}")


def wilson(successes, total):
    if not total:
        return None
    z = 1.959963984540054
    p, z2 = successes / total, z * z
    center = (p + z2 / (2 * total)) / (1 + z2 / total)
    half = z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total)) / (1 + z2 / total)
    return [round(center - half, 4), round(center + half, 4)]


def run(out_dir):
    import tempfile
    out_dir = Path(out_dir).resolve()
    frozen_dir = (ROOT / "evaluations" / "results").resolve()
    if out_dir == frozen_dir or frozen_dir in out_dir.parents:
        raise ValueError("V2 output must not be inside frozen evaluations/results")
    protocol, checks = verify_seal()
    started = datetime.now(timezone.utc).isoformat()
    rows = []
    with tempfile.TemporaryDirectory(prefix="tapm-v2-eval-") as temporary:
        for check in checks:
            try:
                observed, detail = execute_check(check, Path(temporary))
                matches = {key: observed.get(key) == value for key, value in check["expected"].items()}
                rows.append({"id": check["id"], "kind": check["kind"], "passed": all(matches.values()),
                             "expected": check["expected"], "observed": observed, "matches": matches, **detail})
            except Exception as exc:
                rows.append({"id": check["id"], "kind": check["kind"], "passed": False, "error": f"{type(exc).__name__}: {exc}"})
    passed = sum(row["passed"] for row in rows)
    by_kind = {kind: {"passed": sum(r["passed"] for r in rows if r["kind"] == kind), "total": sum(r["kind"] == kind for r in rows)} for kind in sorted({r["kind"] for r in rows})}
    for counts in by_kind.values():
        counts["wilson_95"] = wilson(counts["passed"], counts["total"])
    frozen_integrity = {relative: sha256(ROOT / relative) == digest for relative, digest in protocol["frozen_files"].items()}
    known = [row["score"]["prediction_accounting"] for row in rows if row["kind"] == "known_plan" and "score" in row]
    known_tp = sum(row["coverage_score"]["tp"] for row in known)
    known_fp = sum(row["coverage_score"]["fp"] for row in known)
    known_fn = sum(row["coverage_score"]["fn"] for row in known)
    output = {"schema_version": 2, "evaluation_class": protocol["evaluation_class"], "sealed_at_utc": protocol["sealed_at_utc"],
              "started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
              "protocol_sha256": sha256(SUITE / "protocol.json"), "expected_checks_sha256": sha256(SUITE / "expected-checks.json"),
              "engine_source_sha256": {str(path.relative_to(ROOT)): sha256(path) for path in sorted((ROOT / "src" / "tapm").rglob("*.py"))},
              "summary": {"operational_checks_passed": passed, "operational_checks_total": len(rows),
                          "operational_wilson_95": wilson(passed, len(rows)), "by_kind": by_kind,
                          "known_plan_label_limited_coverage": {
                              "precision_numerator": known_tp, "precision_denominator": known_tp + known_fp,
                              "recall_numerator": known_tp, "recall_denominator": known_tp + known_fn,
                              "precision_wilson_95": wilson(known_tp, known_tp + known_fp),
                              "recall_wilson_95": wilson(known_tp, known_tp + known_fn),
                              "predicted_pairs": sum(row["unique_predicted_pairs"] for row in known),
                              "by_label": {label: sum(row["by_label"][label] for row in known) for label in ("VALID", "INVALID", "OUT_OF_SCOPE", "UNKNOWN", "UNLABELED")},
                              "scope": "two familiar plans; frozen gold plus predeclared supplemental pairs; no unseen-repository inference"},
                          "all_frozen_files_unchanged": all(frozen_integrity.values()),
                          "interpretation": "Boolean regression/known-input checks; not a new independent corpus accuracy estimate. Pair inventories and label-limited coverage scores are separate."},
              "frozen_integrity": frozen_integrity, "checks": rows}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    lines = ["# V2 supplemental evaluation", "", "Observed: sealed regression/known-input evaluation. Previously evaluated repositories remain familiar inputs; no unseen-repository claim.", "",
             f"Operational checks: **{passed}/{len(rows)}**, Wilson 95% {wilson(passed, len(rows))}. These boolean checks are not coverage precision/recall.", "",
             "| Check family | Passed / total | Wilson 95% interval |", "|---|---:|---|" ]
    for kind, counts in by_kind.items():
        lines.append(f"| {kind} | {counts['passed']}/{counts['total']} | {counts['wilson_95']} |")
    lines.extend(["", f"Protocol sealed at `{protocol['sealed_at_utc']}`; first engine call in this run after `{started}`. Protocol SHA-256 `{output['protocol_sha256']}`. Expected/input bundle SHA-256 `{output['expected_checks_sha256']}`.", "",
                  f"The initial protocol hash was `{protocol.get('initial_seal', {}).get('protocol_sha256', output['protocol_sha256'])}`. The first execution was **{protocol.get('first_execution', {}).get('passed', passed)}/{protocol.get('first_execution', {}).get('total', len(rows))}**; its synthetic what-if harness lacked an empty ledger. The protocol retains that error and the runner amendments. Expected outcomes and input specifications have stayed unchanged.", "",
                  f"Familiar-plan label-limited coverage: precision **{known_tp}/{known_tp + known_fp}** (Wilson 95% {wilson(known_tp, known_tp + known_fp) if known_tp + known_fp else 'n/a'}), recall **{known_tp}/{known_tp + known_fn}** (Wilson 95% {wilson(known_tp, known_tp + known_fn) if known_tp + known_fn else 'n/a'}). The two familiar plans emitted {sum(row['unique_predicted_pairs'] for row in known)} unique pairs; excluded prediction labels are {output['summary']['known_plan_label_limited_coverage']['by_label']}. These are narrow known-input coverage counts, not the whole Tier-2 corpus.", "",
                  "Every known-plan prediction is inventoried by exact entry-target pair; multiple displayed routes count once. Frozen gold is retained. Supplemental exact labels cannot override it. UNKNOWN, OUT_OF_SCOPE and UNLABELED are visible exclusions from label-limited precision/recall, so a clean operational run does not mean perfect whole-output accuracy.", "",
                  "Historical context only: original blind precision **28/32**, recall **28/36**; historical same-corpus retest precision **33/34**, recall **33/36**. One human labeler, with eight automated disputed proposals. These are frozen historical records, not this supplemental run's metrics.", "",
                  f"Frozen artifact integrity: {'all unchanged' if all(frozen_integrity.values()) else 'FAILED; inspect results.json'}. No frozen results or gold written.", "",
                  "| Check | Result |", "|---|---|" ])
    lines.extend(f"| {row['id']} | {'PASS' if row['passed'] else 'FAIL'} |" for row in rows)
    (out_dir / "RESULTS.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(output["summary"], indent=2))
    return 0 if passed == len(rows) and all(frozen_integrity.values()) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "artifacts" / "v2", help="new run directory; frozen evaluations/results is rejected")
    parser.add_argument("--verify-seal", action="store_true", help="verify predeclared inputs without executing the engine")
    args = parser.parse_args()
    if args.verify_seal:
        protocol, checks = verify_seal()
        print(json.dumps({"sealed_at_utc": protocol["sealed_at_utc"], "checks": len(checks), "protocol_sha256": sha256(SUITE / "protocol.json")}, indent=2))
    else:
        raise SystemExit(run(args.out_dir))
