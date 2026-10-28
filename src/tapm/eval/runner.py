"""Benchmark runner (Plan §13-18, §38-39).

Modes compared on the same inputs:

  A  Checkov            findings; scanner hop coverage on gold paths
  B  tfsec (baseline)   findings; scanner hop coverage on gold paths
  B' Trivy              findings; scanner hop coverage on gold paths
  C  PyTM-only          generated model, pytm's own threat engine (no path engine)
  D  pipeline           graph + IAM + PyTM + path engine + scanner join
  E  pipeline + AI      D plus Jev routing and bounded agents (AI metrics only)

Scanners and PyTM do not emit attack paths, so path precision/recall is reported
for D only; for A-C we report what they do emit and how much of each gold path
their findings touch. Nothing here is estimated: every number is computed from a
run whose inputs are committed.
"""

from __future__ import annotations

import csv
import json
import platform
import statistics
import time
from pathlib import Path

import yaml

from .. import PROMPT_VERSION, SCHEMA_VERSION, __version__
from ..pytm_gen.generator import PYTM_VERSION
from ..scanners.run import PINNED
from ..util import dump_json
from .metrics import compare_fixture
from .replay import replay

COLUMNS = ["case_id", "repo", "commit", "resources", "edges", "iam_edges", "scanner_findings", "expected_paths",
           "predicted_paths", "true_positive_paths", "false_positive_paths", "false_negative_paths", "runtime_ms",
           "llm_calls", "jev_calls", "cost_usd", "unsupported_annotations",
           # extra columns
           "checkov_findings", "tfsec_findings", "trivy_findings", "pytm_threats", "edge_tp", "edge_fp", "edge_fn",
           "iam_expected", "iam_correct", "false_paths_reported", "replay_identical", "ai_backend", "ai_generated",
           "ai_accepted", "ai_rejected", "ai_human_review", "checkov_hops_covered", "tfsec_hops_covered",
           "trivy_hops_covered", "gold_path_hops",
           # pytm fed with plan evidence (pytm-findings.json)
           "pytm_generic", "pytm_confirmed", "pytm_mitigated", "pytm_needs_app_team", "pytm_ruled_out", "pytm_pack",
           "pytm_hops_covered", "pytm_pack_hops_covered",
           # verified remediation (A1): proposals re-planned and re-run
           "rem_paths", "rem_break", "rem_downgrade_only", "rem_no_fix", "rem_attempts", "rem_rejected", "rem_unverified",
           "rem_whatif_checked", "rem_whatif_agree"]

WHATIF_NAME = {"breaks_path": "breaks_path", "downgrades_path": "downgrades_path", "no_effect": "no_effect",
               "breaks_route": "breaks_path_but_alternative_exists"}


def run_benchmark(root: Path, fixtures: list[str] | None = None, replay_n: int = 10, live_scanners: bool = False,
                  ai_cfg: dict | None = None, max_paths: int | None = None, out_dir: Path | str | None = None) -> dict:
    from ..ai.harness import run_ai
    from ..ai.remediate import run_remediation
    from ..cli import ensure_plan, fixture_config
    from ..pipeline import run_deterministic
    from ..scanners.run import run_scanners

    root = Path(root)
    out_dir = Path(out_dir) if out_dir else root / "evaluations" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    fx_dirs = sorted(d for d in (root / "fixtures").iterdir()
                     if d.is_dir() and (d / "gold.yaml").exists() and (not fixtures or any(d.name.startswith(f) for f in fixtures)))
    if ai_cfg is None:
        ai_cfg = {"llm": "simulated", "jev": "local", "cassette_dir": str(root / "cassettes")}
    else:
        ai_cfg = dict(ai_cfg)
    if max_paths is not None:
        ai_cfg["max_paths"] = max_paths
    ai_active = bool(ai_cfg and ai_cfg.get("llm") != "off")
    rows, per_fixture = [], {}
    for fx in fx_dirs:
        ensure_plan(fx, quiet=True)
        if live_scanners:
            run_scanners(fx, fx / "baselines")
        gold = yaml.safe_load((fx / "gold.yaml").read_text())
        cfg = fixture_config(fx, str(root / "artifacts" / "bench" / fx.name))
        t0 = time.monotonic()
        res = run_deterministic(cfg)
        runtime_ms = int((time.monotonic() - t0) * 1000)
        m = compare_fixture(res, gold)
        ai = run_ai(res, ai_cfg) if ai_active else None
        rem = run_remediation(res, {k: ai_cfg[k] for k in ("llm", "model", "cassette_dir", "max_paths", "allow_fallback", "num_ctx", "seed") if k in ai_cfg}) if (res.paths and ai_active) else None
        rep = replay(fixture_config(fx, None, no_dfd=True), replay_n) if replay_n else {"identical_runs": None, "runs": 0}
        g = res.build.graph
        by_tool = {t: sum(1 for f in res.findings if f.tool == t) for t in ("checkov", "tfsec", "trivy")}
        cov = m["scanner_hop_coverage"]
        gold_hops = sum(len(p["nodes"]) - 1 for p in m["paths"]["matched"])
        row = {
            "case_id": fx.name, "repo": "synthetic", "commit": "",
            "resources": m["resources"]["total"],
            "edges": sum(1 for e in g.edges.values() if e.type != "DEPENDS_ON"),
            "iam_edges": len(g.edges_of("ALLOWS", "ASSUMES", "TRUSTS", "ESCALATES")),
            "scanner_findings": len(res.findings),
            "expected_paths": m["paths"]["tp"] + m["paths"]["fn"],
            "predicted_paths": len(res.paths),
            "true_positive_paths": m["paths"]["tp"], "false_positive_paths": m["paths"]["fp"],
            "false_negative_paths": m["paths"]["fn"], "runtime_ms": runtime_ms,
            "llm_calls": ai["metrics"]["llm_calls"] if ai else 0,
            "jev_calls": ai["metrics"]["jev_calls"] if ai else 0,
            "cost_usd": ai["metrics"]["cost_usd"] if ai else 0.0,
            "unsupported_annotations": ai["summary"]["rejected"] if ai else 0,
            "checkov_findings": by_tool["checkov"], "tfsec_findings": by_tool["tfsec"], "trivy_findings": by_tool["trivy"],
            "pytm_threats": res.pytm.get("threat_count"),
            "edge_tp": m["edges"]["tp"], "edge_fp": m["edges"]["fp"], "edge_fn": m["edges"]["fn"],
            "iam_expected": m["iam"]["expected"], "iam_correct": m["iam"]["correct"],
            "false_paths_reported": len(m["false_paths_found"]),
            "replay_identical": f"{rep['identical_runs']}/{rep['runs']}" if replay_n else "",
            "ai_backend": ai["manifest"]["llm_backend"] if ai else "off",
            "ai_generated": ai["summary"]["generated"] if ai else 0,
            "ai_accepted": ai["summary"]["accepted"] if ai else 0,
            "ai_rejected": ai["summary"]["rejected"] if ai else 0,
            "ai_human_review": ai["summary"]["human_review"] if ai else 0,
            "checkov_hops_covered": cov.get("checkov", {}).get("covered", 0),
            "tfsec_hops_covered": cov.get("tfsec", {}).get("covered", 0),
            "trivy_hops_covered": cov.get("trivy", {}).get("covered", 0),
            "gold_path_hops": gold_hops,
        }
        cs = (res.pytm.get("classification") or {}).get("summary", {})
        pc = m["pytm_hop_coverage"] or {}
        row.update({"pytm_generic": cs.get("generic"), "pytm_confirmed": cs.get("confirmed"), "pytm_mitigated": cs.get("mitigated"),
                    "pytm_needs_app_team": cs.get("needs_app_team"), "pytm_ruled_out": cs.get("ruled_out"),
                    "pytm_pack": cs.get("pack"), "pytm_hops_covered": pc.get("builtin", {}).get("covered"),
                    "pytm_pack_hops_covered": pc.get("with_pack", {}).get("covered")})
        rs = (rem or {}).get("summary", {})
        checked = [a for p in (rem or {}).get("paths", []) for a in p["attempts"] if a.get("effect") and a.get("what_if_predicted")]
        row.update({"rem_paths": rs.get("paths", 0), "rem_break": rs.get("verified_break", 0),
                    "rem_downgrade_only": rs.get("verified_downgrade_only", 0), "rem_no_fix": rs.get("no_verified_fix", 0),
                    "rem_attempts": rs.get("attempts", 0), "rem_rejected": rs.get("rejected", 0),
                    "rem_unverified": rs.get("unverified", 0), "rem_whatif_checked": len(checked),
                    "rem_whatif_agree": sum(1 for a in checked if WHATIF_NAME.get(a["effect"]) == a["what_if_predicted"])})
        rem_detail = None
        if rem:
            rem_detail = [{"path": p["path"], "result": p["result"],
                           "attempts": [{k: a.get(k) for k in ("n", "status", "effect", "what_if_predicted", "reasons")}
                                        | {"hop": a["patch"].get("hop")} for a in p["attempts"]]}
                          for p in rem["paths"]]
        rows.append(row)
        per_fixture[fx.name] = {"metrics": m, "replay": rep, "ai_summary": ai["summary"] if ai else None,
                                "ai_metrics": ai["metrics"] if ai else None, "remediation": rem_detail}
        print(f"  {fx.name:<44} paths {row['true_positive_paths']}/{row['expected_paths']} fp={row['false_positive_paths']} "
              f"edges fp={row['edge_fp']} fn={row['edge_fn']} replay {row['replay_identical']} {runtime_ms} ms")

    with open(out_dir / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    summary = summarise(rows)
    manifest = run_manifest(ai_cfg)
    dump_json({"summary": summary, "per_fixture": per_fixture}, out_dir / "metrics.json")
    dump_json(manifest, out_dir / "manifest.json")
    return {"summary": summary, "rows": rows, "manifest": manifest}


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def summarise(rows: list[dict]) -> dict:
    tp = sum(r["true_positive_paths"] for r in rows)
    fp = sum(r["false_positive_paths"] for r in rows)
    fn = sum(r["false_negative_paths"] for r in rows)
    etp, efp, efn = (sum(r[k] for r in rows) for k in ("edge_tp", "edge_fp", "edge_fn"))
    iam_e = sum(r["iam_expected"] for r in rows)
    iam_c = sum(r["iam_correct"] for r in rows)
    rt = sorted(r["runtime_ms"] for r in rows)
    hops = sum(r["gold_path_hops"] for r in rows)
    rep = [r["replay_identical"] for r in rows if r["replay_identical"]]
    return {
        "fixtures": len(rows),
        "path_precision": _ratio(tp, tp + fp), "path_recall": _ratio(tp, tp + fn),
        "paths": {"tp": tp, "fp": fp, "fn": fn},
        "edge_precision": _ratio(etp, etp + efp), "edge_recall": _ratio(etp, etp + efn),
        "iam_mapping_accuracy": _ratio(iam_c, iam_e),
        "false_paths_reported": sum(r["false_paths_reported"] for r in rows),
        "deterministic_replay": f"{sum(1 for x in rep if x.split('/')[0] == x.split('/')[1])}/{len(rep)} fixtures fully identical",
        "median_runtime_ms": statistics.median(rt) if rt else None,
        "p95_runtime_ms": rt[min(len(rt) - 1, int(round(0.95 * (len(rt) - 1))))] if rt else None,
        "scanner_findings": {t: sum(r[f"{t}_findings"] for r in rows) for t in ("checkov", "tfsec", "trivy")},
        "scanner_hop_coverage_on_gold_paths": {t: _ratio(sum(r[f"{t}_hops_covered"] for r in rows), hops)
                                               for t in ("checkov", "tfsec", "trivy")},
        "pytm_only": {"threats": sum(r["pytm_generic"] or 0 for r in rows), "attack_paths": 0},
        "pytm_evidence": {"threats": sum(r["pytm_threats"] or 0 for r in rows),
                          **{k: sum(r[f"pytm_{k}"] or 0 for r in rows)
                             for k in ("confirmed", "mitigated", "needs_app_team", "ruled_out", "pack")},
                          "hop_coverage_builtin": _ratio(sum(r["pytm_hops_covered"] or 0 for r in rows), hops),
                          "hop_coverage_with_pack": _ratio(sum(r["pytm_pack_hops_covered"] or 0 for r in rows), hops)},
        "remediation": {k: sum(r[f"rem_{k}"] or 0 for r in rows)
                        for k in ("paths", "break", "downgrade_only", "no_fix", "attempts", "rejected", "unverified",
                                  "whatif_checked", "whatif_agree")},
        "ai": {"backend": (sorted({r["ai_backend"] for r in rows if r.get("ai_backend")})[0]
                           if len(sorted({r["ai_backend"] for r in rows if r.get("ai_backend")})) == 1
                           else ", ".join(sorted({r["ai_backend"] for r in rows if r.get("ai_backend")})) if rows else None),
               "backends": sorted({r["ai_backend"] for r in rows if r.get("ai_backend")}),
               "generated": sum(r["ai_generated"] for r in rows), "accepted": sum(r["ai_accepted"] for r in rows),
               "rejected_unsupported": sum(r["ai_rejected"] for r in rows),
               "human_review": sum(r["ai_human_review"] for r in rows),
               "llm_calls": sum(r["llm_calls"] for r in rows), "jev_calls": sum(r["jev_calls"] for r in rows),
               "cost_usd": None if any(r["cost_usd"] is None for r in rows) else round(sum(r["cost_usd"] for r in rows), 6)},
    }


def run_manifest(ai_cfg: dict | None = None) -> dict:
    import importlib.metadata as md

    def ver(pkg):
        try:
            return md.version(pkg)
        except md.PackageNotFoundError:
            return None

    cfg = ai_cfg or {}
    return {
        "tapm": __version__, "schema_version": SCHEMA_VERSION, "prompt_version": PROMPT_VERSION,
        "python": platform.python_version(), "pytm": ver("pytm") or PYTM_VERSION, "python-hcl2": ver("python-hcl2"),
        "terraform": "1.16.4 (plans committed; see fixtures/*/plan.json terraform_version)",
        "aws_provider": "6.66.0",
        "scanners": PINNED,
        "llm": cfg.get("llm") or "off", "llm_model": cfg.get("model"), "jev": cfg.get("jev"),
        "max_paths": cfg.get("max_paths"),
    }
