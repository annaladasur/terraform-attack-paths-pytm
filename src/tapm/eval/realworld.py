"""Real-world benign modules benchmark: public production-grade modules evaluated for false-path suppression."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import yaml

from ..pipeline import RunConfig, run_deterministic
from ..scanners.run import run_scanners, validate_baseline
from ..terraform.offline_plan import plan_fixture
from ..util import PROJECT_ROOT, dump_json

RW = PROJECT_ROOT / "evaluations" / "realworld"


def repo_dir(url: str) -> Path:
    base = Path(os.environ.get("TAPM_REALWORLD_REPOS", PROJECT_ROOT / ".tools" / "realworld-repos"))
    owner, name = url.rstrip("/").split("/")[-2:]
    return base / owner.lower() / name.lower()


def ensure_repo(url: str, commit: str) -> Path:
    d = repo_dir(url)
    if not (d / ".git").exists():
        d.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--depth", "1", url, str(d)], check=True, env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"})
    head = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != commit:
        subprocess.run(["git", "-C", str(d), "fetch", "-q", "--depth", "1", "origin", commit], check=True)
        subprocess.run(["git", "-C", str(d), "checkout", "-q", commit], check=True)
    return d


def case_plan(case: dict, src: Path, manifest: dict) -> Path:
    gz = RW / "plans" / f"{case['id']}.json.gz"
    plain = PROJECT_ROOT / "artifacts" / "realworld" / case["id"] / "plan.json"
    plain.parent.mkdir(parents=True, exist_ok=True)
    if gz.exists():
        plain.write_bytes(gzip.decompress(gz.read_bytes()))
        return plain
    # If uncompressed plan doesn't exist, generate plan using offline planner
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "plan.json"
        variables = {k: str(v).replace("{RW}", str(RW)) for k, v in (case.get("variables") or {}).items()}
        ctx = (src / case["context"]).resolve() if case.get("context") else None
        plan_fixture(src, out, use_cache=False, write_cache=False, mock_aws=manifest.get("mock_aws"),
                     variables=variables, context_dir=ctx)
        plain.write_text(out.read_text(encoding="utf-8"), encoding="utf-8")
        with open(gz, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz_out:
            gz_out.write(out.read_bytes())
    return plain


def score(res, gold: dict) -> dict:
    reach = {(p.entry, p.target) for p in res.paths}
    rows, tp, fn, fp, tn = [], 0, 0, 0, 0
    oos_found = 0
    labeled_entries = set()
    for e in gold.get("expected") or []:
        found = (e["entry"], e["target"]) in reach
        labeled_entries.add(e["entry"])
        lab = e["label"]
        if lab == "VALID":
            tp += found
            fn += not found
        elif lab == "INVALID":
            fp += found
            tn += not found
        else:
            oos_found += found
        rows.append({"entry": e["entry"], "target": e["target"], "label": lab, "found": found})
    unlabeled = sorted({f"{p.entry} -> {p.target}" for p in res.paths if p.entry not in labeled_entries})
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "out_of_scope": sum(1 for r in rows if r["label"] == "OUT_OF_SCOPE"),
        "out_of_scope_found": oos_found, "rows": rows, "unlabeled_paths": unlabeled,
    }


def run_realworld(only: list[str] | None = None, tag: str = "benign",
                  manifest_name: str = "manifest.yaml", out_dir: str | Path | None = None,
                  write_results: bool = False, command: str | None = None) -> dict:
    from .metadata import get_eval_metadata

    manifest = yaml.safe_load((RW / manifest_name).read_text())
    results = []
    for case in manifest["cases"]:
        if only and not any(case["id"].startswith(o) for o in only):
            continue
        repo = manifest["repos"][case["repo"]]
        gz = RW / "plans" / f"{case['id']}.json.gz"
        base = RW / "baselines" / case["id"]
        cached = gz.exists() and (base / "versions.json").exists()

        local_src = repo_dir(repo["url"]) / case["path"]
        vendored = RW / "sources" / case["id"]

        if local_src.exists():
            src = local_src
        elif vendored.exists():
            src = vendored
        elif cached:
            src = vendored if vendored.exists() else local_src
        else:
            src = ensure_repo(repo["url"], repo["commit"]) / case["path"]
        gold = yaml.safe_load((RW / case["gold"]).read_text())
        rec = {
            "id": case["id"], "repo": repo["url"], "commit": repo["commit"],
            "license": repo["license"], "terraform": case.get("terraform"),
        }
        try:
            plan = case_plan(case, src, manifest)
        except Exception as e:
            rec["error"] = f"plan failed: {str(e)[-600:]}"
            results.append(rec)
            print(f"  {case['id']:<42} PLAN FAILED")
            continue
        base = RW / "baselines" / case["id"]
        if not (base / "versions.json").exists() and src.exists():
            run_scanners(src, base)
        validate_baseline(base)
        opts = case.get("options") or {}
        cfg = RunConfig(
            tf_dir=src, plan_path=plan, out_dir=PROJECT_ROOT / "artifacts" / "realworld" / case["id"],
            name=case["id"], baselines_dir=base if base.exists() else None,
            heuristic_sensitivity=bool(opts.get("heuristic_sensitivity")),
            user_entries=bool(opts.get("user_entries")),
            extra_targets=tuple(gold.get("targets") or []),
            render_dfd=False,
        )
        t0 = time.monotonic()
        res = run_deterministic(cfg)
        rec["runtime_ms"] = int((time.monotonic() - t0) * 1000)
        real = [n for n in res.build.graph.nodes.values() if not n.synthetic]
        rec.update({
            "resources": len(real), "modeled": sum(1 for n in real if n.modeled),
            "semantic_edges": sum(1 for e in res.build.graph.edges.values() if e.type != "DEPENDS_ON"),
            "paths": len(res.paths), "unresolved_policies": len(res.build.unresolved_policies),
            "scanner_findings": {t: sum(1 for f in res.findings if f.tool == t) for t in ("checkov", "tfsec", "trivy")},
            "score": score(res, gold),
        })
        s = rec["score"]
        print(f"  {case['id']:<42} res={rec['resources']:<4} paths={rec['paths']:<4} "
              f"TP={s['tp']} FN={s['fn']} FP={s['fp']} TN={s['tn']} {rec['runtime_ms']} ms")
        results.append(rec)

    tp = sum(r.get("score", {}).get("tp", 0) for r in results)
    fn = sum(r.get("score", {}).get("fn", 0) for r in results)
    fp = sum(r.get("score", {}).get("fp", 0) for r in results)
    tn = sum(r.get("score", {}).get("tn", 0) for r in results)

    paths_emitted = sum(r.get("paths", 0) for r in results)
    paths_scored = tp + fp
    labeled_valid = sum(sum(1 for row in r.get("score", {}).get("rows", []) if row.get("label") == "VALID") for r in results)
    labeled_invalid = sum(sum(1 for row in r.get("score", {}).get("rows", []) if row.get("label") == "INVALID") for r in results)

    adj_file = PROJECT_ROOT / "evaluations" / "tier2" / "ADJUDICATION.md"
    adj_text = adj_file.read_text(encoding="utf-8") if adj_file.exists() else ""
    unadjudicated = 0
    for r in results:
        rows = r.get("score", {}).get("rows", [])
        oos_found = [f"{row['entry']} -> {row['target']}" for row in rows if row.get("label") == "OUT_OF_SCOPE" and row.get("found")]
        unscored = list(r.get("score", {}).get("unlabeled_paths", [])) + oos_found
        for p in unscored:
            if p not in adj_text and not all(part.strip() in adj_text for part in p.split("->")):
                unadjudicated += 1

    summary = {
        "tag": tag,
        "cases": len(results),
        "paths_emitted": paths_emitted,
        "paths_scored": paths_scored,
        "paths_unadjudicated": unadjudicated,
        "labeled_valid": labeled_valid,
        "labeled_invalid": labeled_invalid,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "false_path_rate": round(fp / (tp + fp), 4) if (tp + fp) else None,
        "reachability_precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "reachability_recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
    }

    gold_files = [RW / case["gold"] for case in manifest["cases"] if (not only or any(case["id"].startswith(o) for o in only))]
    meta = get_eval_metadata(gold_path=RW, tag=tag, command=command, gold_files=gold_files)
    summary["command"] = meta["command"]
    summary["tool_versions"] = meta["tool_versions"]
    summary["git_sha"] = meta["git_sha"]
    if "gold_commit" in meta:
        summary["gold_commit"] = meta["gold_commit"]
    if "gold_files" in meta:
        summary["gold_files"] = meta["gold_files"]

    out = {
        "metadata": meta,
        "tag": tag,
        "command": meta["command"],
        "tool_versions": meta["tool_versions"],
        "git_sha": meta["git_sha"],
        "gold_commit": meta.get("gold_commit"),
        "gold_files": meta.get("gold_files", {}),
        "summary": summary,
        "cases": results,
        "markdown": markdown(summary, results),
    }

    if out_dir:
        target_dir = Path(out_dir)
    elif write_results:
        target_dir = PROJECT_ROOT / "evaluations" / "results"
    else:
        target_dir = PROJECT_ROOT / "artifacts"

    dump_json(out, target_dir / f"realworld-{tag}.json")
    if tag != "benign" and write_results and out_dir is None:
        dump_json(out, target_dir / "realworld-benign.json")
    return out


def markdown(summary: dict, results: list[dict]) -> str:
    prec = summary['reachability_precision'] if summary.get('reachability_precision') is not None else 'n/a'
    rec = summary['reachability_recall'] if summary.get('reachability_recall') is not None else 'n/a'
    fpr = summary['false_path_rate'] if summary.get('false_path_rate') is not None else 'n/a'
    L = [
        f"Run `{summary['tag']}`: {summary['cases']} benign cases. Reachability over VALID/INVALID labels: "
        f"TP {summary['tp']}, FN {summary['fn']}, FP {summary['fp']}, TN {summary['tn']}; "
        f"precision {prec}, recall {rec}, "
        f"false-path rate {fpr}.",
        "",
        "| Case | Commit | Resources (modeled) | Findings C/tf/T | Paths | TP | FN | FP | TN | Runtime |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        if "error" in r:
            L.append(f"| {r['id']} | `{r['commit'][:7]}` | plan failed | | | | | | | |")
            continue
        s, f = r["score"], r["scanner_findings"]
        L.append(
            f"| {r['id']} | `{r['commit'][:7]}` | {r['resources']} ({r['modeled']}) | "
            f"{f['checkov']}/{f['tfsec']}/{f['trivy']} | {r['paths']} | {s['tp']} | {s['fn']} | "
            f"{s['fp']} | {s['tn']} | {r['runtime_ms']} ms |"
        )
    return "\n".join(L)
