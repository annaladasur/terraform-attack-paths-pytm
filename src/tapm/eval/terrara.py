"""Head-to-head on TerrARA's relevance benchmark (CODASPY '25, Table 4): same samples, same question.

TerrARA's question: does the set of elicited threats cover each known vulnerability? It covered 26 of 28
with 715 threats. We ask the same question of what this pipeline hands a developer (attack paths,
plan-confirmed pytm threats and yes/no questions) and also count how much there is to read.

Known vulnerabilities come from each sample's own walkthrough (``known-vulns.yaml``, written from the
attack manuals and README before the pipeline was run on the samples). TerrARA does not publish its
per-vulnerability list, so where a sample has no walkthrough (its hand-crafted samples, KaiMonkey) we
report counts only and say so; we do not invent a ground truth.
"""

from __future__ import annotations

import gzip
import os
import re
import tempfile
import time
from collections import Counter
from pathlib import Path

import yaml

from ..graph.model import ACCOUNT_ADMIN
from ..pipeline import RunConfig, run_deterministic
from ..scanners.run import run_scanners
from ..terraform.offline_plan import plan_fixture
from ..util import PROJECT_ROOT, dump_json
from .tier2 import T2, _write_gz, ensure_repo

TB = PROJECT_ROOT / "evaluations" / "terrara"
LOCAL = PROJECT_ROOT / "artifacts" / "terrara"  # never committed: plans and baselines of samples we may not redistribute
FIRST_SCREEN_QUESTIONS = 6  # what `tapm ask` shows by default


def _store(sample: dict, repo: dict) -> Path:
    return TB if repo.get("redistribute") else LOCAL


def sample_plan(sample: dict, repo: dict, src: Path, manifest: dict) -> Path:
    gz = _store(sample, repo) / "plans" / f"{sample['id']}.json.gz"
    if not gz.exists():
        env_backup = dict(os.environ)
        if sample.get("mirror") == "terrara":
            os.environ["TAPM_PROVIDER_MIRROR"] = os.environ["TAPM_PROVIDER_MIRROR_TERRARA"]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "plan.json"
                variables = {k: str(v).replace("{T2}", str(T2)) for k, v in (sample.get("variables") or {}).items()}
                ctx = (src / sample["context"]).resolve() if sample.get("context") else None
                plan_fixture(src, out, use_cache=False, write_cache=False, mock_aws=manifest.get("mock_aws"),
                             variables=variables, context_dir=ctx)
                _write_gz(gz, out.read_text(encoding="utf-8"))
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
    plain = LOCAL / sample["id"] / "plan.json"
    plain.parent.mkdir(parents=True, exist_ok=True)
    plain.write_bytes(gzip.decompress(gz.read_bytes()))
    return plain


def _on_elements(addr: str, elements: list[str]) -> bool:
    """Does a graph node or pytm element name one of the vulnerability's resources? Instances count."""
    return any(addr == e or addr.startswith(e + "[") or addr.endswith("." + e) for e in elements)


def _addrs(row: dict) -> list[str]:
    """A pytm finding's resources: the element, or a flow's sink then source."""
    f = row.get("flow")
    return [f["sink"], f["source"]] if f else [row.get("element", "")]


def coverage(res, vuln: dict) -> dict:
    """The strongest way the pipeline's output points a developer at this vulnerability.

    path       an attack path runs through the vulnerability's resources (and reaches its target, if one is named)
    confirmed  a pytm threat the plan confirms on one of those resources, of a kind the vulnerability names
    asked      a yes/no question for the app team on one of those resources, about a control the vulnerability names
    generic    only a generic pytm threat of that kind on those resources (TerrARA's own criterion: a threat exists)
    none       nothing
    """
    els = vuln.get("elements") or []
    want = vuln.get("path") or {}
    for p in (res.paths if "path" in vuln else []):  # only vulnerabilities that are paths count as covered by one
        if want.get("target") and not (p.target == want["target"] or (want["target"] == "ACCOUNT_ADMIN" and p.target == ACCOUNT_ADMIN)
                                        or _on_elements(p.target, [want["target"]])):
            continue
        if any(_on_elements(n, els) for n in p.nodes):
            return {"by": "path", "detail": p.id}
    pats = [re.compile(x) for x in vuln.get("threats") or []]
    cls = (res.pytm or {}).get("classification") or {}
    rows = [r for r in cls.get("findings", []) if any(_on_elements(a, els) for a in _addrs(r))
            and any(x.match(r["threat_id"]) for x in pats)]
    conf = [r for r in rows if r["class"] in ("confirmed", "mitigated")]
    if conf:
        return {"by": "confirmed", "detail": ", ".join(sorted({f"{r['threat_id']}@{_addrs(r)[0]}" for r in conf}))}
    q = (res.pytm or {}).get("questions") or {}
    ctl = set(vuln.get("controls") or [])
    asks = [x for x in q.get("questions", []) + q.get("data_questions", [])
            if _on_elements(x["element"], els) and x.get("control") in ctl]
    if asks:
        first = min(asks, key=lambda x: x.get("n", 999))
        return {"by": "asked", "detail": f"question {first.get('n', 'data')}: {first['element']} {first.get('control')}",
                "rank": first.get("n")}
    gen = [r for r in rows if r["class"] != "ruled_out"]
    if gen:
        return {"by": "generic", "detail": ", ".join(sorted({r["threat_id"] for r in gen}))}
    return {"by": "none", "detail": ""}


def run_terrara(only: list[str] | None = None, ai_cfg: dict | None = None) -> dict:
    manifest = yaml.safe_load((TB / "manifest.yaml").read_text())
    known = yaml.safe_load((TB / "known-vulns.yaml").read_text())["samples"]
    results = []
    for s in manifest["samples"]:
        if only and not any(s["id"].startswith(o) for o in only):
            continue
        repo = manifest["repos"][s["repo"]]
        gz = _store(s, repo) / "plans" / f"{s['id']}.json.gz"
        base = _store(s, repo) / "baselines" / s["id"]
        cached = gz.exists() and (base / "versions.json").exists()

        local_src = repo_dir(repo["url"]) / s["path"]
        if local_src.exists() or cached:
            src = local_src
        else:
            src = ensure_repo(repo["url"], repo["commit"]) / s["path"]
        rec = {"id": s["id"], "group": s["group"], "repo": repo["url"], "commit": repo["commit"], "license": repo["license"],
               "terrara": s["terrara"]}
        try:
            plan = sample_plan(s, repo, src, manifest)
        except Exception as e:  # a plan failure is a result, not a crash
            rec["error"] = f"plan failed: {str(e)[-600:]}"
            results.append(rec)
            print(f"  {s['id']:<26} PLAN FAILED")
            continue
        base = _store(s, repo) / "baselines" / s["id"]
        if not (base / "versions.json").exists():
            run_scanners(src, base)
        opts = s.get("options") or {}
        out = LOCAL / s["id"]
        cfg = RunConfig(tf_dir=src, plan_path=plan, out_dir=out, name=s["id"], baselines_dir=base,
                        heuristic_sensitivity=True, user_entries=bool(opts.get("user_entries")),
                        extra_targets=tuple(s.get("targets") or ()))
        t0 = time.monotonic()
        res = run_deterministic(cfg)
        rec["runtime_ms"] = int((time.monotonic() - t0) * 1000)
        cls = (res.pytm or {}).get("classification") or {}
        cs = cls.get("summary") or {}
        q = (res.pytm or {}).get("questions") or {}
        real = [n for n in res.build.graph.nodes.values() if not n.synthetic]
        confirmed = cs.get("confirmed", 0) + cs.get("mitigated", 0)
        nq = len(q.get("questions", [])) + len(q.get("data_questions", []))
        rec.update({
            "resources": len(real), "modeled": sum(1 for n in real if n.modeled),
            "scanner_findings": len(res.findings),
            "paths": len(res.paths), "path_priorities": dict(Counter(p.priority for p in res.paths)),
            "pytm_generic": cs.get("generic"), "pytm_published": cs.get("published"), "confirmed": confirmed,
            "needs_app_team": cs.get("needs_app_team"), "ruled_out": cs.get("ruled_out"), "questions": nq,
            "open_threats_settled_by_first_screen": (q.get("questions") or [{}])[:FIRST_SCREEN_QUESTIONS][-1].get("cumulative", 0) if q.get("questions") else 0,
            "items_full": len(res.paths) + confirmed + nq,
            "items_first_screen": len(res.paths) + min(FIRST_SCREEN_QUESTIONS, len(q.get("questions", []))) + len(q.get("data_questions", [])),
        })
        if ai_cfg:
            from ..ai.harness import run_ai
            ai = run_ai(res, ai_cfg)
            rec["ai"] = {
                "backend": ai["manifest"]["llm_backend"],
                "summary": ai["summary"],
                "metrics": ai["metrics"],
            }
        kv = known.get(s["id"]) or {}
        if kv.get("vulns"):
            rows = []
            for v in kv["vulns"]:
                c = coverage(res, v)
                rows.append({"id": v["id"], "title": v["title"], "layer": v["layer"], **c})
            rec["vulns"] = rows
        else:
            rec["vulns_note"] = kv.get("note", "no documented vulnerabilities")
        by = Counter(v["by"] for v in rec.get("vulns", []))
        print(f"  {s['id']:<26} res={rec['resources']:<4} paths={rec['paths']:<3} confirmed={confirmed:<4} questions={nq:<4} "
              f"items={rec['items_full']:<4} (TerrARA {s['terrara']['threats']:<4}) "
              + (" ".join(f"{k}={by[k]}" for k in ("path", "confirmed", "asked", "generic", "none") if by[k]) or "-")
              + f"  {rec['runtime_ms']} ms")
        results.append(rec)
    summary = summarize(results)
    doc = {"summary": summary, "samples": results, "markdown": markdown(summary, results)}
    dump_json(doc, PROJECT_ROOT / "evaluations" / "results" / "terrara.json")
    (TB / "RESULTS.md").write_text(doc["markdown"], encoding="utf-8")
    return doc


def summarize(results: list[dict]) -> dict:
    scored = [r for r in results if r.get("vulns")]
    vulns = [v for r in scored for v in r["vulns"]]
    by = Counter(v["by"] for v in vulns)
    t_threats = sum(r["terrara"]["threats"] for r in scored)
    t_cov = sum(r["terrara"]["covered"] for r in scored)
    ours_items = sum(r["items_full"] for r in scored)
    first_items = sum(r["items_first_screen"] for r in scored)
    strict = by["path"] + by["confirmed"]
    dev = strict + by["asked"]
    # what a developer sees without scrolling: every path and plan-confirmed threat, the first questions
    first = strict + sum(1 for v in vulns if v["by"] == "asked" and (v.get("rank") is None or v["rank"] <= FIRST_SCREEN_QUESTIONS))
    ret = {
        "samples": len(results), "scored_samples": len(scored), "known_vulns": len(vulns),
        "terrara": {"threats_all": sum(r["terrara"]["threats"] for r in results), "threats_scored": t_threats,
                    "covered_scored": t_cov, "vulns_scored": sum(r["terrara"]["vulns"] for r in scored),
                    "threats_per_covered_vuln": round(t_threats / t_cov, 1) if t_cov else None},
        "ours": {"by": {k: by[k] for k in ("path", "confirmed", "asked", "generic", "none")},
                 "covered_strict": strict, "covered_developer": dev, "covered_any": dev + by["generic"],
                 "covered_first_screen": first, "items_full": ours_items, "items_first_screen": first_items,
                 "items_all_samples": sum(r.get("items_full", 0) for r in results),
                 "items_per_covered_vuln": round(ours_items / dev, 1) if dev else None,
                 "scanner_findings_scored": sum(r.get("scanner_findings", 0) for r in scored),
                 "pytm_generic_scored": sum(r.get("pytm_generic") or 0 for r in scored)},
    }
    ai_samples = [r["ai"] for r in results if "ai" in r]
    if ai_samples:
        backends = sorted({c["backend"] for c in ai_samples})
        ret["ai"] = {
            "backend": backends[0] if len(backends) == 1 else ", ".join(backends) if backends else None,
            "backends": backends,
            "generated": sum(c["summary"]["generated"] for c in ai_samples),
            "accepted": sum(c["summary"]["accepted"] for c in ai_samples),
            "rejected": sum(c["summary"]["rejected"] for c in ai_samples),
            "human_review": sum(c["summary"]["human_review"] for c in ai_samples),
            "llm_calls": sum(c["metrics"]["llm_calls"] for c in ai_samples),
            "cost_usd": None if (not ai_samples or any(c["metrics"].get("cost_usd") is None for c in ai_samples)) else round(sum(c["metrics"]["cost_usd"] for c in ai_samples), 6),
        }
    return ret


def markdown(summary: dict, results: list[dict]) -> str:
    t, o = summary["terrara"], summary["ours"]
    L = ["# TerrARA benchmark: results", "",
         "Generated by `python -m tapm.eval.terrara`; do not edit by hand. Method and caveats: [README.md](README.md).", ""]
    if summary.get("ai"):
        ai = summary["ai"]
        L.extend([
            f"**AI Stage ({ai['backend']}):** {ai['generated']} generated, {ai['accepted']} accepted, {ai['rejected']} rejected, {ai['human_review']} held for review across {ai['llm_calls']} calls.",
            "",
        ])
    L.extend([
         "| Sample | Resources | TerrARA threats | TerrARA covered | Scanner findings | pytm generic | Paths | Plan-confirmed | Questions | Our items | Coverage (ours) |",
         "|---|---|---|---|---|---|---|---|---|---|---|"])
    for r in results:
        if r.get("error"):
            L.append(f"| {r['id']} | plan failed | {r['terrara']['threats']} | {r['terrara']['covered']}/{r['terrara']['vulns']} | | | | | | | |")
            continue
        vs = r.get("vulns")
        cov = (" · ".join(f"{k} {n}" for k, n in Counter(v["by"] for v in vs).most_common()) if vs else "not scored: " + r.get("vulns_note", "")[:60])
        L.append(f"| {r['id']} | {r['resources']} | {r['terrara']['threats']} | {r['terrara']['covered']}/{r['terrara']['vulns']} | "
                 f"{r['scanner_findings']} | {r['pytm_generic']} | {r['paths']} | {r['confirmed']} | {r['questions']} | {r['items_full']} | {cov} |")
    L += ["", f"On the {summary['scored_samples']} samples with a documented ground truth ({summary['known_vulns']} known vulnerabilities): "
          f"TerrARA reports {t['covered_scored']}/{t['vulns_scored']} covered with {t['threats_scored']} threats "
          f"({t['threats_per_covered_vuln']} per covered vulnerability). This pipeline: "
          f"**{o['covered_strict']}** on an attack path or a plan-confirmed threat, **{o['covered_developer']}** counting a yes/no question "
          f"on the right resource ({o['covered_first_screen']} of them on the first screen: paths, confirmed threats and the first "
          f"{FIRST_SCREEN_QUESTIONS} questions), {o['covered_any']} counting generic threats; {o['items_full']} items to read in full "
          f"({o['items_per_covered_vuln']} per covered vulnerability), {o['items_first_screen']} on the first screen.", ""]
    for r in results:
        if not r.get("vulns"):
            continue
        L += [f"## {r['id']}", "", "| Vulnerability | Layer | Covered by | Detail |", "|---|---|---|---|"]
        for v in r["vulns"]:
            late = " (below the first screen)" if v["by"] == "asked" and (v.get("rank") or 0) > FIRST_SCREEN_QUESTIONS else ""
            L.append(f"| {v['id']} {v['title']} | {v['layer']} | **{v['by']}**{late} | {v['detail']} |")
        L.append("")
    return "\n".join(L)


if __name__ == "__main__":
    import sys

    run_terrara(sys.argv[1:] or None)
