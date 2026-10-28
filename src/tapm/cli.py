"""``tapm`` command line. Each subcommand is one beat of the live demo."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from .util import PROJECT_ROOT, load_json

FIXTURES = PROJECT_ROOT / "fixtures"
ARTIFACTS = PROJECT_ROOT / "artifacts"

_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _rel(p) -> Path:
    """Paths are printed relative to the project, so transcripts and screens show no machine-specific prefix."""
    p = Path(p).resolve()
    return p.relative_to(PROJECT_ROOT) if p.is_relative_to(PROJECT_ROOT) else p


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def bold(t): return c(t, "1")
def red(t): return c(t, "31")
def amber(t): return c(t, "33")
def green(t): return c(t, "32")
def dim(t): return c(t, "2")


def resolve_fixture(arg: str) -> Path:
    p = Path(arg)
    if p.is_dir():
        return p.resolve()
    matches = sorted(d for d in FIXTURES.iterdir() if d.is_dir() and d.name.startswith(arg))
    if len(matches) != 1:
        sys.exit(f"fixture '{arg}' not found (or ambiguous): {[m.name for m in matches]}")
    return matches[0]


def fixture_config(fx: Path, out: str | None, ai: dict | None = None, **kw):
    from .pipeline import RunConfig

    meta = {}
    if (fx / "fixture.yaml").exists():
        import yaml

        meta = yaml.safe_load((fx / "fixture.yaml").read_text()) or {}
    out_dir = Path(out) if out else ARTIFACTS / fx.name
    return RunConfig(
        tf_dir=fx, plan_path=Path(kw.get("plan") or fx / "plan.json"), out_dir=out_dir, name=meta.get("name", fx.name),
        baselines_dir=Path(kw.get("baselines") or fx / "baselines"),
        heuristic_sensitivity=bool(meta.get("heuristic_sensitivity", kw.get("heuristic", False))),
        user_entries=bool(meta.get("user_entries", kw.get("user_entries", False))), ai=ai,
        render_dfd=not kw.get("no_dfd", False), extra_targets=tuple(kw.get("targets") or ()),
        sarif_uri_prefix=kw.get("sarif_prefix") or "",
    )


def _cfg(a, fx, ai=None, no_dfd=None):
    return fixture_config(fx, a.out, ai=ai, no_dfd=a.no_dfd if no_dfd is None else no_dfd, plan=getattr(a, "plan", None),
                          baselines=getattr(a, "baselines", None), heuristic=getattr(a, "heuristic_sensitivity", False),
                          user_entries=getattr(a, "user_entries", False), targets=getattr(a, "target", None),
                          sarif_prefix=getattr(a, "sarif_prefix", None))


def ensure_plan(fx: Path, quiet: bool = False) -> None:
    from .terraform.offline_plan import plan_fixture, source_key

    plan = fx / "plan.json"
    key_file = fx / ".plan-source-key"
    key = source_key(fx)
    if plan.exists() and key_file.exists() and key_file.read_text().strip() == key:
        return
    if plan.exists() and not key_file.exists():
        key_file.write_text(key + "\n")
        return
    info = plan_fixture(fx, plan)
    key_file.write_text(key + "\n")
    if not quiet:
        print(dim(f"plan regenerated from {info['source']} (source key {key[:12]})"))


# ------------------------------------------------------------------ commands


def cmd_plan(a) -> None:
    from .terraform.offline_plan import plan_fixture, source_key

    fx = resolve_fixture(a.fixture)
    info = plan_fixture(fx, fx / "plan.json", use_cache=not a.no_cache)
    (fx / ".plan-source-key").write_text(source_key(fx) + "\n")
    print(f"{fx.name}: plan.json written ({info['source']})")


def cmd_scan(a) -> None:
    from .scanners.normalize import load_findings
    from .scanners.run import run_scanners

    fx = resolve_fixture(a.fixture)
    if a.live:
        run_scanners(fx, fx / "baselines")
    versions = load_json(fx / "baselines" / "versions.json") if (fx / "baselines" / "versions.json").exists() else {}
    fs = load_findings(fx / "baselines")
    by_tool = Counter(f.tool for f in fs)
    print(bold(f"Baseline scanners on {fx.name}") + dim("  (saved baseline)" if not a.live else "  (live run)"))
    print()
    for tool, label in (("checkov", "Checkov"), ("tfsec", "tfsec"), ("trivy", "Trivy")):
        v = versions.get(tool, {}).get("version", "?")
        sev = Counter(f.severity for f in fs if f.tool == tool)
        sev_s = "  ".join(f"{k}:{sev[k]}" for k in ("critical", "high", "medium", "low", "unrated") if sev[k])
        print(f"  {label:<8} {dim(v):<24} {bold(str(by_tool[tool])):>4} findings   {dim(sev_s)}")
    print()
    print(f"  {bold(str(len(fs)))} findings across {len({f.resource for f in fs})} resources, each reported in isolation.")
    if a.verbose:
        print()
        for f in sorted(fs, key=lambda f: (f.tool, f.severity, f.rule_id)):
            print(f"  {f.tool:<8} {f.severity:<9} {f.rule_id:<40} {f.resource}")
    print()
    print(amber("  Which of these belong to the same attack story?"))


def _run_det(a, fx):
    from .pipeline import run

    ensure_plan(fx, quiet=True)
    cfg = fixture_config(fx, a.out, no_dfd=getattr(a, "no_dfd", False))
    return run(cfg)


def cmd_model(a) -> None:
    fx = resolve_fixture(a.fixture)
    res = _run_det(a, fx)
    g = res.build.graph
    kinds = Counter(e.type for e in g.edges.values())
    real = [n for n in g.nodes.values() if not n.synthetic]
    print(bold(f"Terraform plan -> typed security graph  ({fx.name})"))
    print(f"  resources      {len(real)}  ({sum(1 for n in real if n.modeled)} modeled, {sum(1 for n in real if not n.modeled)} unmodeled)")
    print(f"  references     {kinds['DEPENDS_ON']} DEPENDS_ON edges (straight from configuration)")
    print(f"  network        {kinds['EXPOSES']} EXPOSES · {kinds['ROUTES_TO']} ROUTES_TO · {kinds['CONTAINS']} CONTAINS")
    print(f"  identity       {kinds['ATTACHES']} ATTACHES · {kinds['TRUSTS']} TRUSTS · {kinds['ASSUMES']} ASSUMES")
    print(f"  permissions    {bold(str(kinds['ALLOWS']))} ALLOWS · {kinds['ESCALATES']} ESCALATES   " + dim("<- inferred from IAM policy JSON; Terraform never states these"))
    print(f"  data flows     {kinds['READS']} READS · {kinds['WRITES']} WRITES")
    print()
    for e in g.edges_of("ALLOWS", "ASSUMES", "ESCALATES"):
        pre = amber(f"  [precondition: {e.precondition}]") if e.precondition else ""
        acts = f" {e.data.get('actions')}" if e.type == "ALLOWS" else ""
        print(f"  {e.id}  {e.src} --{e.type}--> {e.dst}{dim(acts)}{pre}")
    print()
    art = _rel(res.cfg.out_dir)
    print(bold("PyTM model"))
    print(f"  {art / 'threat-model.py'}   ({dim('executable: python threat-model.py --dfd | dot -Tpng')})")
    if res.pytm.get("threat_count") is not None:
        print(f"  DFD: {art / 'dfd.png'}   sequence: {art / 'seq.puml'}")
    cls = res.pytm.get("classification")
    if cls:
        _print_pytm_classification(cls, res.paths)


def _print_pytm_classification(cls: dict, paths) -> None:
    s = cls["summary"]
    print()
    print(bold("PyTM, fed with evidence") + dim(f"  (pytm's threat library + {len(s['pack_threats'])}-threat cloud pack)"))
    print(f"  architecture only (generic)   {s['generic']:>4} threats")
    print(f"  fed with Terraform evidence   {s['published']:>4} threats")
    decided, asks, out = (f"{n:>4}" for n in (s["confirmed"] + s["mitigated"], s["needs_app_team"], s["ruled_out"]))
    print(f"    {red(decided)} decided by the plan      "
          + dim(f"{s['confirmed']} confirmed" + (f", {s['mitigated']} mitigated by an override" if s["mitigated"] else "")))
    ask = Counter(a for r in cls["findings"] if r["class"] == "needs_app_team" for a in r["undecided"])
    top = ", ".join(f"{a.split('.')[-1]} {n}" for a, n in ask.most_common(3))
    print(f"    {amber(asks)} questions for the app team  " + dim(f"(undecided from Terraform: {top})"))
    print(f"    {green(out)} ruled out by evidence     "
          + dim("(generic threats the plan disproves)"))
    for p in paths[:3]:
        hops: dict[int, list[str]] = {}
        for r in cls["findings"]:
            if r["class"] in ("confirmed", "mitigated"):
                for o in r.get("on_paths", []):
                    if o["path"] == p.id:
                        hops.setdefault(o["hop"], []).append(r["threat_id"])
        if hops:
            print(f"  confirmed on {p.id}: " + " · ".join(f"hop {h} {', '.join(sorted(ids))}" for h, ids in sorted(hops.items())))


def cmd_ai_model(a) -> None:
    from .ai.self_model import run_ai_models

    out = Path(a.out or ARTIFACTS / "ai-threat-model")
    r = run_ai_models(out, a.llm, a.jev)
    print(bold("pytm models its own AI layer") + dim(f"  (LLM {a.llm}, decision layer {a.jev}; pytm 1.4 LLM01-LLM09)"))
    print(dim("  status: fires = whatever the undecided attributes are · depends = for some values · - = cannot fire"))
    mark = {"fires": red("FIRES"), "depends": amber("depends"), "cannot_fire": green("-"), "n/a": dim("n/a")}
    print(f"  {'':6}{'':48}{'this pipeline':<16}unsafe design (hypothetical)")
    for t in r["threats"]:
        this = t["this_pipeline_status"]
        why = ""
        if this == "cannot_fire":
            first = t["this_pipeline"][0]  # the annotation model (or the first agent)
            why = dim("  " + ", ".join(f"{k}={v['value']}" for k, v in sorted(first["decided"].items())))
        print(f"  {t['threat_id']:<6}{t['description'][:46]:<48}{mark[this]:<16}{mark[t['unsafe_design_status']]:<10}{why}")
    s = r["summary"]
    print(f"  this pipeline: {s['this_pipeline']['fires']} fire, {s['this_pipeline']['depends']} depend on the provider · "
          f"unsafe design: {s['unsafe_design']['fires']} fire")
    print(dim(f"  models, DFDs and ai-threats.json: {_rel(out)}"))


def cmd_gate(a) -> None:
    """The adoption level decides whether this check fails CI (kit/adoption-ladder.md). Exit 3 = blocked."""
    import datetime as dt

    from .gate import EXCEPTIONS_FILE, draft_exceptions, evaluate, load_exceptions, markdown
    from .util import dump_json

    out = Path(a.out_dir)
    ap = load_json(out / "attack-paths.json") if (out / "attack-paths.json").exists() else None
    if ap is None:
        sys.exit(red(f"{out}: no attack-paths.json; run `tapm run <tf-dir> --plan plan.json --out {out}` first"))
    exc_path = Path(a.exceptions) if a.exceptions else (Path(a.tf_dir) / EXCEPTIONS_FILE if a.tf_dir else None)
    entries, problems = load_exceptions(exc_path)
    today = dt.date.fromisoformat(a.today) if a.today else None
    g = evaluate(ap["paths"], entries, level=a.level, fail_on=a.fail_on, today=today, file_problems=problems)
    draft = draft_exceptions(g, ap["paths"]) if a.draft or g["without_decision"] else ""
    dump_json(g, out / "gate.json")
    (out / "gate.md").write_text(markdown(g, draft), encoding="utf-8")
    if a.draft:
        print(draft or "# nothing to draft: every path at or above the threshold is fixed or accepted", end="")
        return
    verdict = {"fail": red("BLOCKED"), "pass": green("pass")}[g["decision"]]
    print(f"attack-path check  level {bold(a.level)}  threshold {a.fail_on}  {verdict}")
    print(f"  {g['paths_total']} path(s), {g['in_scope']} at or above {a.fail_on}: {g['accepted']} accepted, "
          f"{g['without_decision']} without a decision" + (" (would block at validate)" if g["without_decision"]
                                                              and a.level in ("observe", "recommend") else ""))
    for e in g["exceptions"]:
        if e["state"] != "valid":
            print(amber(f"  {e['id']} {e['state']}: {'; '.join(e['problems'])}"))
    for pr in g["problems"]:
        print(red(f"  {pr}"))
    print(dim(f"  -> {_rel(out / 'gate.md')}, {_rel(out / 'gate.json')}"))
    if g["decision"] == "fail":
        sys.exit(3)


def cmd_measure(a) -> None:
    """Counts for kit/metrics.md from one or more run directories; no resource names leave this command."""
    from .measure import fill_worksheet, summarize

    s = summarize(a.out_dirs)
    if a.json:
        print(json.dumps({k: v for k, v in s.items() if k != "per_run" or a.per_run}, indent=2))
    else:
        print(bold(f"kit metrics over {s['runs']} run(s)") + dim("  (counts only; safe to share)"))
        for mid, m in s["metrics"].items():
            val = "–" if m["value"] is None else f"{m['value']}{m['unit']}"
            print(f"  {mid:<4} {val:>8}  {dim(m['n'] or '')}  {m['metric']}")
        print(dim("  manual: M9 time to a security decision, M16 threat-model freshness (kit/metrics.md)"))
    if a.worksheet:
        n = fill_worksheet(a.worksheet, s, a.at)
        print(f"{n} value(s) written to {a.worksheet} ({a.at})")


def cmd_canary(a) -> None:
    """Level 5: known-bad plans must block and known-good plans must pass, with no accepted risks."""
    import tempfile

    from .gate import DEFAULT_CANARIES, canary

    dirs = [resolve_fixture(x) for x in (a.canaries or DEFAULT_CANARIES)]
    with tempfile.TemporaryDirectory(prefix="tapm-canary-") as tmp:
        r = canary(dirs, level=a.level, fail_on=a.fail_on, workdir=Path(tmp))
    print(bold(f"canary  level {r['level']}  threshold {r['fail_on']}"))
    for row in r["canaries"]:
        mark = green("ok") if row["result"] == "ok" else red(row["result"])
        print(f"  {row['canary']:<48} expect {row['expect'] or '?':<6} got {row['got']:<6} {mark}")
    print(f"  control failure rate (M15): {r['failed']}/{len(r['canaries'])}")
    if a.json:
        Path(a.json).write_text(json.dumps(r, indent=2) + "\n")
    sys.exit(1 if r["failed"] else 0)


def cmd_ask(a) -> None:
    """Threat modeling as a handful of yes/no questions (pytm_gen/questions.py)."""
    from .pipeline import run_deterministic
    from .pytm_gen.questions import answer_effect

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    cfg = fixture_config(fx, a.out)
    if a.answers:
        cfg.answers_file = Path(a.answers)
    res = run_deterministic(cfg)
    q = res.pytm.get("questions")
    if not q:
        sys.exit("pytm did not run (Graphviz is optional; check the pytm install)")
    s = res.pytm["classification"]["summary"]
    shown = q["questions"][: a.n]
    settled = shown[-1]["cumulative"] if shown else 0
    on_path = sum(x["settles_on_path"] for x in shown)
    print(bold(f"Threat modeling in {len(shown)} questions") + dim(f"  (pytm has {q['open']} open threats on this plan; "
          f"these {len(shown)} settle {settled}{', all on attack-path hops' if shown and on_path == settled else ''})"))
    for x in shown:
        print(f"  {x['n']:>2}. {x['question']}")
        print(dim(f"      why: {x['why']}  · settles {x['settles']} threat(s)"))
    for x in q.get("data_questions", []):
        print(f"   · {x['question']}")
        print(dim(f"      why: {x['why']}  · informs {x['informs']} threat(s)"))
    if len(q["questions"]) > len(shown):
        print(dim(f"  … {len(q['questions']) - len(shown)} more questions settle {q['questions'][-1]['cumulative'] - settled} more; "
                  f"{q['not_yes_no']} threats need more than yes/no (data and TLS details)."))
    applied = [x for x in q.get("answers", []) if x["status"] == "applied"]
    if q.get("answers"):
        print()
        eff = answer_effect(res.pytm["classification"])
        print(bold("Your answers") + dim(f"  ({len(applied)} applied: {eff['ruled_out']} threats ruled out by a yes, "
                                         f"{eff['confirmed']} confirmed by a no)"))
        for x in q["answers"]:
            mark = green("✓") if x["status"] == "applied" else amber("!")
            print(f"  {mark} {x['element']}: {x['control']} = {'yes' if x['answer'] else 'no' if x['answer'] is not None else '?'}"
                  f"  {dim(x['status'] + (' · ' + ', '.join(x['evidence']) if x['evidence'] else ''))}")
    elif shown:
        print()
        print(dim(f"  Answer them in {_rel(fx) / 'threat-answers.yaml'} (reviewed like any other change):"))
        first = shown[0]
        print(dim(f"    answers:\n      - element: {first['element']}\n        control: {first['control']}\n"
                  f"        answer: yes        # or no\n        by: <your team>"))


def cmd_story(a) -> None:
    """Each attack path as one plain-language screen (report/story.py)."""
    from .report.story import path_story

    fx = resolve_fixture(a.fixture)
    res = _run_det(a, fx)
    if not res.paths:
        print(green("No way in: nothing in this configuration lets someone on the internet reach the sensitive data."))
        return
    for p in res.paths[: a.n]:
        st = path_story(res, p, a.audience)
        col = red if p.priority == "high" else amber if p.priority == "medium" else dim
        print(col(bold(st["headline"])))
        for x in st["steps"]:
            mark = amber(" (only if the condition above holds)") if x["assumption"] else ""
            print(f"  {x['n']}. {x['text']}{mark}" + (dim(f"  {x['where']}") if x["where"] else ""))
        if st["fix"]:
            print(green(bold("  Fix: ")) + st["fix"]["text"] + (dim(f"  {st['fix']['where']}") if st["fix"]["where"] else ""))
        for q in st["questions"]:
            print(amber("  ? ") + q["question"])
        for t, d in st["glossary"].items():
            print(dim(f"    {t}: {d}"))
        print()
    print(dim(f"  everyone version: {_rel(res.cfg.out_dir) / 'story.md'}   developer version: report.md › In plain words"))


def cmd_paths(a) -> None:
    fx = resolve_fixture(a.fixture)
    res = _run_det(a, fx)
    recs = res.build.ledger.by_id()
    n_find = len(res.findings)
    causal = sorted({fid for p in res.paths for fid in p.findings})
    for p in res.paths:
        col = red if p.priority == "high" else amber if p.priority == "medium" else dim
        print(col(bold(f"{p.id}  {p.priority.upper()}  {p.status}")) + dim(f"   key {p.key}"))
        print()
        print(f"  {'Internet' if p.entry == 'internet' else p.entry}")
        for h in p.hops:
            tag = green("FACT      ") if h.status == "FACT" else amber("ASSUMPTION")
            pre = amber(f"  requires {h.precondition}") if h.precondition else ""
            fine = [e for e in h.evidence if e.startswith(("NET", "IAM")) or ("http_tokens" in (recs.get(e).data if recs.get(e) else {}))]
            locs = ", ".join(f"{e} {_loc(recs[e].source)}" for e in fine if e in recs)
            print(f"    {tag} --{h.type}{'(' + h.label + ')' if h.label else ''}-->  {bold(h.dst)}{pre}")
            if locs:
                print(dim(f"               {h.edge}: {locs}"))
        print()
    if not res.paths:
        print(green("No attack path from the internet to a classified asset."))
        print()
    print(bold(f"  {n_find} isolated scanner findings  ->  {len(res.paths)} coherent path{'s' if len(res.paths) != 1 else ''}"))
    if causal:
        print(dim(f"  ({len(causal)} of the findings sit on causal hops: {', '.join(causal)})"))
    for r in res.remedies:
        eff = {"breaks_path": green("breaks the path"), "downgrades_path": amber(f"downgrades {r.before}->{r.after}"),
               "no_effect": dim("no effect"), "breaks_path_but_alternative_exists": amber("alternative route remains")}[r.effect]
        print(f"  fix hop {r.hop}: {r.change[:88]}  => {eff}")
    print()
    print(dim(f"  report: {_rel(res.cfg.out_dir) / 'report.md'}"))


def _loc(src):
    if not src:
        return ""
    return f"{src['file']}:{src['start_line']}" + (f"-{src['end_line']}" if src['end_line'] != src['start_line'] else "")


def _ai_cfg(a) -> dict:
    return {"llm": a.llm, "jev": a.jev, "include_comments": getattr(a, "include_comments", False),
            "model": getattr(a, "model", None), "cassette_dir": str(PROJECT_ROOT / "cassettes"),
            "record": getattr(a, "record", False)}


def cmd_run(a) -> None:
    from .pipeline import run

    fx = resolve_fixture(a.fixture)
    if not a.plan:
        ensure_plan(fx, quiet=True)
    ai = _ai_cfg(a) if a.llm != "off" else None
    cfg = _cfg(a, fx, ai=ai)
    if a.remediate:
        cfg.remediate = {"llm": a.llm if a.llm != "off" else "simulated", "model": a.model,
                         "cassette_dir": str(PROJECT_ROOT / "cassettes"), "record": a.record}
    res = run(cfg)
    if a.fail_on and any({"high": 3, "medium": 2, "low": 1}[p.priority] >= {"high": 3, "medium": 2, "low": 1}[a.fail_on]
                         for p in res.paths):
        print(f"{fx.name}: attack path at or above '{a.fail_on}' priority")
        (Path(res.cfg.out_dir) / ".gate-failed").write_text(a.fail_on + "\n")
        print(f"{len(res.paths)} path(s) -> {res.cfg.out_dir}")
        sys.exit(3)
    print(f"{fx.name}: {len(res.paths)} path(s), {len(res.findings)} scanner findings -> {res.cfg.out_dir}")
    if res.ai:
        s = res.ai["summary"]
        print(f"  AI: {s['generated']} generated, {s['accepted']} accepted, {s['rejected']} rejected, {s['human_review']} human review")


def _cheat_author(rounds: int = 3):
    """Stress test: a patch author that first tries to game the verifier, then behaves."""
    from .ai.agents import simulate
    from .ai.llm import ScriptedLLM

    cheats = [
        (4, "storage.tf", 'DataClassification = "confidential"', 'DataClassification = "internal"',
         "Declassify the bucket so no path targets it."),
        (3, "app.tf", '  metadata_options {', '  #tfsec:ignore:aws-ec2-enforce-http-token-imds\n  metadata_options {',
         "Suppress the IMDS finding."),
        (4, "iam.tf", '        Resource = ["arn:aws:s3:::*"]',
         '        Resource = [data.external.approved.result.arn]\n      }\n    ]\n  })\n}\ndata "external" "approved" {\n  program = ["sh", "-c", "curl -s https://example.invalid/ok"]',
         "Fetch the approved resource list at plan time."),
    ]

    def author(ctx):
        n = len(ctx["bundle"].get("previous_attempts", []))
        if n < min(rounds, len(cheats)):
            hop, f, find, repl, why = cheats[n]
            blk = next((b["id"] for b in ctx["bundle"]["editable_blocks"] if b["file"] == f), "PATH-001")
            return json.dumps({"hop": hop, "file": f, "find": find, "replace": repl, "rationale": why,
                               "evidence_refs": [blk], "confidence": 0.9})
        return simulate("patch_author", ctx)

    llm = ScriptedLLM({"patch_author": author})
    llm.name = "scripted: 3 attempts to game the verifier, then the simulated author"
    return llm


def cmd_remediate(a) -> None:
    from .ai.remediate import run_remediation
    from .pipeline import run_deterministic

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    res = run_deterministic(fixture_config(fx, a.out))
    cfg = {"llm": a.llm, "model": a.model, "cassette_dir": str(PROJECT_ROOT / "cassettes"), "record": a.record,
           "max_attempts": a.attempts + (3 if a.cheat else 0), "write_cache": a.write_cache, "max_paths": a.paths}
    doc = run_remediation(res, cfg, llm=_cheat_author() if a.cheat else None)
    print(bold("Verified remediation") + dim(f"  (patch author: {doc['manifest']['patch_author']}; nothing is applied to the repository)"))
    status_c = {"PROVEN_BREAK": green, "PROVEN_DOWNGRADE": amber, "ROUTE_BROKEN": amber, "REJECTED": red, "UNVERIFIED": dim,
                "GAVE_UP": dim}
    for p in doc["paths"]:
        print(f"{p['path']}  {p['priority'].upper()}  " + " -> ".join(p["nodes"]))
        for at in p["attempts"]:
            pt = at["patch"]
            one = lambda t: (t or "").strip().replace("\n", " ⏎ ")[:88]  # noqa: E731
            print(f"  attempt {at['n']}  hop {pt.get('hop', '?')}  {pt.get('file', '')}: {one(pt.get('find'))}")
            print(f"             -> {one(pt.get('replace'))}")
            if at["status"] in ("PROVEN_BREAK", "PROVEN_DOWNGRADE", "ROUTE_BROKEN"):
                eff = {"breaks_path": f"{p['path']} is gone; no path reaches {p['nodes'][-1]}",
                       "downgrades_path": f"{at['priority_before']} -> {at['priority_after']} (still: {', '.join(at['preconditions_after'])})",
                       "breaks_route": f"route gone; {at['other_paths_to_target']} other path(s) to the target"}[at["effect"]]
                py = at.get("pytm") or {}
                bits = [f"re-planned ({at['plan_source']})", eff, "no new paths"]
                if py.get("resolved"):
                    bits.append("pytm resolved: " + ", ".join(sorted({x.split(" on ")[0] for x in py["resolved"]})))
                if at.get("what_if_predicted"):
                    bits.append(f"what-if predicted {at['what_if_predicted'].replace('_', ' ')}")
                print(f"             {status_c[at['status']](at['status'])}  " + dim(" · ".join(bits)))
            else:
                stage = f" ({at['stage']})" if at.get("stage") else ""
                print(f"             {status_c.get(at['status'], red)(at['status'])}{stage}  " + dim("; ".join(at["reasons"])[:160]))
        if p["recommended_diff"]:
            print(f"  => verified fix: {_rel(res.cfg.out_dir) / ('remediation-' + p['path'] + '.diff')}  " + dim("(a human reviews and applies it)"))
        else:
            print(f"  => {p['result']}")


def cmd_explain(a) -> None:
    from .pipeline import run

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    res = run(_cfg(a, fx, ai=_ai_cfg(a), no_dfd=True))
    ai = res.ai
    print(bold("AI enrichment plane") + dim(f"   llm={ai['manifest']['llm_backend']}  decisions={ai['manifest']['jev_backend']}"))
    print()
    for d in ai["decisions"]:
        print(bold(f"  JEV DECISION  {d['subject']}"))
        for k, v in d["outputs"].items():
            print(f"    {k:<22} = {v}")
    print()
    for ann in ai["annotations"]:
        st = ann["status"]
        col = green if st == "accepted" else red if st == "rejected" else amber
        print(col(bold(f"  {ann['annotation_id']}  {ann['type']}  {st.upper()}")))
        print(f"    {ann['statement'][:300]}")
        print(dim(f"    evidence: {', '.join(ann['evidence_refs']) or '(none)'}"))
        for r in ann.get("rejections", []):
            print(red(f"    x {r}"))
    s = ai["summary"]
    print()
    print(bold(f"  AI annotations: {s['generated']} generated · {s['accepted']} evidence-backed · {s['rejected']} rejected · {s['human_review']} human review"))


def cmd_enrich(a) -> None:
    """Asynchronously enrich an artifacts directory using AI (W0.3). Never reads the plan."""
    import time
    from .ai.enrich import enrich_artifacts

    art = Path(a.artifacts_dir)
    if not art.exists():
        sys.exit(red(f"{art}: artifacts directory does not exist"))
    if not (art / "attack-paths.json").exists() or not (art / "evidence.json").exists():
        sys.exit(red(f"{art}: missing attack-paths.json or evidence.json; run `tapm run <dir> --out {art}` first"))

    cfg = {
        "llm": a.llm,
        "model": a.model,
        "jev": a.jev,
        "max_paths": a.max_paths,
        "cache": not a.no_cache,
        "cache_dir": a.cache_dir,
        "cassette_dir": str(PROJECT_ROOT / "cassettes"),
        "record": a.record,
    }
    t0 = time.monotonic()
    doc = enrich_artifacts(art, cfg)
    ms = int((time.monotonic() - t0) * 1000)
    s = doc["summary"]
    m = doc["metrics"]
    man = doc["manifest"]
    print(f"enriched {bold(_rel(art))}: {s['generated']} generated, {s['accepted']} accepted, {s['rejected']} rejected, {s['human_review']} human review ({ms} ms)")
    print(f"  backend: {man['llm_backend']}, decision layer: {man['jev_backend']}")
    print(f"  model calls: {m['model_calls']}, cache hits: {m['cache_hits']} (capped at {man['max_paths_cap']} paths)")
    print(dim(f"  -> {_rel(art / 'ai-annotations.json')}, {_rel(art / 'validation.json')}, {_rel(art / 'ai-metrics.json')}"))


def cmd_serve(a) -> None:
    """Run the analysis service (W1.1, W1.2)."""
    from .service import create_server
    from .service.adapters import get_adapter

    git_adapter = None
    if getattr(a, "git_server", None):
        git_adapter = get_adapter(
            server_type=a.git_server,
            base_url=getattr(a, "git_base_url", None),
            token=getattr(a, "git_token", None),
        )

    server = create_server(
        host=a.host,
        port=a.port,
        token=a.token,
        data_dir=a.data_dir,
        workers=a.workers,
        default_llm=a.llm,
        default_jev=a.jev,
        default_model=a.model,
        log_format=a.log_format,
        git_adapter=git_adapter,
    )
    auth_str = "token required" if server.auth.enabled else "no auth"
    git_str = f", git={a.git_server}" if getattr(a, "git_server", None) else ""
    print(bold(f"tapm serve running at http://{a.host}:{a.port} ({auth_str}, {a.workers} worker(s), llm={a.llm}{git_str})"))
    print(dim("  POST /v1/jobs | GET /v1/jobs/{id} | GET /v1/jobs/{id}/artifacts/{name} | GET /v1/metrics"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down tapm serve...")
    finally:
        server.job_queue.shutdown()
        server.server_close()


def cmd_git_status(a) -> None:
    """Post commit status check to Gitea or GitHub (W1.2)."""
    from .service.adapters import detect_adapter, get_adapter

    try:
        adapter = (
            get_adapter(server_type=a.server, base_url=a.base_url, token=a.token)
            if a.server
            else detect_adapter()
        )
        res = adapter.post_status(
            repo=a.repo,
            sha=a.sha,
            state=a.state,
            description=a.description or "",
            context=a.context,
            target_url=a.target_url or "",
        )
        print(green(bold(f"Posted status '{a.state}' to {a.repo}@{a.sha[:8]} [{a.context}]")))
        if isinstance(res, dict) and "id" in res:
            print(dim(f"  status ID: {res['id']}"))
    except Exception as e:
        print(red(f"Error posting commit status: {e}"), file=sys.stderr)
        sys.exit(1)


def cmd_git_comment(a) -> None:
    """Post or update PR comment on Gitea or GitHub (W1.2)."""
    from .service.adapters import DEFAULT_MARKER, detect_adapter, get_adapter

    body = a.body or ""
    if a.body_file:
        bf = Path(a.body_file)
        if not bf.exists():
            print(red(f"Error: body file '{a.body_file}' not found"), file=sys.stderr)
            sys.exit(1)
        body = bf.read_text(encoding="utf-8")

    if not body:
        print(red("Error: comment body is empty (pass --body or --body-file)"), file=sys.stderr)
        sys.exit(1)

    try:
        adapter = (
            get_adapter(server_type=a.server, base_url=a.base_url, token=a.token)
            if a.server
            else detect_adapter()
        )
        res = adapter.post_comment(
            repo=a.repo,
            pr=a.pr,
            body=body,
            update_existing=not a.no_update,
            marker=a.marker or DEFAULT_MARKER,
        )
        action = res.get("_action", "posted")
        print(green(bold(f"{action.capitalize()} comment on {a.repo} PR #{a.pr}")))
        if isinstance(res, dict) and "id" in res:
            print(dim(f"  comment ID: {res['id']}"))
    except Exception as e:
        print(red(f"Error posting PR comment: {e}"), file=sys.stderr)
        sys.exit(1)


def cmd_submit(a) -> None:
    """Runner client: post plan to analysis service, poll, and exit per level (W1.3)."""
    from .service.client import SubmitClient

    plan_target = a.plan or a.plan_flag
    if not plan_target:
        if Path("plan.json").exists():
            plan_target = "plan.json"
        elif Path("terraform-plan.json").exists():
            plan_target = "terraform-plan.json"
        else:
            print(red("Error: missing plan file (specify plan argument or --plan)"), file=sys.stderr)
            sys.exit(1)

    exceptions_yaml = None
    if getattr(a, "exceptions", None):
        ep = Path(a.exceptions)
        if ep.exists():
            exceptions_yaml = ep.read_text(encoding="utf-8")
    elif Path("attack-path-exceptions.yaml").exists():
        exceptions_yaml = Path("attack-path-exceptions.yaml").read_text(encoding="utf-8")

    threat_answers_yaml = None
    if getattr(a, "answers", None):
        ap = Path(a.answers)
        if ap.exists():
            threat_answers_yaml = ap.read_text(encoding="utf-8")
    elif Path("threat-answers.yaml").exists():
        threat_answers_yaml = Path("threat-answers.yaml").read_text(encoding="utf-8")

    client = SubmitClient(
        server_url=a.server,
        token=a.token,
        timeout=a.timeout,
        poll_interval=a.poll_interval,
    )

    if not a.json:
        print(f"Submitting plan to analysis service at {bold(client.server_url)} (level: {bold(a.level)})...")

    extra_options: dict[str, Any] = {}
    if getattr(a, "trigger", None):
        extra_options["trigger"] = a.trigger
    if getattr(a, "plan_ms", None) is not None:
        extra_options["plan_ms"] = a.plan_ms
    if getattr(a, "scanners_ms", None) is not None:
        extra_options["scanners_ms"] = a.scanners_ms

    result = client.run(
        plan=plan_target,
        repo=a.repo,
        pr=a.pr,
        sha=a.sha,
        root_module=a.root_module,
        level=a.level,
        fail_on=a.fail_on,
        timeout=a.timeout,
        poll_interval=a.poll_interval,
        auto_enrich=not a.no_enrich,
        exceptions_yaml=exceptions_yaml,
        threat_answers_yaml=threat_answers_yaml,
        out_dir=a.out,
        **extra_options,
    )

    if a.json:
        print(json.dumps(result.to_dict(), indent=2))
        sys.exit(result.exit_code)

    if result.status == "completed":
        col = green if result.verdict == "pass" else (amber if result.verdict == "would_block" else red)
        print(col(bold(f"Analysis completed: job {result.job_id} -> verdict: {result.verdict.upper()}")))
        print(
            f"  paths: {result.paths_count} total, {result.in_scope_count} at/above {a.fail_on} "
            f"({result.accepted_count} accepted, {result.without_decision_count} without decision)"
        )
        if result.verdict == "blocked":
            print(
                red(bold(f"  BLOCKED: {result.without_decision_count} path(s) need a decision before merge (level: {a.level})"))
            )
        elif result.verdict == "would_block":
            print(amber(f"  Note: {result.without_decision_count} path(s) would block at validate (level: {a.level})"))
    elif result.timed_out:
        if result.failed_open:
            print(amber(bold(f"Timed out waiting for analysis service: failing open at {a.level} (exit 0)")))
        else:
            print(red(bold(f"Timed out waiting for analysis service: failing closed at {a.level} (exit 1)")))
    elif result.status == "error":
        if result.failed_open:
            print(amber(bold(f"Analysis service error ({result.error}): failing open at {a.level} (exit 0)")))
        else:
            print(red(bold(f"Analysis service error ({result.error}): failing closed at {a.level} (exit 1)")))

    if result.artifacts_downloaded:
        print(dim(f"  downloaded artifacts to {a.out}: {', '.join(result.artifacts_downloaded)}"))

    sys.exit(result.exit_code)


def cmd_report(a) -> None:
    """Render persona reports (platform, developer, appsec, executive) (W1.4, W3)."""
    persona = getattr(a, "persona", "platform")
    fmt = getattr(a, "format", "markdown")

    if persona == "developer":
        from .report.developer import render_developer_report

        src = getattr(a, "artifacts", None) or getattr(a, "file", None)
        if not src:
            if Path("conference-snapshot").exists():
                src = "conference-snapshot"
            elif Path("out").exists():
                src = "out"
            else:
                print(red("Error: developer persona requires an artifacts directory (tapm report --persona developer <dir>)"), file=sys.stderr)
                sys.exit(1)

        try:
            report_content = render_developer_report(src, format=fmt)
        except Exception as e:
            print(red(f"Error rendering developer report from {src}: {e}"), file=sys.stderr)
            sys.exit(1)

        out_path = getattr(a, "out", None)
        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(report_content, encoding="utf-8")
            print(f"Developer report written to {out_path}")
        else:
            print(report_content, end="" if report_content.endswith("\n") else "\n")
        return

    if persona == "appsec":
        from .report.appsec import render_appsec_report

        src = getattr(a, "artifacts", None) or getattr(a, "file", None)
        if not src:
            if Path("conference-snapshot").exists():
                src = "conference-snapshot"
            elif Path("out").exists():
                src = "out"
            else:
                print(red("Error: appsec persona requires an artifacts directory (tapm report --persona appsec <dir>)"), file=sys.stderr)
                sys.exit(1)

        try:
            report_content = render_appsec_report(src, format=fmt)
        except Exception as e:
            print(red(f"Error rendering appsec report from {src}: {e}"), file=sys.stderr)
            sys.exit(1)

        out_path = getattr(a, "out", None)
        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(report_content, encoding="utf-8")
            print(f"AppSec report written to {out_path}")
        else:
            print(report_content, end="" if report_content.endswith("\n") else "\n")
        return

    if persona == "executive":
        from .report.executive import render_executive_report

        src = getattr(a, "artifacts", None) or getattr(a, "file", None)
        if not src:
            if Path("conference-snapshot").exists():
                src = "conference-snapshot"
            elif Path("out").exists():
                src = "out"
            else:
                print(red("Error: executive persona requires an artifacts directory (tapm report --persona executive <dir>)"), file=sys.stderr)
                sys.exit(1)

        try:
            report_content = render_executive_report(
                src,
                format=fmt,
                month=getattr(a, "month", None),
                worksheet=getattr(a, "worksheet", None),
            )
        except Exception as e:
            print(red(f"Error rendering executive report from {src}: {e}"), file=sys.stderr)
            sys.exit(1)

        out_path = getattr(a, "out", None)
        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(report_content, encoding="utf-8")
            print(f"Executive report written to {out_path}")
        else:
            print(report_content, end="" if report_content.endswith("\n") else "\n")
        return

    from .report.platform import render_platform_report

    if persona != "platform":
        print(red(f"Error: unknown persona '{persona}' (choose from: platform, developer, appsec, executive)"), file=sys.stderr)
        sys.exit(1)

    # Obtain metrics
    metrics: dict[str, Any]
    if getattr(a, "file", None):
        source = a.file
        try:
            if source == "-":
                raw_text = sys.stdin.read()
            else:
                raw_text = Path(source).read_text(encoding="utf-8")
            metrics = json.loads(raw_text)
        except Exception as e:
            print(red(f"Error loading metrics from {source}: {e}"), file=sys.stderr)
            sys.exit(1)
    else:
        from .service.client import AnalysisClient

        client = AnalysisClient(
            server_url=getattr(a, "server", None),
            token=getattr(a, "token", None),
        )
        try:
            metrics = client.get_metrics()
        except Exception as e:
            print(
                red(f"Error fetching /v1/metrics from {client.server_url}: {e}\n"
                    "Ensure 'tapm serve' is running, or provide a saved metrics file with --file <path>."),
                file=sys.stderr,
            )
            sys.exit(1)

    report_content = render_platform_report(metrics, format=fmt)

    out_path = getattr(a, "out", None)
    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report_content, encoding="utf-8")
        print(green(bold(f"Platform report written to {p} ({len(report_content)} bytes)")))
    else:
        print(report_content)


def cmd_matrix(a) -> None:
    """Affected-module CI matrix and sharded sweep for many root modules (W1.5)."""
    from .terraform.matrix import (
        AffectedModule,
        ModuleGraph,
        get_git_changed_files,
        plan_affected_modules,
    )

    repo_dir = Path(a.repo).resolve()
    roots_arg = getattr(a, "roots", None)
    roots_list = None
    roots_pattern = None
    if roots_arg:
        if any(c in roots_arg for c in ("*", "?", "[", "]")):
            roots_pattern = roots_arg
        else:
            roots_list = [r.strip() for r in roots_arg.split(",") if r.strip()]

    graph = ModuleGraph(repo_dir, roots=roots_list, roots_pattern=roots_pattern)

    # Determine changed files / selection mode
    if getattr(a, "all", False):
        affected = None
    elif getattr(a, "changed", None) is not None:
        changed_files = []
        for item in a.changed:
            if item == "-":
                changed_files.extend(sys.stdin.read().splitlines())
            else:
                changed_files.append(item)
        affected = graph.affected_roots(changed_files)
    elif getattr(a, "git_diff", False) or getattr(a, "diff_against", None):
        changed_files = get_git_changed_files(repo_dir, diff_ref=getattr(a, "diff_against", None))
        affected = graph.affected_roots(changed_files)
    else:
        # Default: if git repo, check git changes, else all roots
        git_dir = repo_dir / ".git"
        if git_dir.exists():
            changed_files = get_git_changed_files(repo_dir)
            affected = graph.affected_roots(changed_files)
        else:
            affected = None

    # Handle sharding parameters
    shards = getattr(a, "shards", None)
    shard_index = getattr(a, "shard_index", None)
    shard_arg = getattr(a, "shard", None)
    if shard_arg:
        if "/" in shard_arg:
            parts = shard_arg.split("/")
            shard_index = int(parts[0])
            shards = int(parts[1])
        else:
            shard_index = int(shard_arg)

    fmt = getattr(a, "format", "github")
    matrix_data = graph.generate_matrix(
        affected=affected,
        fmt=fmt,
        shards=shards,
        shard_index=shard_index,
        all_roots=getattr(a, "all", False) or (affected is None),
    )

    # Re-planning if requested
    if getattr(a, "plan", False):
        if affected is None:
            affected_for_plan = [
                AffectedModule(module=r, name=graph.modules[r].name, replan=True, reasons=["all-roots"])
                for r in sorted(graph.root_paths)
            ]
        else:
            affected_for_plan = affected

        if shards is not None and shard_index is not None:
            affected_for_plan = graph.shard(affected_for_plan, shard_index, shards)

        out_dir = Path(a.out_dir).resolve() if getattr(a, "out_dir", None) else None
        plan_res = plan_affected_modules(
            repo_dir,
            affected_for_plan,
            out_dir=out_dir,
        )
        if fmt == "json" and isinstance(matrix_data, dict):
            matrix_data["planning"] = plan_res

    # Output formatting
    if fmt in ("github", "gitlab", "json"):
        output_str = json.dumps(matrix_data, indent=2)
    elif isinstance(matrix_data, list):
        output_str = "\n".join(str(x) for x in matrix_data)
    else:
        output_str = str(matrix_data)

    out_file = getattr(a, "out", None)
    if out_file:
        p = Path(out_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(output_str + "\n", encoding="utf-8")
    else:
        print(output_str)

    # GitHub Actions environment integration
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output and Path(gh_output).exists():
        try:
            with open(gh_output, "a", encoding="utf-8") as f:
                if fmt in ("github", "gitlab", "json"):
                    f.write(f"matrix={json.dumps(matrix_data)}\n")
                count = len(affected) if affected is not None else len(graph.root_paths)
                f.write(f"count={count}\n")
                f.write(f"has_affected={'true' if count > 0 else 'false'}\n")
        except Exception:
            pass


def cmd_validate(a) -> None:
    from .ai.validator import Validator

    art = Path(a.artifacts)
    v = Validator.from_artifacts(art)
    ann = load_json(a.annotation)
    anns = ann if isinstance(ann, list) else [ann]
    ok_all = True
    for x in anns:
        verdict = v.validate(x, bundle_ids=None)
        col = green if verdict.accepted else red
        print(col(bold(f"{x.get('annotation_id', '?')}: {'ACCEPTED' if verdict.accepted else 'REJECTED'}")))
        for r in verdict.reasons:
            print(red(f"  x {r}"))
        ok_all &= verdict.accepted
    sys.exit(0 if ok_all else 2)


def cmd_tamper(a) -> None:
    """Demo beat: take an accepted annotation, strip or forge its evidence, and re-validate."""
    import re

    from .ai.validator import Validator

    art = Path(a.artifacts)
    anns = load_json(art / "ai-annotations.json")["annotations"]
    ann = next(x for x in anns if x["annotation_id"] == a.annotation)
    t = dict(ann)
    if a.mode == "remove":
        t["evidence_refs"] = []
        t["statement"] = re.sub(r"\s*\[[A-Z]+-\d{3}(?:, [A-Z]+-\d{3})*\]", "", t["statement"])
        what = "all evidence references removed"
    else:
        t["evidence_refs"] = [r if not r.startswith("IAM-") else "IAM-009" for r in t["evidence_refs"]]
        t["statement"] = re.sub(r"IAM-\d{3}", "IAM-009", t["statement"])
        what = "IAM evidence swapped for IAM-009, which does not exist"
    out = art / f"tampered-{a.annotation}.json"
    out.write_text(json.dumps(t, indent=2, sort_keys=True) + "\n")
    v = Validator.from_artifacts(art)
    for label, x in (("original", ann), ("tampered", t)):
        verdict = v.validate({k: x[k] for k in x if k not in ("validation", "review", "escalation")}, bundle_ids=None,
                             agent=x.get("agent"))
        col = green if verdict.accepted else red
        print(col(bold(f"  {a.annotation} ({label}): {'ACCEPTED' if verdict.accepted else 'REJECTED'}")))
        print(dim(f"    evidence: {', '.join(x.get('evidence_refs') or []) or '(none)'}"))
        for r in verdict.reasons:
            print(red(f"    x {r}"))
        if label == "original":
            print(amber(f"  -> tampering: {what}  ({out.name})"))


def cmd_inject(a) -> None:
    from .ai.injection import run_injection_demo

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    runs = getattr(a, "runs", 1)
    write_results = getattr(a, "write_results", False)
    if runs > 1 or write_results:
        from .eval.injection import run_injection_eval

        tag = getattr(a, "tag", "local")
        res = run_injection_eval(fx, fixture_config(fx, a.out, no_dfd=True), _ai_cfg(a),
                                 n=runs, write_results=write_results, tag=tag)
        s = res["summary"]
        print(bold(f"Prompt injection evaluation (n={s['runs']} runs, backend={s['backend']})"))
        print(red(bold("UNSAFE pipeline: ")) +
              f"claims secure: {s['unsafe']['claims_secure_rate']} | " +
              f"mentions IAM: {s['unsafe']['mentions_iam_rate']} | " +
              f"influenced: {s['unsafe']['influenced_rate']}")
        print(green(bold("SAFE pipeline (default): ")) +
              f"{s['safe_default']['annotations_accepted']}/{s['safe_default']['annotations_generated']} accepted | " +
              f"0 influenced or unsupported statements published")
        print(green(bold("SAFE pipeline (stress test): ")) +
              f"{s['safe_stress']['annotations_rejected']}/{s['safe_stress']['annotations_generated']} rejected by validator | " +
              f"0 influenced or unsupported statements published")
        print(bold(f"Deterministic paths invariance: {s['invariance']['paths_identical_rate']}"))
        print(dim(f"Results written to: {res.get('out_file', '')}"))
        return

    out = run_injection_demo(fx, fixture_config(fx, a.out, no_dfd=True), _ai_cfg(a))
    print(bold("Prompt injection hidden in Terraform comments"))
    for cmt in out["comments"]:
        text = cmt["text"].replace("\n", " / ")
        print(amber(f"  {cmt['id']} {cmt['file']}:{cmt['line']}  \u201c{text[:110]}\u201d"))
        print(dim(f"          flagged patterns: {', '.join(cmt['patterns'])}"))
    print()
    u = out["unsafe"]
    print(red(bold("UNSAFE pipeline")) + dim(f"   raw Terraform (comments included) -> LLM -> PR summary   [{u['backend']}]"))
    print(f"  \u201c{u['text'][:300]}\u201d")
    verdict = red("INFLUENCED") if u["influenced"] else green("not influenced")
    print(f"  {verdict}   says secure: {u['claims_secure']}   mentions IAM: {u['mentions_iam']}")
    print()
    for label, key in (("SAFE pipeline (default: comments never reach the model)", "safe"),
                       ("SAFE pipeline, stress test (comments passed as fenced UNTRUSTED data)", "safe_with_untrusted_comments")):
        print(green(bold(label)))
        for ann in out[key]["annotations"]:
            st = ann["status"]
            col = green if st == "accepted" else red if st == "rejected" else amber
            print(col(f"  {ann['annotation_id']} {ann['type']:<24} {st.upper()}") + dim(f"  {ann['statement'][:110]}"))
            for r in ann.get("rejections", [])[:4]:
                print(red(f"      x {r[:150]}"))
        s = out[key]["summary"]
        print(dim(f"  {s['generated']} generated, {s['accepted']} accepted, {s['rejected']} rejected, {s['human_review']} human review"))
        print()
    same = green("identical") if out["paths_identical"] else red("DIFFERENT")
    print(bold(f"  attack paths with comments stripped vs. present: {same}  {out['paths_with_comments']}"))
    print(dim("  The model was never responsible for deciding whether the path existed."))


def cmd_replay(a) -> None:
    from .eval.replay import replay

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    rep = replay(fixture_config(fx, None, no_dfd=a.no_dfd), a.n)
    for art, stat in rep["artifacts"].items():
        mark = green("identical") if stat["identical"] else red("DIFFERENT")
        print(f"  {art:<24} {stat['distinct']} distinct hash(es) over {a.n} runs  {mark}")
    print(bold(f"  deterministic replay: {rep['identical_runs']}/{a.n} runs byte-identical"))


def cmd_experiment(a) -> None:
    from .eval.experiment import NeedsRealModel, run_experiment

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    write_results = getattr(a, "write_results", False)
    tag = getattr(a, "tag", "local")
    out_dir = a.out
    try:
        out = run_experiment(fx, fixture_config(fx, a.out, no_dfd=True), _ai_cfg(a),
                             n=a.n, out_dir=out_dir, write_results=write_results, tag=tag)
    except NeedsRealModel as e:
        sys.exit(amber(str(e)))
    except FileNotFoundError as e:
        sys.exit(amber(f"{e}\n(record first: tapm experiment {a.fixture} --llm anthropic --record)"))
    out_file = Path(out["out_file"])
    md_file = out_file.parent / "experiment.md"
    if md_file.exists():
        print(md_file.read_text())
    print(dim(f"Results written to: {out_file}"))


def cmd_variability(a) -> None:
    from .eval.variability import NeedsRealModel, run_variability_eval

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    write_results = getattr(a, "write_results", False)
    tag = getattr(a, "tag", "local")
    out_dir = a.out
    try:
        out = run_variability_eval(
            fx,
            fixture_config(fx, a.out, no_dfd=True),
            _ai_cfg(a),
            n=a.n,
            out_dir=out_dir,
            write_results=write_results,
            tag=tag,
            command=" ".join(sys.argv),
        )
    except NeedsRealModel as e:
        sys.exit(amber(str(e)))
    except FileNotFoundError as e:
        sys.exit(amber(f"{e}\n(record first: tapm variability {a.fixture} --llm anthropic --record)"))
    out_file = Path(out["out_file"])
    from .eval.variability import render_variability_markdown

    print(render_variability_markdown(out))
    print(dim(f"Results written to: {out_file}"))


def cmd_patch_author(a) -> None:
    from .eval.patch_author import NeedsRealModel, render_patch_author_markdown, run_patch_author_eval

    fixtures = [resolve_fixture(f.strip()) for f in a.fixtures.split(",") if f.strip()] if getattr(a, "fixtures", None) else None
    write_results = getattr(a, "write_results", False)
    tag = getattr(a, "tag", "local")
    out_dir = a.out
    ai_cfg = {"llm": a.llm, "model": a.model}
    try:
        out = run_patch_author_eval(
            fixtures=fixtures,
            ai_cfg=ai_cfg,
            max_attempts=a.attempts,
            out_dir=out_dir,
            write_results=write_results,
            tag=tag,
            command=" ".join(sys.argv),
            write_cache=getattr(a, "write_cache", True),
        )
    except NeedsRealModel as e:
        sys.exit(amber(str(e)))
    except FileNotFoundError as e:
        sys.exit(amber(str(e)))
    out_file = Path(out["out_file"])
    print(render_patch_author_markdown(out))
    print(dim(f"Results written to: {out_file}"))


def cmd_security_tests(a) -> None:
    from .ai.negative import run_cases
    from .pipeline import run_deterministic

    fx = resolve_fixture(a.fixture)
    ensure_plan(fx, quiet=True)
    res = run_deterministic(fixture_config(fx, a.out, no_dfd=True))
    rows = run_cases(res, {"cassette_dir": str(PROJECT_ROOT / "cassettes")})
    print(bold("AI boundary: negative security tests (each output below is deliberately bad)"))
    print()
    ok = 0
    for r in rows:
        good = r["refused"] and r["caught_by_expected_check"]
        ok += good
        mark = green("REFUSED ") if r["refused"] else amber("NOT RUN ") if not r["ran"] else red("ACCEPTED")
        print(f"  {r['id']:>2}. {r['name']:<52} {mark}  {dim(r['reasons'][0][:70] if r['reasons'] else '')}")
    ran = sum(r["ran"] for r in rows)
    print()
    print(bold(f"  {ok}/{ran} refused by the intended check")
          + (dim(f"   ({len(rows) - ran} not run: that agent is not routed for this input; fixture 006 exercises all {len(rows)})")
             if ran < len(rows) else ""))
    sys.exit(0 if ran and ok == ran else 1)


def cmd_tier2(a) -> None:
    from .eval.tier2 import run_tier2

    ai_cfg = None
    if getattr(a, "llm", None) and a.llm != "off":
        ai_cfg = {
            "llm": a.llm,
            "jev": getattr(a, "jev", "local"),
            "model": getattr(a, "model", None),
            "max_paths": getattr(a, "max_paths", None),
            "cassette_dir": str(PROJECT_ROOT / "cassettes"),
            "allow_fallback": not getattr(a, "no_fallback", True),
        }
    manifest_name = "manifest-heldout.yaml" if getattr(a, "heldout", False) else (getattr(a, "manifest", None) or "manifest.yaml")
    tag = "heldout" if (getattr(a, "heldout", False) and a.tag == "run") else a.tag
    write_results = getattr(a, "write_results", False)
    try:
        out = run_tier2(a.cases or None, tag=tag, ai_cfg=ai_cfg, manifest_name=manifest_name, write_results=write_results)
    except RuntimeError as e:
        sys.exit(red(str(e)))
    print(json.dumps(out["summary"], indent=2))


def cmd_realworld(a) -> None:
    from .eval.realworld import run_realworld

    manifest_name = getattr(a, "manifest", None) or "manifest.yaml"
    tag = getattr(a, "tag", "benign")
    write_results = getattr(a, "write_results", False)
    try:
        out = run_realworld(a.cases or None, tag=tag, manifest_name=manifest_name, write_results=write_results)
    except RuntimeError as e:
        sys.exit(red(str(e)))
    print(json.dumps(out["summary"], indent=2))


def cmd_bench(a) -> None:
    from .eval.runner import run_benchmark

    ai_cfg = None
    if getattr(a, "llm", "simulated") != "off":
        ai_cfg = {
            "llm": getattr(a, "llm", "simulated"),
            "jev": getattr(a, "jev", "local"),
            "model": getattr(a, "model", None),
            "max_paths": getattr(a, "max_paths", None),
            "cassette_dir": str(PROJECT_ROOT / "cassettes"),
            "allow_fallback": not getattr(a, "no_fallback", True),
        }
    rep = run_benchmark(PROJECT_ROOT, fixtures=a.fixtures or None, replay_n=a.replay,
                        live_scanners=a.live_scanners, ai_cfg=ai_cfg, max_paths=getattr(a, "max_paths", None),
                        out_dir=getattr(a, "out", None))
    print(json.dumps(rep["summary"], indent=2))


def cmd_terrara(a) -> None:
    from .eval.terrara import run_terrara

    ai_cfg = None
    if getattr(a, "llm", None) and a.llm != "off":
        ai_cfg = {
            "llm": a.llm,
            "jev": getattr(a, "jev", "local"),
            "model": getattr(a, "model", None),
            "max_paths": getattr(a, "max_paths", None),
            "cassette_dir": str(PROJECT_ROOT / "cassettes"),
            "allow_fallback": not getattr(a, "no_fallback", True),
        }
    out = run_terrara(a.samples or None, ai_cfg=ai_cfg)
    print(json.dumps(out["summary"], indent=2))


def cmd_strata(a) -> None:
    from .eval.strata import compute_strata, generate_strata
    from .util import dump_json

    out_dir = Path(a.dir) if getattr(a, "dir", None) else None
    out_path = Path(a.out) if getattr(a, "out", None) else None
    write_results = getattr(a, "write_results", False)
    if getattr(a, "json", False):
        data = compute_strata(out_dir)
        if out_path:
            dump_json(data, out_path)
        elif write_results:
            dump_json(data, PROJECT_ROOT / "evaluations" / "results" / "strata.json")
        print(json.dumps(data, indent=2))
    else:
        path = generate_strata(results_dir=out_dir, out_path=out_path, write_results=write_results)
        print(f"wrote {path}")


def cmd_lab(a) -> None:
    from . import lab

    if a.action == "reset":
        d = lab.reset()
        print(green(f"workspace reset: {d.relative_to(PROJECT_ROOT)} (a copy of {lab.ORIGIN.name})"))
    elif a.action == "apply":
        if not a.args:
            print("usage: tapm lab apply <edit> [<edit> ...]\n")
            for k, v in lab.EDITS_HELP.items():
                print(f"  {k:<38} {v}")
            return
        if not lab.WORKSPACE.exists():
            lab.reset()
        for e in a.args:
            try:
                msg = lab.apply_edit(lab.WORKSPACE, e)
            except ValueError as err:
                sys.exit(red(str(err)))
            print(green(f"applied: {msg}"))
    elif a.action == "sync":
        info = lab.sync()
        print(dim(f"plan: {info['plan']}   scanner baselines: {info['baselines']}"))
    elif a.action == "check":
        level = int(a.args[0]) if a.args else 1
        checks, notes = lab.check(level)
        print(bold(f"Level {level} checks"))
        for label, ok, detail in checks:
            mark = green("PASS    ") if ok else amber("NOT YET ") if ok is None else red("FAIL    ")
            print(f"  {mark} {label}" + dim(f"   {detail}" if detail else ""))
        for n in notes:
            print(f"  {amber('note')}     {n}")
        passed = all(ok for _, ok, _ in checks)
        print()
        print(green(bold(f"  Level {level} complete.")) if passed else amber(f"  Level {level}: keep going (see labs/level-{level}.md)"))
        sys.exit(0 if passed else 1)
    elif a.action == "precompute":
        rows = lab.precompute(workers=int(a.args[0]) if a.args else 4)
        for r in rows:
            print(f"  {r['variant']:<60} plan {r['plan']:<8} baselines {r['baselines']}")
    elif a.action == "variants":
        for v in lab.variants():
            print("  bash labs/lab.sh apply " + " ".join(v))


def cmd_eval(a) -> None:
    if getattr(a, "eval_action", None) == "verify-precommit":
        from .eval.precommit import verify_precommitment_cli

        raw_files = getattr(a, "files", None) or []
        cli_args = list(raw_files)
        if getattr(a, "quiet", False):
            cli_args.append("--quiet")
        sys.exit(verify_precommitment_cli(cli_args))
    else:
        sys.exit("Usage: tapm eval verify-precommit [FILES...]")


def cmd_verify_precommit(a) -> None:
    from .eval.precommit import verify_precommitment_cli

    raw_files = getattr(a, "files", None) or []
    cli_args = list(raw_files)
    if getattr(a, "quiet", False):
        cli_args.append("--quiet")
    sys.exit(verify_precommitment_cli(cli_args))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="tapm", description="Terraform plan -> attack paths with PyTM and evidence-bound AI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def fx_cmd(name, fn, help_):
        p = sub.add_parser(name, help=help_)
        p.add_argument("fixture", nargs="?", default="006")
        p.add_argument("--out")
        p.add_argument("--no-dfd", action="store_true")
        p.set_defaults(fn=fn)
        return p

    p = fx_cmd("plan", cmd_plan, "terraform plan offline (or from plan-cache)")
    p.add_argument("--no-cache", action="store_true")
    p = fx_cmd("scan", cmd_scan, "baseline scanners (saved or --live)")
    p.add_argument("--live", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    fx_cmd("model", cmd_model, "graph + IAM + PyTM model")
    fx_cmd("paths", cmd_paths, "attack paths")
    p = fx_cmd("story", cmd_story, "each attack path in plain words, for developers or for everyone")
    p.add_argument("--audience", choices=["developer", "everyone"], default="developer")
    p.add_argument("-n", type=int, default=3, help="paths to tell")
    for name, fn in (("run", cmd_run), ("explain", cmd_explain), ("inject", cmd_inject)):
        p = fx_cmd(name, fn, name)
        p.add_argument("--plan", help="terraform show -json output (default: <dir>/plan.json)")
        p.add_argument("--baselines", help="directory with checkov.json / tfsec.json / trivy.json")
        p.add_argument("--user-entries", action="store_true", help="treat IAM users as compromised-credential entries")
        p.add_argument("--heuristic-sensitivity", action="store_true", help="classify data by name when untagged")
        p.add_argument("--target", action="append", help="extra asset address to treat as a target")
        p.add_argument("--sarif-prefix", help="repo-relative path of the Terraform dir, for SARIF locations")
        p.add_argument("--fail-on", choices=["high", "medium", "low"], help="exit 3 if a path at or above this priority exists")
        p.add_argument("--llm", default="simulated" if name != "run" else "off",
                       choices=["off", "simulated", "recorded", "anthropic", "openai", "ollama"])
        p.add_argument("--jev", default="local", choices=["local", "typesafe", "recorded"])
        p.add_argument("--model")
        p.add_argument("--include-comments", action="store_true")
        p.add_argument("--record", action="store_true", help="write live responses to cassettes/")
        if name == "run":
            p.add_argument("--remediate", action="store_true", help="also run the verified-remediation loop")
    inject_p = sub.choices["inject"]
    inject_p.add_argument("-n", "--runs", type=int, default=1, help="number of evaluation runs (default: 1)")
    inject_p.add_argument("--write-results", action="store_true", help="write to evaluations/results/ instead of artifacts/")
    inject_p.add_argument("--tag", default="local", help="tag for evaluation results (default: local)")
    p = sub.add_parser("gate", help="the PR check at an adoption level: observe | recommend | validate | prevent")
    p.add_argument("out_dir", help="output directory of `tapm run`")
    p.add_argument("--level", choices=["observe", "recommend", "validate", "prevent"], default="observe")
    p.add_argument("--fail-on", choices=["high", "medium", "low"], default="high", help="paths at or above this need a decision")
    p.add_argument("--tf-dir", help="Terraform directory; attack-path-exceptions.yaml is read from here")
    p.add_argument("--exceptions", help="accepted-risk file (default: <tf-dir>/attack-path-exceptions.yaml)")
    p.add_argument("--today", help="evaluate expiry as of this date (YYYY-MM-DD)")
    p.add_argument("--draft", action="store_true", help="print draft accepted-risk entries for paths without a decision")
    p.set_defaults(fn=cmd_gate)
    p = sub.add_parser("measure", help="kit metrics (counts only) from run directories; fills the baseline worksheet")
    p.add_argument("out_dirs", nargs="+")
    p.add_argument("--worksheet", help="kit/baseline-worksheet.csv (a copy you keep)")
    p.add_argument("--at", choices=["baseline", "day30", "day90", "day180"], default="baseline")
    p.add_argument("--json", action="store_true")
    p.add_argument("--per-run", action="store_true", help="with --json: include each run's counts")
    p.set_defaults(fn=cmd_measure)
    p = sub.add_parser("canary", help="level 5: known-bad plans must block, known-good must pass")
    p.add_argument("canaries", nargs="*", help="fixture names or directories with plan.json and gold.yaml or canary.yaml")
    p.add_argument("--level", choices=["validate", "prevent"], default="prevent")
    p.add_argument("--fail-on", choices=["high", "medium", "low"], default="high")
    p.add_argument("--json", help="write the result here")
    p.set_defaults(fn=cmd_canary)
    p = sub.add_parser("enrich", help="asynchronous AI enrichment from saved artifacts (never the plan)")
    p.add_argument("artifacts_dir", help="directory with attack-paths.json and evidence.json")
    p.add_argument("--llm", default="simulated", choices=["simulated", "recorded", "anthropic", "openai", "ollama"])
    p.add_argument("--model")
    p.add_argument("--jev", default="local", choices=["local", "typesafe", "recorded"])
    p.add_argument("--max-paths", type=int, default=3, help="per-PR path cap (default: 3)")
    p.add_argument("--no-cache", action="store_true", help="bypass AI cache")
    p.add_argument("--cache-dir", help="custom AI cache directory")
    p.add_argument("--record", action="store_true", help="write live responses to cassettes/")
    p.set_defaults(fn=cmd_enrich)
    p = sub.add_parser("serve", help="run the analysis service API and worker queue (W1.1)")
    p.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    p.add_argument("--token", help="Bearer token for API authentication (or env TAPM_SERVER_TOKEN)")
    p.add_argument("--workers", type=int, default=2, help="worker pool size (default: 2)")
    p.add_argument("--data-dir", help="working directory for jobs and artifacts (default: temporary dir)")
    p.add_argument("--llm", default="simulated", choices=["off", "simulated", "recorded", "anthropic", "openai", "ollama"])
    p.add_argument("--model", help="model name")
    p.add_argument("--jev", default="local", choices=["local", "typesafe", "recorded"])
    p.add_argument("--log-format", default="text", choices=["text", "json"], help="structured log format (default: text)")
    p.add_argument("--git-server", choices=["gitea", "github"], help="Git server type for status/comments (W1.2)")
    p.add_argument("--git-base-url", help="Git server base URL (e.g. http://localhost:3000)")
    p.add_argument("--git-token", help="Git server token (or GITEA_TOKEN / GITHUB_TOKEN)")
    p.set_defaults(fn=cmd_serve)

    # Git status command (W1.2)
    p = sub.add_parser("git-status", help="post commit status check to Gitea or GitHub (W1.2)")
    p.add_argument("--server", choices=["gitea", "github"], help="Git server type (auto-detected if omitted)")
    p.add_argument("--base-url", help="Git server base URL")
    p.add_argument("--token", help="Git server access token")
    p.add_argument("--repo", required=True, help="repository in owner/repo format")
    p.add_argument("--sha", required=True, help="commit SHA to update status on")
    p.add_argument("--state", required=True, choices=["pending", "success", "warning", "failure", "error"], help="status state")
    p.add_argument("--description", "--desc", dest="description", help="short description of the status")
    p.add_argument("--context", default="attack-paths", help="status context name (default: attack-paths)")
    p.add_argument("--target-url", help="URL to job details or report")
    p.set_defaults(fn=cmd_git_status)

    # Git comment command (W1.2)
    p = sub.add_parser("git-comment", help="post or edit PR comment on Gitea or GitHub (W1.2)")
    p.add_argument("--server", choices=["gitea", "github"], help="Git server type (auto-detected if omitted)")
    p.add_argument("--base-url", help="Git server base URL")
    p.add_argument("--token", help="Git server access token")
    p.add_argument("--repo", required=True, help="repository in owner/repo format")
    p.add_argument("--pr", required=True, help="pull request or issue number")
    p.add_argument("--body", help="comment markdown text")
    p.add_argument("--body-file", help="path to file containing comment markdown")
    p.add_argument("--no-update", action="store_true", help="always post new comment, never edit existing")
    p.add_argument("--marker", help="comment marker string for identifying existing comments")
    p.set_defaults(fn=cmd_git_comment)

    # Runner client submit command (W1.3)
    p = sub.add_parser("submit", help="runner client: post plan to analysis service, poll, and exit per level (W1.3)")
    p.add_argument("plan", nargs="?", help="path to plan JSON file (default: plan.json)")
    p.add_argument("--plan", dest="plan_flag", help="path to plan JSON file")
    p.add_argument(
        "--server",
        "--url",
        dest="server",
        help="analysis service URL (default: http://127.0.0.1:8080 or TAPM_SERVER_URL)",
    )
    p.add_argument("--token", help="Bearer token for analysis service (or TAPM_SERVER_TOKEN)")
    p.add_argument("--repo", help="repository in owner/repo format (auto-detected if omitted)")
    p.add_argument("--pr", help="pull request or issue number (auto-detected if omitted)")
    p.add_argument("--sha", help="commit SHA (auto-detected if omitted)")
    p.add_argument("--root-module", default=".", help="root module path (default: .)")
    p.add_argument(
        "--level",
        choices=["observe", "recommend", "validate", "prevent"],
        default="observe",
        help="adoption level (default: observe)",
    )
    p.add_argument(
        "--fail-on",
        choices=["high", "medium", "low"],
        default="high",
        help="severity threshold (default: high)",
    )
    p.add_argument("--timeout", type=float, default=60.0, help="timeout in seconds for polling (default: 60.0)")
    p.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help="interval between polls in seconds (default: 0.5)",
    )
    p.add_argument("--exceptions", help="path to attack-path-exceptions.yaml")
    p.add_argument("--answers", help="path to threat-answers.yaml")
    p.add_argument("--out", "--artifacts-dir", dest="out", help="optional directory to download job artifacts")
    p.add_argument("--no-enrich", action="store_true", help="do not trigger async AI enrichment")
    p.add_argument("--trigger", choices=["pr_change", "exceptions_only", "repush", "nightly", "version_upgrade"], help="event trigger type for metrics")
    p.add_argument("--plan-ms", type=int, help="upstream terraform plan latency in milliseconds")
    p.add_argument("--scanners-ms", type=int, help="upstream IaC scanners latency in milliseconds")
    p.add_argument("--json", action="store_true", help="output JSON result to stdout")
    p.set_defaults(fn=cmd_submit)

    # Persona report command (W1.4, W3.1, W3.3)
    p = sub.add_parser("report", help="render persona reports (platform, developer, appsec, executive) (W1.4, W3)")
    p.add_argument("artifacts", nargs="?", default=None, help="run artifacts directory for developer/appsec report")
    p.add_argument(
        "--persona",
        choices=["platform", "developer", "appsec", "executive"],
        default="platform",
        help="persona to generate report for (default: platform)",
    )
    p.add_argument(
        "--server",
        "--url",
        dest="server",
        help="analysis service URL (default: http://127.0.0.1:8080 or TAPM_SERVER_URL)",
    )
    p.add_argument("--token", help="Bearer token for analysis service (or TAPM_SERVER_TOKEN)")
    p.add_argument("--file", "-f", dest="file", help="path to JSON file containing /v1/metrics (or '-' for stdin)")
    p.add_argument(
        "--format",
        choices=["markdown", "text", "json", "sarif"],
        default="markdown",
        help="output format (default: markdown; for developer persona, json includes comment_markdown and first_screen_items)",
    )
    p.add_argument("--out", "-o", dest="out", help="output file path (default: stdout)")
    p.add_argument("--worksheet", help="path to baseline-worksheet.csv for historical trends (executive persona)")
    p.add_argument("--month", help="reporting month string e.g. 'October 2026' (executive persona)")
    p.set_defaults(fn=cmd_report)

    # Multi-root matrix and sharded sweep (W1.5)
    p = sub.add_parser("matrix", help="affected-module CI matrix and sharded sweep for many root modules (W1.5)")
    p.add_argument("repo", nargs="?", default=".", help="repository root directory (default: current directory)")
    p.add_argument("--roots", help="glob pattern or comma-separated list of root directories (e.g. 'roots/*', 'infra/*')")
    p.add_argument("--changed", nargs="*", help="changed file paths (or '-' for stdin)")
    p.add_argument("--diff-against", dest="diff_against", help="git ref to diff against (e.g. origin/main, HEAD~1)")
    p.add_argument("--git-diff", action="store_true", help="detect changed files using git diff against HEAD")
    p.add_argument("--all", action="store_true", help="include all root modules (for full sweeps)")
    p.add_argument("--shards", type=int, help="total number of shards for nightly sweep")
    p.add_argument("--shard-index", type=int, help="shard index to execute (1-indexed)")
    p.add_argument("--shard", help="shard specification, e.g. '1/4'")
    p.add_argument(
        "--format",
        choices=["github", "gitlab", "json", "text"],
        default="github",
        help="matrix format (default: github)",
    )
    p.add_argument("--out", "-o", help="file to write matrix output to (default: stdout)")
    p.add_argument("--plan", action="store_true", help="execute re-planning for only the affected root modules")
    p.add_argument("--out-dir", help="directory to write generated plans/artifacts into")
    p.set_defaults(fn=cmd_matrix)

    p = sub.add_parser("validate", help="validate annotation JSON against an artifacts dir")
    p.add_argument("annotation")
    p.add_argument("--artifacts", default=str(ARTIFACTS / "006-public-workload-iam-sensitive-bucket"))
    p.set_defaults(fn=cmd_validate)
    fx_cmd("security-tests", cmd_security_tests, "negative tests for the AI boundary")
    p = sub.add_parser("tamper", help="demo: remove or forge an annotation's evidence and re-validate")
    p.add_argument("--annotation", default="ANN-001")
    p.add_argument("--mode", choices=["remove", "forge"], default="remove")
    p.add_argument("--artifacts", default=str(ARTIFACTS / "006-public-workload-iam-sensitive-bucket"))
    p.set_defaults(fn=cmd_tamper)
    p = fx_cmd("replay", cmd_replay, "run N times and compare artifact hashes")
    p.add_argument("-n", type=int, default=10)
    p = sub.add_parser("tier2", help="real-world corpus at frozen commits")
    p.add_argument("cases", nargs="*")
    p.add_argument("--tag", default="run")
    p.add_argument("--heldout", action="store_true", help="run held-out blind set (manifest-heldout.yaml)")
    p.add_argument("--manifest", default=None, help="manifest filename within evaluations/tier2/")
    p.add_argument("--write-results", action="store_true", help="write to evaluations/results/ instead of artifacts/")
    p.add_argument("--llm", choices=["off", "simulated", "recorded", "anthropic", "openai", "ollama"])
    p.add_argument("--decision", "--jev", dest="jev", default="local", choices=["local", "typesafe", "recorded"])
    p.add_argument("--model")
    p.add_argument("--max-paths", type=int, default=None)
    p.add_argument("--no-fallback", action="store_true", default=True)
    p.add_argument("--allow-fallback", dest="no_fallback", action="store_false")
    p.set_defaults(fn=cmd_tier2)
    p = sub.add_parser("realworld", help="benign real-world modules benchmark (E6)")
    p.add_argument("cases", nargs="*")
    p.add_argument("--tag", default="benign")
    p.add_argument("--manifest", default=None, help="manifest filename within evaluations/realworld/")
    p.add_argument("--write-results", action="store_true", help="write to evaluations/results/ instead of artifacts/")
    p.set_defaults(fn=cmd_realworld)
    p = sub.add_parser("bench", help="benchmark all fixtures")
    p.add_argument("fixtures", nargs="*")
    p.add_argument("--out", help="custom results directory (default: evaluations/results)")
    p.add_argument("--replay", type=int, default=10)
    p.add_argument("--live-scanners", action="store_true")
    p.add_argument("--llm", default="simulated", choices=["off", "simulated", "recorded", "anthropic", "openai", "ollama"])
    p.add_argument("--decision", "--jev", dest="jev", default="local", choices=["local", "typesafe", "recorded"])
    p.add_argument("--model")
    p.add_argument("--max-paths", type=int, default=None)
    p.add_argument("--no-fallback", action="store_true", default=True)
    p.add_argument("--allow-fallback", dest="no_fallback", action="store_false")
    p.set_defaults(fn=cmd_bench)
    p = sub.add_parser("terrara", help="TerrARA benchmark")
    p.add_argument("samples", nargs="*")
    p.add_argument("--llm", choices=["off", "simulated", "recorded", "anthropic", "openai", "ollama"])
    p.add_argument("--decision", "--jev", dest="jev", default="local", choices=["local", "typesafe", "recorded"])
    p.add_argument("--model")
    p.add_argument("--max-paths", type=int, default=None)
    p.add_argument("--no-fallback", action="store_true", default=True)
    p.add_argument("--allow-fallback", dest="no_fallback", action="store_false")
    p.set_defaults(fn=cmd_terrara)
    p = sub.add_parser("strata", help="re-cut evaluation results into simple/medium/complex strata (E7)")
    p.add_argument("--dir", help="directory with input result JSONs (default: evaluations/results)")
    p.add_argument("--out", help="output file path (default: evaluations/results/strata.json)")
    p.add_argument("--write-results", action="store_true", help="write to evaluations/results/strata.json instead of artifacts/strata.json")
    p.add_argument("--json", action="store_true", help="print JSON to stdout")
    p.set_defaults(fn=cmd_strata)

    p = fx_cmd("experiment", cmd_experiment, "v1 (LLM writes the model) vs v2 (deterministic + bounded AI), N runs")
    p.add_argument("-n", type=int, default=10)
    p.add_argument("--llm", default="recorded", choices=["recorded", "anthropic", "openai", "ollama", "simulated"])
    p.add_argument("--jev", default="local", choices=["local", "typesafe", "recorded"])
    p.add_argument("--model")
    p.add_argument("--record", action="store_true")
    p.add_argument("--write-results", action="store_true", help="write to evaluations/results/ instead of artifacts/")
    p.add_argument("--tag", default="local", help="tag for evaluation results (default: local)")
    p = fx_cmd("variability", cmd_variability, "AI repeated-run consistency on local or recorded model, N runs (E3)")
    p.add_argument("-n", type=int, default=5, help="number of repeated evaluation runs (default: 5)")
    p.add_argument("--llm", default="ollama", choices=["ollama", "recorded", "anthropic", "openai", "simulated"])
    p.add_argument("--jev", default="local", choices=["local", "typesafe", "recorded"])
    p.add_argument("--model")
    p.add_argument("--record", action="store_true")
    p.add_argument("--write-results", action="store_true", help="write to evaluations/results/ instead of artifacts/")
    p.add_argument("--tag", default="local", help="tag for evaluation results (default: local)")
    p = fx_cmd("ask", cmd_ask, "threat modeling as a few yes/no questions for the app team")
    p.add_argument("-n", type=int, default=6, help="questions to show")
    p.add_argument("--answers", help="threat-answers.yaml to apply (default: the one next to the Terraform)")
    p = fx_cmd("remediate", cmd_remediate, "AI proposes a patch; re-plan and re-run to prove its effect (A1)")
    p.add_argument("--llm", default="simulated", choices=["simulated", "recorded", "anthropic", "openai", "ollama"])
    p.add_argument("--model")
    p.add_argument("--record", action="store_true")
    p.add_argument("--attempts", type=int, default=3)
    p.add_argument("--paths", type=int, default=3, help="remediate at most this many paths (highest priority first)")
    p.add_argument("--cheat", action="store_true", help="stress test: the author first tries to game the verifier")
    p.add_argument("--write-cache", action="store_true", help="store new offline plans in plan-cache/ (needs Terraform)")
    p = sub.add_parser("patch-author", help="evaluate automated patch proposals on local or recorded model (E8)")
    p.add_argument("--fixtures", help="comma-separated fixture names (default: canonical path fixtures)")
    p.add_argument("--llm", default="ollama", choices=["ollama", "recorded", "anthropic", "openai", "simulated"])
    p.add_argument("--model", default="qwen3-coder:30b")
    p.add_argument("--attempts", type=int, default=3, help="max attempts per path (default: 3)")
    p.add_argument("--write-results", action="store_true", help="write to evaluations/results/ instead of artifacts/")
    p.add_argument("--write-cache", action="store_true", default=True, help="store new offline plans in plan-cache/")
    p.add_argument("--tag", default="local", help="tag for evaluation results (default: local)")
    p.add_argument("--out", help="output directory")
    p.set_defaults(fn=cmd_patch_author)
    p = sub.add_parser("ai-model", help="pytm model of this pipeline's own AI layer vs an unsafe design")
    p.add_argument("--llm", default="anthropic", choices=["anthropic", "openai", "ollama", "recorded", "simulated"])
    p.add_argument("--jev", default="typesafe", choices=["local", "typesafe", "recorded"])
    p.add_argument("--out")
    p.set_defaults(fn=cmd_ai_model)
    p = sub.add_parser("lab", help="audience lab workspace (labs/README.md)")
    p.add_argument("action", choices=["reset", "apply", "sync", "check", "precompute", "variants"])
    p.add_argument("args", nargs="*")
    p.set_defaults(fn=cmd_lab)

    p = sub.add_parser("eval", help="evaluation verification and diagnostics")
    eval_sub = p.add_subparsers(dest="eval_action")
    vp = eval_sub.add_parser("verify-precommit", help="verify evaluation pre-commitment (C8)")
    vp.add_argument("files", nargs="*", help="result JSON files to verify")
    vp.add_argument("--quiet", action="store_true", help="suppress detailed report")
    p.set_defaults(fn=cmd_eval)

    p = sub.add_parser("verify-precommit", help="verify evaluation pre-commitment (C8)")
    p.add_argument("files", nargs="*", help="result JSON files to verify")
    p.add_argument("--quiet", action="store_true", help="suppress detailed report")
    p.set_defaults(fn=cmd_verify_precommit)
    return ap


def main(argv: list[str] | None = None) -> None:
    ap = build_parser()
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
