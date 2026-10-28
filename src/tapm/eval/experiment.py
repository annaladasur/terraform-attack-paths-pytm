"""The architecture experiment (Plan §18-19): v1 vs v2 on the same input, N runs each.

v1 (abandoned)   Terraform source -> LLM "generate the threat model" -> elements, flows, paths
v2 (this repo)   Terraform plan -> deterministic graph / PyTM / paths -> bounded AI -> validator

Measured per architecture: how much the *security result* (flows, paths) varies
between identical runs, how much of it the deterministic graph supports, and how
many resources it names that do not exist. For v2 the AI text is measured
separately from the security result, because only the text is probabilistic.

This needs a real model, live or recorded (``--llm anthropic|openai|ollama``, add
``--record`` to save cassettes, then replay with ``--llm recorded``). The offline
stand-in is deterministic by construction and would measure nothing, so it is
refused rather than reported.
"""

from __future__ import annotations

import itertools
import json
import re
import statistics
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..ai.agents import SCHEMAS
from ..ai.llm import AnthropicLLM, CassetteLLM, OllamaLLM, OpenAILLM
from ..pipeline import run_deterministic
from ..terraform.offline_plan import strip_comments
from ..util import PROJECT_ROOT, dump_json, sha256
from .metadata import get_eval_metadata
from .replay import ai_variability, replay
from .stats import format_rate_with_ci, wilson_interval

PROMPT = Path(__file__).resolve().parents[1] / "ai" / "prompts" / "v1_threat_model.md"
SECURITY_EDGES = ("EXPOSES", "ROUTES_TO", "ASSUMES", "ALLOWS", "READS", "WRITES", "ESCALATES")
_ADDR = re.compile(r"^(?:module\.[\w-]+(?:\[[^\]]+\])?\.)*(?:data\.)?aws_[a-z0-9_]+\.[\w-]+(?:\[[^\]]+\])?$")


class NeedsRealModel(RuntimeError):
    pass


def make_run_llm(ai_cfg: dict, run_tag: str):
    kind = ai_cfg.get("llm", "simulated")
    cassettes = ai_cfg.get("cassette_dir", "cassettes")
    if kind in ("simulated", "scripted", "off"):
        raise NeedsRealModel("the experiment measures a real model's variability; use --llm anthropic|openai|ollama "
                             "(add --record to save cassettes) or --llm recorded to replay them")
    if kind == "recorded":
        return CassetteLLM(cassettes, run_tag=run_tag)
    if kind == "ollama":
        inner = OllamaLLM(ai_cfg.get("model"), num_ctx=ai_cfg.get("num_ctx"), seed=ai_cfg.get("seed"))
    elif kind in ("anthropic", "openai"):
        inner = {"anthropic": AnthropicLLM, "openai": OpenAILLM}[kind](ai_cfg.get("model"))
    else:
        raise ValueError(f"unknown or unsupported LLM backend: '{kind}'")
    return CassetteLLM(cassettes, inner=inner, run_tag=run_tag) if ai_cfg.get("record") else inner


def _norm(x: str) -> str:
    x = str(x).strip().strip("`'\"")
    return "internet" if "internet" in x.lower() or x.lower() in ("attacker", "external users", "users") else x


def _jaccard(a: set, b: set) -> float:
    return 1.0 if not a and not b else len(a & b) / len(a | b)


def score_v1(out: dict, g, det_paths) -> dict:
    """Compare one v1 answer with the deterministic graph of the same configuration."""
    real = {n for n, node in g.nodes.items() if not node.synthetic}
    known = real | {"internet"}
    any_edge = {frozenset((e.src, e.dst)) for e in g.edges.values()}
    sec_edge = {frozenset((e.src, e.dst)) for e in g.edges.values() if e.type in SECURITY_EDGES}
    elements = {_norm(e["id"]) for e in out.get("elements", [])}
    flows = {frozenset((_norm(f["src"]), _norm(f["dst"]))) for f in out.get("dataflows", [])
             if _norm(f["src"]) != _norm(f["dst"])}
    paths = {tuple(_norm(x) for x in p.get("nodes", [])) for p in out.get("attack_paths", [])}
    named = elements | {x for f in flows for x in f} | {x for p in paths for x in p}
    hallucinated = sorted(x for x in named if _ADDR.match(x) and x not in known)
    flows_on_resources = {f for f in flows if all(x in known for x in f)}
    supported = flows_on_resources & any_edge
    det = {tuple(p.nodes) for p in det_paths}
    det_targets = {(p.nodes[0], p.nodes[-1]) for p in det_paths}
    return {
        "elements": sorted(elements),
        "flows": sorted(sorted(f) for f in flows),
        "paths": sorted(list(p) for p in paths),
        "hallucinated_resources": hallucinated,
        "flow_precision": round(len(supported) / len(flows), 4) if flows else None,
        "flow_recall": round(len(flows & sec_edge) / len(sec_edge), 4) if sec_edge else None,
        "unsupported_flows": sorted(sorted(f) for f in flows - supported),
        "paths_exact": len(paths & det),
        "paths_right_target": sum(1 for p in paths if len(p) > 1 and (p[0], p[-1]) in det_targets),
        "paths_other": sorted(list(p) for p in paths if len(p) > 1 and (p[0], p[-1]) not in det_targets),
    }


def run_experiment(
    fx: Path,
    cfg,
    ai_cfg: dict,
    n: int = 10,
    out_dir: Path | str | None = None,
    write_results: bool = False,
    tag: str = "local",
    command: str | None = None,
) -> dict:
    res = run_deterministic(cfg)
    g = res.build.graph
    source = "\n\n".join(f"# file: {f.name}\n{strip_comments(f.read_text(encoding='utf-8'))}"
                         for f in sorted(Path(fx).glob("*.tf")))
    system = PROMPT.read_text(encoding="utf-8")

    # ---- v1: the model writes the threat model
    v1_runs = []
    base_seed = ai_cfg.get("seed") or 42
    for i in range(n):
        run_ai_cfg = dict(ai_cfg)
        run_ai_cfg["seed"] = base_seed + i
        llm = make_run_llm(run_ai_cfg, f"run{i:02d}")
        r = llm.complete("v1_threat_model", system, source, SCHEMAS["v1_threat_model"], {"bundle_hash": f"v1:{fx.name}"})
        row = {"run": i, "seed": run_ai_cfg["seed"], "backend": r.backend, "model": r.model, "latency_ms": r.latency_ms, "cost_usd": r.cost_usd,
               "output_sha256": sha256(r.text)}
        try:
            row.update(score_v1(json.loads(r.text), g, res.paths))
        except (json.JSONDecodeError, TypeError, KeyError, AttributeError) as e:
            row["error"] = f"unparseable output: {e}"
        v1_runs.append(row)
    ok = [r for r in v1_runs if "error" not in r]
    flow_sets = [frozenset(map(tuple, r["flows"])) for r in ok]
    path_sets = [frozenset(map(tuple, r["paths"])) for r in ok]
    pairs = list(itertools.combinations(flow_sets, 2))
    parsed_n = len(ok)
    v1 = {
        "runs": n, "parsed": parsed_n,
        "distinct_outputs": len({r["output_sha256"] for r in v1_runs}),
        "distinct_flow_sets": len(set(flow_sets)),
        "distinct_path_sets": len(set(path_sets)),
        "mean_pairwise_flow_jaccard": round(statistics.mean(_jaccard(a, b) for a, b in pairs), 4) if pairs else None,
        "flow_precision": _spread([r["flow_precision"] for r in ok]),
        "flow_recall": _spread([r["flow_recall"] for r in ok]),
        "runs_with_hallucinated_resources": sum(1 for r in ok if r["hallucinated_resources"]),
        "runs_with_hallucinated_resources_rate": format_rate_with_ci(sum(1 for r in ok if r["hallucinated_resources"]), parsed_n) if parsed_n else "n/a",
        "hallucinated_resources": sorted({x for r in ok for x in r["hallucinated_resources"]}),
        "runs_finding_the_deterministic_path_exactly": sum(1 for r in ok if r["paths_exact"]),
        "runs_finding_the_deterministic_path_rate": format_rate_with_ci(sum(1 for r in ok if r["paths_exact"]), parsed_n) if parsed_n else "n/a",
        "runs_reaching_the_right_target": sum(1 for r in ok if r["paths_right_target"]),
        "runs_reaching_the_right_target_rate": format_rate_with_ci(sum(1 for r in ok if r["paths_right_target"]), parsed_n) if parsed_n else "n/a",
        "cost_usd": _sum([r["cost_usd"] for r in v1_runs]),
        "median_latency_ms": statistics.median(r["latency_ms"] for r in v1_runs) if v1_runs else None,
        "per_run": v1_runs,
    }

    # ---- v2: deterministic security result + bounded AI text
    det = replay(replace(cfg, render_dfd=False), n)
    llms = iter([make_run_llm({**ai_cfg, "seed": base_seed + i}, f"run{i:02d}") for i in range(n)])
    ai = ai_variability(res, {**ai_cfg, "include_comments": False}, n, llm_factory=lambda: next(llms))
    v2 = {
        "runs": n,
        "deterministic_identical_runs": det["identical_runs"],
        "deterministic_identical_rate": format_rate_with_ci(det["identical_runs"], n),
        "artifacts": det["artifacts"],
        "deterministic_paths": [p.key for p in res.paths],
        "ai": ai,
    }

    cmd_str = command or " ".join(sys.argv)
    meta = get_eval_metadata(tag=tag, command=cmd_str)

    out = {
        "metadata": meta,
        "tag": tag,
        "command": meta["command"],
        "tool_versions": meta["tool_versions"],
        "git_sha": meta["git_sha"],
        "fixture": fx.name,
        "backend": v1_runs[0]["backend"] if v1_runs else None,
        "model": v1_runs[0]["model"] if v1_runs else None,
        "v1": v1,
        "v2": v2,
    }

    if out_dir:
        target_dir = Path(out_dir)
        target_file = target_dir if str(out_dir).endswith(".json") else target_dir / f"experiment-{tag}.json"
        target_dir = target_file.parent
    elif write_results:
        target_dir = PROJECT_ROOT / "evaluations" / "results"
        target_file = target_dir / f"experiment-{tag}.json"
    elif cfg.out_dir:
        target_dir = Path(cfg.out_dir)
        target_file = target_dir / "experiment.json"
    else:
        target_dir = PROJECT_ROOT / "artifacts" / "experiment" / fx.name
        target_file = target_dir / "experiment.json"

    target_dir.mkdir(parents=True, exist_ok=True)
    dump_json(out, target_file)
    if not write_results:
        (target_dir / "experiment.md").write_text(render(out), encoding="utf-8")
    out["out_file"] = str(target_file)
    return out



def _spread(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return {"mean": round(statistics.mean(xs), 4), "min": min(xs), "max": max(xs)}


def _sum(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs), 6) if xs else None


def _pct(s):
    return "n/a" if not s else f"{s['mean']:.0%} ({s['min']:.0%}–{s['max']:.0%})"


def render(out: dict) -> str:
    v1, v2 = out["v1"], out["v2"]
    ai = v2["ai"]
    distinct = [x["distinct_texts"] for x in ai["per_annotation"].values()]
    n = v1["runs"]
    rows = [
        ("Runs on identical input", n, n),
        ("Distinct security results (flow sets)", f"{v1['distinct_flow_sets']}/{v1['parsed']}", f"1/{n}" if v2["deterministic_identical_runs"] == n else f"{n - v2['deterministic_identical_runs'] + 1}/{n}"),
        ("Distinct attack-path sets", f"{v1['distinct_path_sets']}/{v1['parsed']}", f"1/{n}" if v2["deterministic_identical_runs"] == n else "see artifacts"),
        ("Mean pairwise flow agreement (Jaccard)", "n/a" if v1["mean_pairwise_flow_jaccard"] is None else f"{v1['mean_pairwise_flow_jaccard']:.0%}", "100%"),
        ("Flows supported by the plan (precision)", _pct(v1["flow_precision"]), "100% (by construction)"),
        ("Security relations found (recall vs. deterministic graph)", _pct(v1["flow_recall"]), "100% (by construction)"),
        ("Runs naming resources that do not exist", f"{v1['runs_with_hallucinated_resources']}/{v1['parsed']}", "0 (validator rejects)"),
        ("Runs that found the deterministic path exactly", f"{v1['runs_finding_the_deterministic_path_exactly']}/{v1['parsed']}", f"{n}/{n}"),
        ("Distinct AI texts per annotation (median)", "n/a", statistics.median(distinct) if distinct else "n/a"),
        ("AI annotations rejected by the validator", "no validator", f"{ai['rejected_total']}/{ai['annotations_total']}"),
        ("LLM cost (all runs)", f"${v1['cost_usd']}" if v1["cost_usd"] is not None else "n/a", "see ai-metrics.json"),
    ]
    lines = [f"# Architecture experiment: {out['fixture']}", "",
             f"Backend: `{out['backend']}`" + (f", model `{out['model']}`" if out["model"] else ""), "",
             "| | v1: LLM generates the threat model | v2: deterministic model + bounded AI |", "|---|---|---|"]
    lines += [f"| {a} | {b} | {c} |" for a, b, c in rows]
    if v1["hallucinated_resources"]:
        lines += ["", "Resources v1 named that are not in the plan: " + ", ".join(f"`{x}`" for x in v1["hallucinated_resources"])]
    lines += ["", "> Deterministic security logic is reproducible by construction. AI language remains probabilistic,",
              "> so it requires a separate acceptance boundary.", ""]
    return "\n".join(lines)
