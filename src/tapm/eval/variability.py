"""Evaluation runner for AI repeated-run consistency (Task E3 / Plan §18-19).

Measures across N runs on the local model (or recorded / remote):
1. Text variation: distinct statement strings per (path, agent).
2. Validator agreement: agreement on validator status (accepted, rejected, human_review).
3. Publishing boundary: 0 unsupported or influenced statements published.
4. Framework mapping agreement: Jaccard similarity, precision, recall vs.
   _map_hop(h, bundle) ground truth in src/tapm/ai/agents.py.
5. Operational metrics: calls per path, per-call latency (p50 / p95), cost ($0.0 local).
6. Statistical intervals: Wilson 95% score confidence intervals for all binomial rates.
7. Provenance: git SHAs, tool versions, command line, tag, gold hashes.
"""

from __future__ import annotations

import itertools
import json
import statistics
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..ai.agents import _map_hop
from ..ai.bundle import path_bundle
from ..ai.harness import run_ai
from ..ai.llm import AnthropicLLM, CassetteLLM, OllamaLLM, OpenAILLM, SimulatedLLM
from ..pipeline import run_deterministic
from ..util import PROJECT_ROOT, dump_json
from .metadata import get_eval_metadata
from .stats import format_rate_with_ci, wilson_interval


class NeedsRealModel(RuntimeError):
    pass


def make_run_llm(ai_cfg: dict, run_tag: str, seed: int | None = None):
    kind = ai_cfg.get("llm", "simulated")
    cassettes = ai_cfg.get("cassette_dir", "cassettes")
    if kind in ("simulated", "scripted", "off"):
        if ai_cfg.get("allow_simulated"):
            return SimulatedLLM()
        raise NeedsRealModel(
            "the variability evaluation measures repeated-run consistency on a real model; "
            "use --llm ollama|anthropic|openai or --llm recorded to replay them"
        )
    if kind == "recorded":
        return CassetteLLM(cassettes, run_tag=run_tag)
    if kind == "ollama":
        inner = OllamaLLM(ai_cfg.get("model"), num_ctx=ai_cfg.get("num_ctx"), seed=seed)
    elif kind in ("anthropic", "openai"):
        inner = {"anthropic": AnthropicLLM, "openai": OpenAILLM}[kind](ai_cfg.get("model"))
    else:
        raise ValueError(f"unknown or unsupported LLM backend: '{kind}'")
    return CassetteLLM(cassettes, inner=inner, run_tag=run_tag) if ai_cfg.get("record") else inner


def get_ground_truth_mappings(bundle: dict) -> list[tuple[str, str, str]]:
    """Extract deterministic ground truth framework mappings from path bundle hops."""
    out: list[tuple[str, str, str]] = []
    hops = bundle.get("subject", {}).get("hops", [])
    for h in hops:
        out.extend(_map_hop(h, bundle))
    return out


def _calc_p95(vals: list[float | int]) -> float | int:
    if not vals:
        return 0
    s = sorted(vals)
    return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]


def run_variability_eval(
    fx: Path,
    cfg: Any,
    ai_cfg: dict,
    n: int = 5,
    out_dir: Path | str | None = None,
    write_results: bool = False,
    tag: str = "local",
    command: str | None = None,
    base_seed: int = 42,
    llm_factory: Any = None,
) -> dict:
    """Run N evaluations of the AI layer on the given fixture; measure consistency across runs."""
    # 1. Run deterministic pipeline once to produce base graph, ledger, and paths
    res = run_deterministic(cfg)
    if not res.paths:
        raise ValueError(f"fixture '{fx.name}' emitted 0 paths; cannot evaluate AI variability")

    path_bundles = [(p, path_bundle(res, p, res.remedies)) for p in res.paths]
    gt_by_path: dict[str, list[str]] = {}
    for p, b in path_bundles:
        gt_mappings = get_ground_truth_mappings(b)
        gt_by_path[p.id] = sorted({m[1] for m in gt_mappings})

    runs: list[dict[str, Any]] = []
    all_calls: list[dict[str, Any]] = []

    # Temporary directory for run-specific artifact outputs so runs don't collide
    with tempfile.TemporaryDirectory(prefix="tapm-variability-") as tmp:
        tmp_path = Path(tmp)
        for i in range(n):
            seed = base_seed + i
            run_tag = f"run{i:02d}"
            run_out_dir = tmp_path / run_tag
            run_out_dir.mkdir(parents=True, exist_ok=True)

            run_ai_cfg = dict(ai_cfg)
            run_ai_cfg["seed"] = seed
            run_ai_cfg["cache"] = False  # Enforce evaluation of repeated LLM generation, not cache hits

            if llm_factory:
                run_llm = llm_factory(i, seed)
            else:
                run_llm = make_run_llm(run_ai_cfg, run_tag, seed=seed)

            run_cfg = replace(cfg, out_dir=run_out_dir)
            res_run = replace(res, cfg=run_cfg)

            t0 = time.monotonic()
            out = run_ai(res_run, run_ai_cfg, llm=run_llm)
            duration_ms = int((time.monotonic() - t0) * 1000)

            run_calls = out.get("calls", [])
            all_calls.extend(run_calls)

            runs.append({
                "run_index": i,
                "seed": seed,
                "duration_ms": duration_ms,
                "annotations": out.get("annotations", []),
                "summary": out.get("summary", {}),
                "metrics": out.get("metrics", {}),
                "calls_count": len(run_calls),
            })

    # 2. Analyze per-(path, agent) variability across runs
    per_annotation: dict[str, dict[str, Any]] = {}
    path_refs = [p.id for p in res.paths]

    # Collect keys
    all_keys = sorted({
        f"{a['path_ref']}:{a['agent']}"
        for r in runs
        for a in r["annotations"]
        if "path_ref" in a and "agent" in a
    })

    total_agreeing_verdicts = 0
    total_annotations_evaluated = 0

    fw_jaccards: list[float] = []
    fw_precisions: list[float] = []
    fw_recalls: list[float] = []
    fw_emitted_sets: list[set[str]] = []
    total_fw_tp = 0
    total_fw_emitted = 0

    for key in all_keys:
        pref, agent = key.split(":", 1)
        ann_runs: list[dict[str, Any]] = []
        for r in runs:
            match = next((a for a in r["annotations"] if a.get("path_ref") == pref and a.get("agent") == agent), None)
            if match:
                ann_runs.append(match)

        statements = [a.get("statement", "") for a in ann_runs]
        statuses = [a.get("status", "unknown") for a in ann_runs]
        distinct_texts = len(set(statements))

        # Modal status agreement
        status_counts: dict[str, int] = {}
        for s in statuses:
            status_counts[s] = status_counts.get(s, 0) + 1
        modal_status = max(status_counts, key=status_counts.get) if status_counts else "unknown"
        modal_count = status_counts.get(modal_status, 0)
        verdict_agreement_pct = round(modal_count / len(statuses), 4) if statuses else 1.0
        verdict_agreement_ci = wilson_interval(modal_count, len(statuses), 0.95) if statuses else None

        total_agreeing_verdicts += modal_count
        total_annotations_evaluated += len(statuses)

        rejected_count = sum(1 for a in ann_runs if a.get("status") == "rejected")
        # Enforced by validator: rejected annotations are never published; 0 unsupported statements published
        unsupported_published = sum(
            1 for a in ann_runs
            if a.get("status") == "accepted" and any(k for k, v in a.get("validation", {}).items() if not v)
        )

        ann_stat: dict[str, Any] = {
            "path_ref": pref,
            "agent": agent,
            "runs": len(ann_runs),
            "distinct_texts": distinct_texts,
            "sample_statement": statements[0] if statements else "",
            "modal_verdict": modal_status,
            "verdict_agreement": verdict_agreement_pct,
            "verdict_agreement_rate": format_rate_with_ci(modal_count, len(statuses)),
            "verdict_agreement_wilson_95": list(verdict_agreement_ci) if verdict_agreement_ci else None,
            "statuses": sorted(set(statuses)),
            "status_counts": status_counts,
            "rejected_count": rejected_count,
            "unsupported_published": unsupported_published,
        }

        # Framework mapper specific ground truth comparison
        if agent == "framework_mapper":
            gt_ids = set(gt_by_path.get(pref, []))
            ann_stat["ground_truth_ids"] = sorted(gt_ids)
            run_fw_details = []
            ann_fw_jaccards = []
            ann_fw_precisions = []
            ann_fw_recalls = []

            for ann in ann_runs:
                emitted_ids = sorted({m.get("id") for m in ann.get("mappings", []) if m.get("id")})
                em_set = set(emitted_ids)
                matching = sorted(em_set & gt_ids)
                jacc = round(len(matching) / len(em_set | gt_ids), 4) if (em_set | gt_ids) else 1.0
                prec = round(len(matching) / len(em_set), 4) if em_set else 0.0
                rec = round(len(matching) / len(gt_ids), 4) if gt_ids else 1.0

                ann_fw_jaccards.append(jacc)
                ann_fw_precisions.append(prec)
                ann_fw_recalls.append(rec)
                fw_emitted_sets.append(em_set)
                total_fw_tp += len(matching)
                total_fw_emitted += len(em_set)

                run_fw_details.append({
                    "annotation_id": ann.get("annotation_id"),
                    "emitted_ids": emitted_ids,
                    "matching_ids": matching,
                    "jaccard": jacc,
                    "precision": prec,
                    "recall": rec,
                })

            ann_stat["per_run"] = run_fw_details
            ann_stat["mean_jaccard"] = round(statistics.mean(ann_fw_jaccards), 4) if ann_fw_jaccards else 1.0
            ann_stat["mean_precision"] = round(statistics.mean(ann_fw_precisions), 4) if ann_fw_precisions else 1.0
            ann_stat["mean_recall"] = round(statistics.mean(ann_fw_recalls), 4) if ann_fw_recalls else 1.0
            ann_stat["distinct_id_sets"] = len({tuple(sorted(x)) for x in fw_emitted_sets})

            # Pairwise Jaccard between runs
            pairwise = []
            for (i1, s1), (i2, s2) in itertools.combinations(enumerate(fw_emitted_sets), 2):
                denom = len(s1 | s2)
                pairwise.append(len(s1 & s2) / denom if denom else 1.0)
            ann_stat["mean_pairwise_jaccard"] = round(statistics.mean(pairwise), 4) if pairwise else 1.0

            fw_jaccards.extend(ann_fw_jaccards)
            fw_precisions.extend(ann_fw_precisions)
            fw_recalls.extend(ann_fw_recalls)

        per_annotation[key] = ann_stat

    # 3. Overall Latencies & Costs
    call_latencies = [c["latency_ms"] for c in all_calls if c.get("latency_ms") is not None]
    call_costs = [c["cost_usd"] for c in all_calls if c.get("cost_usd") is not None]
    total_cost_usd = round(sum(call_costs), 6) if call_costs else 0.0

    p50_ms = round(statistics.median(call_latencies), 1) if call_latencies else 0
    p95_ms = round(_calc_p95(call_latencies), 1) if call_latencies else 0

    all_gt_ids = sorted({fid for ids in gt_by_path.values() for fid in ids})
    total_possible_gt = n * len(all_gt_ids)

    summary = {
        "runs": n,
        "fixture": fx.name,
        "backend": ai_cfg.get("llm", "unknown"),
        "model": ai_cfg.get("model"),
        "paths_count": len(res.paths),
        "calls_per_path": len(all_keys) // len(res.paths) if res.paths else 5,
        "generator_calls_per_path": len(all_keys) // len(res.paths) if res.paths else 5,
        "total_calls": len(all_calls),
        "cost_usd": total_cost_usd,
        "latency_ms": {
            "p50": p50_ms,
            "p95": p95_ms,
            "min": min(call_latencies) if call_latencies else 0,
            "max": max(call_latencies) if call_latencies else 0,
            "mean": round(statistics.mean(call_latencies), 1) if call_latencies else 0,
        },
        "annotations_total": total_annotations_evaluated,
        "unsupported_published": sum(a["unsupported_published"] for a in per_annotation.values()),
        "unsupported_published_rate": format_rate_with_ci(
            sum(a["unsupported_published"] for a in per_annotation.values()), total_annotations_evaluated
        ),
        "verdict_agreement_overall": format_rate_with_ci(total_agreeing_verdicts, total_annotations_evaluated),
        "framework_mapping_agreement": {
            "ground_truth_ids": all_gt_ids,
            "mean_jaccard": round(statistics.mean(fw_jaccards), 4) if fw_jaccards else 1.0,
            "mean_precision": round(statistics.mean(fw_precisions), 4) if fw_precisions else 1.0,
            "mean_recall": round(statistics.mean(fw_recalls), 4) if fw_recalls else 1.0,
            "pairwise_jaccard": round(
                statistics.mean([
                    len(s1 & s2) / len(s1 | s2) if (s1 | s2) else 1.0
                    for (i1, s1), (i2, s2) in itertools.combinations(enumerate(fw_emitted_sets), 2)
                ]),
                4,
            ) if len(fw_emitted_sets) > 1 else 1.0,
            "precision_rate": format_rate_with_ci(total_fw_tp, total_fw_emitted),
            "recall_rate": format_rate_with_ci(total_fw_tp, total_possible_gt),
        },
        "per_annotation": per_annotation,
    }

    cmd_str = command or " ".join(sys.argv)
    metadata = get_eval_metadata(gold_path=fx, tag=tag, command=cmd_str)

    out = {
        "command": cmd_str,
        "fixture": fx.name,
        "backend": ai_cfg.get("llm", "unknown"),
        "model": ai_cfg.get("model"),
        "tag": tag,
        "runs": n,
        "seeds": [base_seed + i for i in range(n)],
        "metadata": metadata,
        "git_sha": metadata.get("git_sha", {}),
        "tool_versions": metadata.get("tool_versions", {}),
        "summary": summary,
        "per_run": runs,
    }

    # Output file handling
    if out_dir:
        target_dir = Path(out_dir)
        target_file = target_dir if str(out_dir).endswith(".json") else target_dir / f"ai-variability-{tag}.json"
        target_dir = target_file.parent
    elif write_results:
        target_dir = PROJECT_ROOT / "evaluations" / "results"
        target_file = target_dir / f"ai-variability-{tag}.json"
    elif cfg.out_dir:
        target_dir = Path(cfg.out_dir)
        target_file = target_dir / f"ai-variability-{tag}.json"
    else:
        target_dir = PROJECT_ROOT / "artifacts" / "variability" / fx.name
        target_file = target_dir / f"ai-variability-{tag}.json"

    target_dir.mkdir(parents=True, exist_ok=True)
    dump_json(out, target_file)

    md_report = render_variability_markdown(out)
    if not write_results:
        md_file = target_dir / "variability.md"
        md_file.write_text(md_report, encoding="utf-8")

    out["out_file"] = str(target_file)
    return out


def render_variability_markdown(out: dict) -> str:
    s = out["summary"]
    fw = s["framework_mapping_agreement"]
    lat = s["latency_ms"]

    lines = [
        f"# AI Repeated-Run Consistency Evaluation: {out['fixture']}",
        "",
        f"- **Backend:** `{out['backend']}`" + (f", model `{out['model']}`" if out['model'] else ""),
        f"- **Runs:** {out['runs']} (seeds {out['seeds'][0]}..{out['seeds'][-1]})",
        f"- **Calls per Path:** {s['calls_per_path']} (total calls across all runs: {s['total_calls']})",
        f"- **Per-call Latency:** p50 `{lat['p50']} ms`, p95 `{lat['p95']} ms` (mean `{lat['mean']} ms`)",
        f"- **Cost:** `${s['cost_usd']:.2f}` (local model)",
        f"- **Overall Verdict Agreement:** {s['verdict_agreement_overall']}",
        f"- **Unsupported Published:** {s['unsupported_published']} ({s['unsupported_published_rate']})",
        "",
        "## Per-Annotation Consistency",
        "",
        "| Path Ref | Agent | Distinct Texts | Modal Verdict | Verdict Agreement (95% CI) | Unsupported Published |",
        "|---|---|---|---|---|---|",
    ]

    for key, a in s["per_annotation"].items():
        lines.append(
            f"| `{a['path_ref']}` | `{a['agent']}` | {a['distinct_texts']}/{a['runs']} | "
            f"`{a['modal_verdict']}` | {a['verdict_agreement_rate']} | {a['unsupported_published']} |"
        )

    lines += [
        "",
        "## Framework Mapping Agreement vs Ground Truth (`_map_hop`)",
        "",
        f"- **Ground Truth IDs ({len(fw['ground_truth_ids'])}):** " + ", ".join(f"`{x}`" for x in fw["ground_truth_ids"]),
        f"- **Mean Jaccard Agreement vs Ground Truth:** `{fw['mean_jaccard']:.1%}`",
        f"- **Mean Precision:** `{fw['mean_precision']:.1%}` ({fw['precision_rate']})",
        f"- **Mean Recall:** `{fw['mean_recall']:.1%}` ({fw['recall_rate']})",
        f"- **Pairwise Jaccard Across Runs:** `{fw['pairwise_jaccard']:.1%}`",
        "",
        "> In accordance with talk principles: security results and evidence validation remain strictly deterministic. "
        "Probabilistic natural language and framework associations are bounded, audited, and verified before publishing.",
        "",
    ]
    return "\n".join(lines)
