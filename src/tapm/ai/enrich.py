"""Asynchronous AI enrichment from saved artifacts (Plane 7 / W0.3).

Reads only evidence.json, attack-paths.json, and resource-graph.json from an
artifacts directory (never the raw Terraform plan). Applies routing, agent
roles, validator, and adversarial reviewer with persistent caching by
bundle_hash + prompt_version + model, subject to a per-PR path cap.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .. import PROMPT_VERSION
from ..report.markdown import escape_statement
from ..util import dump_json
from .agents import ANNOTATION_TYPE, SCHEMAS, system_prompt, user_message
from .bundle import path_bundles_from_artifacts
from .cache import AICache, CachedLLM
from .harness import PUBLISH_THRESHOLD
from .jev import make_jev, path_state, question_escalation, questions_for_path
from .llm import LLMResult, SimulatedLLM, make_llm
from .validator import Validator


def render_ai_markdown(ai_doc: dict) -> str:
    """Render the Markdown section for AI annotations."""
    s = ai_doc["summary"]
    lines = [
        "## AI annotations (bounded, evidence-validated)",
        "",
        (
            f"{s['generated']} generated · {s['accepted']} evidence-backed and accepted · {s['rejected']} rejected · "
            f"{s['human_review']} routed to human review · backend `{ai_doc['manifest']['llm_backend']}`, "
            f"decision layer `{ai_doc['manifest']['jev_backend']}`"
        ),
        "",
    ]
    for a in ai_doc["annotations"]:
        if a["status"] != "accepted":
            continue
        lines.append(
            f"- **{a['annotation_id']}** ({a['type']}, {a.get('path_ref') or a.get('target_ref') or ''}): {escape_statement(a['statement'])}  "
        )
        lines.append(f"  Evidence: {', '.join(a['evidence_refs'])}")
    rej = [a for a in ai_doc["annotations"] if a["status"] != "accepted"]
    if rej:
        lines += [
            "",
            "<details><summary>Rejected or held annotations</summary>",
            "",
        ]
        for a in rej:
            lines.append(
                f"- {a['annotation_id']} ({a['type']}): **{a['status']}** — {escape_statement('; '.join(a.get('rejections', [])) or a.get('reason', ''))}"
            )
        lines += ["", "</details>"]
    lines.append("")
    return "\n".join(lines)


def update_report_markdown(report_text: str, ai_markdown: str) -> str:
    """Update or inject the AI annotations section into report.md."""
    ai_header = "## AI annotations (bounded, evidence-validated)"
    if ai_header in report_text:
        idx_start = report_text.index(ai_header)
        rest = report_text[idx_start + len(ai_header):]
        m = re.search(r"\n(?=## |<details><summary>Scanner findings|---)", rest)
        if m:
            idx_end = idx_start + len(ai_header) + m.start() + 1
            return report_text[:idx_start] + ai_markdown + report_text[idx_end:]
        return report_text[:idx_start] + ai_markdown

    for anchor in ("\n## Untrusted source comments", "\n<details><summary>Scanner findings", "\n---"):
        if anchor in report_text:
            parts = report_text.split(anchor, 1)
            return parts[0] + "\n" + ai_markdown + anchor + parts[1]

    return report_text + "\n" + ai_markdown


def enrich_artifacts(
    artifacts_dir: str | Path,
    cfg: dict | None = None,
    llm: Any = None,
    jev: Any = None,
    on_event: Any = None,
) -> dict:
    """Run asynchronous AI enrichment against an existing artifacts directory.

    Reads evidence.json and attack-paths.json; never reads or requires plan.json.
    """
    art = Path(artifacts_dir)
    ev_path = art / "evidence.json"
    ap_path = art / "attack-paths.json"

    if not ev_path.exists():
        raise FileNotFoundError(f"Missing evidence.json in {art}")
    if not ap_path.exists():
        raise FileNotFoundError(f"Missing attack-paths.json in {art}")

    cfg = dict(cfg or {})
    on_event = on_event or cfg.get("on_event")
    max_paths = cfg.get("max_paths", 3)

    # 1. Setup cache
    use_cache = cfg.get("cache") is not False
    cache_inst = None
    if use_cache:
        cache_inst = cfg.get("cache") if isinstance(cfg.get("cache"), AICache) else AICache(cfg.get("cache_dir"))

    # 2. Setup LLM and Jev
    fallback = SimulatedLLM() if cfg.get("allow_fallback") else None
    llm = llm or make_llm(
        cfg.get("llm", "simulated"),
        cfg.get("model"),
        cfg.get("cassette_dir", "cassettes"),
        record=cfg.get("record", False),
        prompt_version=PROMPT_VERSION,
        fallback=fallback,
        num_ctx=cfg.get("num_ctx"),
        seed=cfg.get("seed"),
    )
    if cache_inst:
        llm = CachedLLM(llm, cache_inst, prompt_version=PROMPT_VERSION)

    jev = jev or make_jev(cfg.get("jev", "local"), cfg.get("cassette_dir", "cassettes"), record=cfg.get("record", False))

    # 3. Setup Validator
    validator = Validator.from_artifacts(art)

    # 4. Rebuild bundles directly from artifacts (never the plan)
    path_bundles = path_bundles_from_artifacts(
        art,
        max_paths=max_paths,
        include_comments=cfg.get("include_comments", False),
    )

    annotations: list[dict] = []
    decisions: list[dict] = []
    calls: list[dict] = []
    jev_ms: list[int] = []
    n = 0

    def call(agent: str, context: dict, annotation: dict | None = None) -> tuple[dict | None, LLMResult]:
        bundle = context["bundle"]
        r = llm.complete(agent, system_prompt(agent), user_message(bundle, annotation), SCHEMAS[agent], context)
        calls.append({
            "agent": agent,
            "backend": r.backend,
            "model": r.model,
            "latency_ms": r.latency_ms,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
            "cost_usd": r.cost_usd,
            "stop_reason": r.stop_reason,
            "from_cache": getattr(r, "_from_cache", False),
        })
        try:
            return json.loads(r.text), r
        except (json.JSONDecodeError, TypeError):
            return None, r

    for path_data, bundle in path_bundles:
        pid = path_data["id"]
        findings = path_data.get("findings", [])
        state = path_state(bundle)
        t0 = time.monotonic()
        d = jev.decide(state, questions_for_path())
        jev_ms.append(int((time.monotonic() - t0) * 1000))
        route = d["route"]["choice"]
        sufficient = d["evidence_sufficiency"]["choice"]
        agents: list[str] = []
        if route != "NO_AI" and sufficient != "NO":
            agents.append("path_narrator" if route in ("NARRATE_PATH", "HUMAN_REVIEW") else "finding_explainer")
            if route in ("NARRATE_PATH", "HUMAN_REVIEW"):
                agents.append("plain_explainer")
            if findings:
                agents.append("finding_explainer")
            if d["want_remediation"]["noul"] >= 0.5:
                agents.append("remediation")
            if d["want_framework_mapping"]["noul"] >= 0.5:
                agents.append("framework_mapper")
        agents = list(dict.fromkeys(agents))
        decisions.append({
            "subject": pid,
            "state": state,
            "backend": jev.name,
            "outputs": {
                "annotation_required": route != "NO_AI",
                "route": route,
                "evidence_sufficiency": sufficient,
                "agents": agents,
                "human_review": route == "HUMAN_REVIEW" or sufficient == "REVIEW",
            },
            "raw": d,
        })

        for agent in agents:
            n += 1
            ann_id = f"ANN-{n:03d}"
            context = {"bundle": bundle}
            out, r = call(agent, context)
            ann = {
                "annotation_id": ann_id,
                "type": ANNOTATION_TYPE[agent],
                "agent": agent,
                "path_ref": pid,
                "backend": r.backend,
                "model": r.model,
                "prompt_version": PROMPT_VERSION,
                "bundle_hash": bundle["bundle_hash"],
            }
            if out is None:
                ann.update({
                    "statement": "",
                    "evidence_refs": [],
                    "status": "rejected",
                    "rejections": ["schema: output is not valid JSON"],
                })
                annotations.append(ann)
                if on_event:
                    on_event({
                        "role": agent,
                        "status": "rejected",
                        "latency_ms": r.latency_ms,
                        "model": r.model,
                        "annotation_id": ann_id,
                        "from_cache": getattr(r, "_from_cache", False),
                    })
                continue
            allowed = set(SCHEMAS[agent]["properties"])
            ann.update({k: v for k, v in out.items() if k in allowed})
            verdict = validator.validate(ann, bundle_ids=bundle["allowed_ids"], agent=agent, raw=out)
            ann["validation"] = verdict.checks
            if not verdict.accepted:
                ann["status"] = "rejected"
                ann["rejections"] = verdict.reasons
                annotations.append(ann)
                if on_event:
                    on_event({
                        "role": agent,
                        "status": "rejected",
                        "latency_ms": r.latency_ms,
                        "model": r.model,
                        "annotation_id": ann_id,
                        "rejections": verdict.reasons,
                        "from_cache": getattr(r, "_from_cache", False),
                    })
                continue
            review, rev_r = call("adversarial_reviewer", {"bundle": bundle, "annotation": out}, annotation=out)
            ann["review"] = review or {
                "verdict": "needs_review",
                "issues": [{"claim": "", "problem": "reviewer output invalid"}],
            }
            if on_event:
                on_event({
                    "role": "adversarial_reviewer",
                    "status": "reviewed",
                    "latency_ms": rev_r.latency_ms,
                    "model": rev_r.model,
                    "verdict": ann["review"].get("verdict"),
                    "from_cache": getattr(rev_r, "_from_cache", False),
                })
            t0 = time.monotonic()
            esc = jev.decide(
                {
                    "subject": ann_id,
                    "validator_accepted": True,
                    "reviewer_verdict": ann["review"].get("verdict"),
                    "reviewer_issues": len(ann["review"].get("issues") or []),
                },
                question_escalation(),
            )
            jev_ms.append(int((time.monotonic() - t0) * 1000))
            p = esc["publish_without_human"]["noul"]
            ann["escalation"] = {"publish_without_human": p, "threshold": PUBLISH_THRESHOLD}
            held = (
                decisions[-1]["outputs"]["human_review"]
                or ann["review"].get("verdict") != "accept"
                or p < PUBLISH_THRESHOLD
            )
            ann["status"] = "human_review" if held else "accepted"
            if held:
                ann["reason"] = "held for a human: " + (
                    "route/evidence requires review"
                    if decisions[-1]["outputs"]["human_review"]
                    else f"reviewer verdict {ann['review'].get('verdict')}, publish p={p}"
                )
            annotations.append(ann)
            if on_event:
                on_event({
                    "role": agent,
                    "status": ann["status"],
                    "latency_ms": r.latency_ms,
                    "model": r.model,
                    "annotation_id": ann_id,
                    "from_cache": getattr(r, "_from_cache", False),
                })

    summary = {
        "generated": len(annotations),
        "accepted": sum(1 for a in annotations if a["status"] == "accepted"),
        "rejected": sum(1 for a in annotations if a["status"] == "rejected"),
        "human_review": sum(1 for a in annotations if a["status"] == "human_review"),
        "evidence_backed": sum(1 for a in annotations if a["status"] != "rejected" and a.get("evidence_refs")),
        "unsupported": sum(1 for a in annotations if a["status"] == "rejected"),
    }
    costs = [c["cost_usd"] for c in calls]
    model_calls = getattr(llm, "model_calls", len(calls))
    cache_hits = getattr(llm, "cache_hits", sum(1 for c in calls if c.get("from_cache")))
    metrics = {
        "llm_calls": len(calls),
        "model_calls": model_calls,
        "cache_hits": cache_hits,
        "jev_calls": len(jev_ms),
        "llm_latency_ms_total": sum(c["latency_ms"] for c in calls),
        "jev_latency_ms_total": sum(jev_ms),
        "input_tokens": sum(c["input_tokens"] or 0 for c in calls),
        "output_tokens": sum(c["output_tokens"] or 0 for c in calls),
        "cost_usd": None if any(c is None for c in costs) else round(sum(costs), 6),
    }
    manifest = {
        "llm_backend": llm.name,
        "jev_backend": jev.name,
        "prompt_version": PROMPT_VERSION,
        "include_comments": bool(cfg.get("include_comments")),
        "publish_threshold": PUBLISH_THRESHOLD,
        "tools_offered_to_models": [],
        "max_paths_cap": max_paths,
    }
    ai_doc = {
        "manifest": manifest,
        "decisions": decisions,
        "annotations": annotations,
        "summary": summary,
        "metrics": metrics,
        "calls": calls,
    }

    # 5. Write artifacts
    dump_json({"manifest": manifest, "annotations": annotations, "summary": summary}, art / "ai-annotations.json")
    dump_json({
        "annotations": [
            {
                "annotation_id": a["annotation_id"],
                "status": a["status"],
                "checks": a.get("validation", {}),
                "rejections": a.get("rejections", []),
                "review": a.get("review"),
                "escalation": a.get("escalation"),
            }
            for a in annotations
        ]
    }, art / "validation.json")
    dump_json({"decisions": decisions}, art / "jev-decisions.json")
    dump_json({"metrics": metrics, "calls": calls}, art / "ai-metrics.json")

    # 6. Update report.md if present (or create it)
    rep_path = art / "report.md"
    ai_md = render_ai_markdown(ai_doc)
    if rep_path.exists():
        old_rep = rep_path.read_text(encoding="utf-8")
        new_rep = update_report_markdown(old_rep, ai_md)
        rep_path.write_text(new_rep, encoding="utf-8")
    else:
        rep_path.write_text(ai_md, encoding="utf-8")

    # 7. Update run-manifest.json if present
    man_path = art / "run-manifest.json"
    if man_path.exists():
        try:
            m = json.loads(man_path.read_text(encoding="utf-8"))
            m["ai"] = manifest
            m.setdefault("timings_ms", {})["ai"] = metrics["llm_latency_ms_total"] + metrics["jev_latency_ms_total"]
            dump_json(m, man_path)
        except Exception:
            pass

    return ai_doc
