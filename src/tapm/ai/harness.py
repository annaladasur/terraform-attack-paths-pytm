"""Agent harness: deterministic control flow around bounded AI calls.

For each attack path:

    evidence bundle -> Jev: route / sufficiency / which agents
                    -> agent (LLM, no tools) -> JSON annotation
                    -> validator (deterministic)            -- reject? stop.
                    -> adversarial reviewer (LLM)
                    -> Jev: publish without a human?        -- no? human review.
                    -> accepted

The harness can annotate the security model. It has no code path that can
modify the graph, the paths, priorities or evidence: it only reads them.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .. import PROMPT_VERSION
from ..util import dump_json
from .agents import ANNOTATION_TYPE, SCHEMAS, system_prompt, user_message
from .bundle import path_bundle
from .jev import make_jev, path_state, question_escalation, questions_for_path
from .llm import LLMResult, SimulatedLLM, make_llm
from .validator import Validator

PUBLISH_THRESHOLD = 0.7


def run_ai(res, cfg: dict, llm=None, jev=None) -> dict:
    fallback = SimulatedLLM() if cfg.get("allow_fallback") else None
    llm = llm or make_llm(cfg.get("llm", "simulated"), cfg.get("model"), cfg.get("cassette_dir", "cassettes"),
                          record=cfg.get("record", False), prompt_version=PROMPT_VERSION,
                          fallback=fallback, num_ctx=cfg.get("num_ctx"), seed=cfg.get("seed"))
    if cfg.get("cache") is not False and cfg.get("cache") is not None:
        from .cache import AICache, CachedLLM

        cache_inst = cfg["cache"] if isinstance(cfg["cache"], AICache) else AICache(cfg.get("cache_dir"))
        llm = CachedLLM(llm, cache_inst, prompt_version=PROMPT_VERSION)
    jev = jev or make_jev(cfg.get("jev", "local"), cfg.get("cassette_dir", "cassettes"), record=cfg.get("record", False))
    validator = Validator.from_run(res)
    annotations: list[dict] = []
    decisions: list[dict] = []
    calls: list[dict] = []
    jev_ms: list[int] = []
    n = 0

    def call(agent: str, context: dict, annotation: dict | None = None) -> tuple[dict | None, LLMResult]:
        bundle = context["bundle"]
        r = llm.complete(agent, system_prompt(agent), user_message(bundle, annotation), SCHEMAS[agent], context)
        calls.append({"agent": agent, "backend": r.backend, "model": r.model, "latency_ms": r.latency_ms,
                      "input_tokens": r.input_tokens, "output_tokens": r.output_tokens, "cost_usd": r.cost_usd,
                      "stop_reason": r.stop_reason, "from_cache": getattr(r, "_from_cache", False)})
        try:
            return json.loads(r.text), r
        except (json.JSONDecodeError, TypeError):
            return None, r

    max_paths = cfg.get("max_paths")
    paths = res.paths[:max_paths] if max_paths is not None else res.paths
    for path in paths:
        bundle = path_bundle(res, path, res.remedies, include_comments=cfg.get("include_comments", False))
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
            if path.findings:
                agents.append("finding_explainer")
            if d["want_remediation"]["noul"] >= 0.5:
                agents.append("remediation")
            if d["want_framework_mapping"]["noul"] >= 0.5:
                agents.append("framework_mapper")
        agents = list(dict.fromkeys(agents))
        decisions.append({
            "subject": path.id, "state": state, "backend": jev.name,
            "outputs": {"annotation_required": route != "NO_AI", "route": route, "evidence_sufficiency": sufficient,
                        "agents": agents, "human_review": route == "HUMAN_REVIEW" or sufficient == "REVIEW"},
            "raw": d,
        })

        for agent in agents:
            n += 1
            ann_id = f"ANN-{n:03d}"
            context = {"bundle": bundle}
            out, r = call(agent, context)
            ann = {"annotation_id": ann_id, "type": ANNOTATION_TYPE[agent], "agent": agent, "path_ref": path.id,
                   "backend": r.backend, "model": r.model, "prompt_version": PROMPT_VERSION,
                   "bundle_hash": bundle["bundle_hash"]}
            if out is None:
                ann.update({"statement": "", "evidence_refs": [], "status": "rejected",
                            "rejections": ["schema: output is not valid JSON"]})
                annotations.append(ann)
                continue
            allowed = set(SCHEMAS[agent]["properties"])
            ann.update({k: v for k, v in out.items() if k in allowed})  # agents cannot set harness fields
            verdict = validator.validate(ann, bundle_ids=bundle["allowed_ids"], agent=agent, raw=out)
            ann["validation"] = verdict.checks
            if not verdict.accepted:
                ann["status"] = "rejected"
                ann["rejections"] = verdict.reasons
                annotations.append(ann)
                continue
            review, _ = call("adversarial_reviewer", {"bundle": bundle, "annotation": out}, annotation=out)
            ann["review"] = review or {"verdict": "needs_review", "issues": [{"claim": "", "problem": "reviewer output invalid"}]}
            t0 = time.monotonic()
            esc = jev.decide({"subject": ann_id, "validator_accepted": True,
                              "reviewer_verdict": ann["review"].get("verdict"),
                              "reviewer_issues": len(ann["review"].get("issues") or [])}, question_escalation())
            jev_ms.append(int((time.monotonic() - t0) * 1000))
            p = esc["publish_without_human"]["noul"]
            ann["escalation"] = {"publish_without_human": p, "threshold": PUBLISH_THRESHOLD}
            held = decisions[-1]["outputs"]["human_review"] or ann["review"].get("verdict") != "accept" or p < PUBLISH_THRESHOLD
            ann["status"] = "human_review" if held else "accepted"
            if held:
                ann["reason"] = "held for a human: " + ("route/evidence requires review" if decisions[-1]["outputs"]["human_review"]
                                                        else f"reviewer verdict {ann['review'].get('verdict')}, publish p={p}")
            annotations.append(ann)

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
    manifest = {"llm_backend": llm.name, "jev_backend": jev.name, "prompt_version": PROMPT_VERSION,
                "include_comments": bool(cfg.get("include_comments")), "publish_threshold": PUBLISH_THRESHOLD,
                "tools_offered_to_models": []}
    out = {"manifest": manifest, "decisions": decisions, "annotations": annotations, "summary": summary,
           "metrics": metrics, "calls": calls}
    art = Path(res.cfg.out_dir)
    dump_json({"manifest": manifest, "annotations": annotations, "summary": summary}, art / "ai-annotations.json")
    dump_json({"annotations": [{"annotation_id": a["annotation_id"], "status": a["status"], "checks": a.get("validation", {}),
                                "rejections": a.get("rejections", []), "review": a.get("review"), "escalation": a.get("escalation")}
                               for a in annotations]}, art / "validation.json")
    dump_json({"decisions": decisions}, art / "jev-decisions.json")
    dump_json({"metrics": metrics, "calls": calls}, art / "ai-metrics.json")
    return out
