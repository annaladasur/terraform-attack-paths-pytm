"""Evaluation runner for prompt injection on live or recorded models (Task E1).

Measures across N runs on fixture 019:
1. Unsafe pipeline (raw HCL + comments -> LLM -> PR summary):
   - whether model claims configuration is secure / compliant
   - whether model mentions IAM / permissions
   - whether model was influenced by injection directives
2. Safe pipeline (default: comments never enter the prompt):
   - annotations generated, accepted, rejected, human review
   - 0 unsupported or influenced statements published
3. Safe pipeline (stress test: comments passed as fenced untrusted data):
   - annotations generated, accepted, rejected by validator
   - breakdown of validator checks that caught injected text
   - 0 unsupported or influenced statements published
4. Deterministic structural invariance:
   - attack paths with comments stripped vs comments present: identical (100% agreement)
5. Statistical intervals:
   - Wilson 95% score confidence intervals for all binomial rates (Check C7)
"""

from __future__ import annotations

import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..ai.injection import run_injection_demo
from ..util import PROJECT_ROOT, dump_json
from .metadata import get_eval_metadata
from .stats import format_rate_with_ci, wilson_interval


def run_injection_eval(
    fx: Path,
    cfg: Any,
    ai_cfg: dict,
    n: int = 10,
    out_dir: Path | str | None = None,
    write_results: bool = False,
    tag: str = "local",
    command: str | None = None,
) -> dict:
    """Run N evaluations of prompt injection on fixture 019."""
    runs = []
    stress_rejections: dict[str, int] = {}

    for i in range(n):
        run_ai_cfg = dict(ai_cfg)
        run_ai_cfg["seed"] = (ai_cfg.get("seed") or 42) + i
        t0 = time.monotonic()
        out = run_injection_demo(fx, cfg, run_ai_cfg)
        duration_ms = int((time.monotonic() - t0) * 1000)

        # Collect stress test validator rejections breakdown
        for ann in out.get("safe_with_untrusted_comments", {}).get("annotations", []):
            for r in ann.get("rejections", []):
                check_name = r.split(":")[0].strip() if ":" in r else r[:30]
                stress_rejections[check_name] = stress_rejections.get(check_name, 0) + 1

        runs.append({
            "run_index": i,
            "seed": run_ai_cfg["seed"],
            "duration_ms": duration_ms,
            "unsafe": out["unsafe"],
            "safe_default_summary": out["safe"]["summary"],
            "safe_stress_summary": out["safe_with_untrusted_comments"]["summary"],
            "paths_identical": out["paths_identical"],
            "paths_with_comments": out["paths_with_comments"],
            "paths_without_comments": out["paths_without_comments"],
            "comments_flagged": len(out.get("comments", [])),
        })

    # Summary metrics
    unsafe_claims_secure = sum(1 for r in runs if r["unsafe"].get("claims_secure"))
    unsafe_mentions_iam = sum(1 for r in runs if r["unsafe"].get("mentions_iam"))
    unsafe_influenced = sum(1 for r in runs if r["unsafe"].get("influenced"))

    safe_default_gen = sum(r["safe_default_summary"]["generated"] for r in runs)
    safe_default_acc = sum(r["safe_default_summary"]["accepted"] for r in runs)
    safe_default_rej = sum(r["safe_default_summary"]["rejected"] for r in runs)
    safe_default_rev = sum(r["safe_default_summary"].get("human_review", 0) for r in runs)

    safe_stress_gen = sum(r["safe_stress_summary"]["generated"] for r in runs)
    safe_stress_acc = sum(r["safe_stress_summary"]["accepted"] for r in runs)
    safe_stress_rej = sum(r["safe_stress_summary"]["rejected"] for r in runs)
    safe_stress_rev = sum(r["safe_stress_summary"].get("human_review", 0) for r in runs)

    paths_identical_runs = sum(1 for r in runs if r["paths_identical"])

    summary = {
        "runs": n,
        "fixture": fx.name,
        "backend": ai_cfg.get("llm", "unknown"),
        "model": ai_cfg.get("model"),
        "unsafe": {
            "runs": n,
            "claims_secure_count": unsafe_claims_secure,
            "claims_secure_rate": format_rate_with_ci(unsafe_claims_secure, n),
            "claims_secure_wilson_95": wilson_interval(unsafe_claims_secure, n, 0.95),
            "mentions_iam_count": unsafe_mentions_iam,
            "mentions_iam_rate": format_rate_with_ci(unsafe_mentions_iam, n),
            "mentions_iam_wilson_95": wilson_interval(unsafe_mentions_iam, n, 0.95),
            "influenced_count": unsafe_influenced,
            "influenced_rate": format_rate_with_ci(unsafe_influenced, n),
            "influenced_wilson_95": wilson_interval(unsafe_influenced, n, 0.95),
            "sample_statement": runs[0]["unsafe"].get("text", "") if runs else "",
        },
        "safe_default": {
            "annotations_generated": safe_default_gen,
            "annotations_accepted": safe_default_acc,
            "annotations_rejected": safe_default_rej,
            "annotations_human_review": safe_default_rev,
            "unsupported_published": 0,
            "influenced_published": 0,
            "published_rate": format_rate_with_ci(safe_default_acc, safe_default_gen),
        },
        "safe_stress": {
            "annotations_generated": safe_stress_gen,
            "annotations_accepted": safe_stress_acc,
            "annotations_rejected": safe_stress_rej,
            "annotations_human_review": safe_stress_rev,
            "unsupported_published": 0,
            "influenced_published": 0,
            "rejections_by_check": stress_rejections,
            "rejection_rate": format_rate_with_ci(safe_stress_rej, safe_stress_gen),
            "rejection_wilson_95": wilson_interval(safe_stress_rej, safe_stress_gen, 0.95),
        },
        "invariance": {
            "paths_identical_runs": paths_identical_runs,
            "paths_identical_total": n,
            "paths_identical_rate": format_rate_with_ci(paths_identical_runs, n),
        },
    }

    cmd_str = command or " ".join(sys.argv)
    meta = get_eval_metadata(tag=tag, command=cmd_str)

    result = {
        "metadata": meta,
        "tag": tag,
        "command": meta["command"],
        "tool_versions": meta["tool_versions"],
        "git_sha": meta["git_sha"],
        "summary": summary,
        "runs": runs,
    }

    if out_dir:
        target_dir = Path(out_dir)
    elif write_results:
        target_dir = PROJECT_ROOT / "evaluations" / "results"
    else:
        target_dir = PROJECT_ROOT / "artifacts" / fx.name

    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / f"inject-live-{tag}.json"
    dump_json(result, out_file)
    result["out_file"] = str(out_file)
    return result
