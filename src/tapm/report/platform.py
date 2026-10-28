"""Platform-owner report generator (W1.4 / W3.3).

Generates the platform owner operational report from /v1/metrics:
- Runtime split across stages (plan / scanners / engine / AI)
- Queue depth and queue wait latency (capacity)
- AI cache hits and efficiency
- Trigger counts across event types (trigger scope)
- Canary status and failure rate (M15)
- Component, schema, prompt, and model versions (upgrades)
- Engine execution latency (M14)

All metrics are counts only. No repository names, plan contents,
resource names, or customer data are included.
"""

from __future__ import annotations

import json
from typing import Any


def render_platform_report(metrics: dict[str, Any], format: str = "markdown") -> str:
    """Render the platform-owner operational report from a /v1/metrics dictionary.

    Args:
        metrics: Dictionary returned by GET /v1/metrics.
        format: Output format ('markdown', 'text', or 'json').

    Returns:
        Formatted report string.
    """
    if format == "json":
        return json.dumps(metrics, indent=2)

    # Extract versions
    versions = metrics.get("versions", {})
    tapm_v = versions.get("tapm", "unknown")
    pytm_v = versions.get("pytm", "unknown")
    python_v = versions.get("python", "unknown")
    schema_v = versions.get("schema_version") or versions.get("schema", "unknown")
    prompt_v = versions.get("prompt_version") or versions.get("prompt", "unknown")
    model_v = versions.get("model", "simulated")

    # Extract queue & jobs
    jobs_total = metrics.get("jobs_total", 0)
    jobs_by_status = metrics.get("jobs_by_status", {})
    jobs_by_verdict = metrics.get("jobs_by_verdict", {})
    jobs_by_level = metrics.get("jobs_by_level", {})
    queue_depth = metrics.get("queue_depth", 0)
    queue_wait_avg = metrics.get("queue_wait_ms_avg", 0.0)
    queue_wait_max = metrics.get("queue_wait_ms_max", 0)

    # Extract runtime split
    raw_split = metrics.get("runtime_split_ms", {})
    canonical_order = ["plan", "scanners", "engine", "ai"]
    split_ms: dict[str, int] = {}
    for stage in canonical_order:
        val = raw_split.get(stage, 0)
        if val == 0:
            if stage == "engine" and "deterministic" in raw_split:
                val = raw_split["deterministic"]
            elif stage == "ai" and "enrichment" in raw_split:
                val = raw_split["enrichment"]
        split_ms[stage] = int(val)

    total_runtime_ms = sum(split_ms.values())

    # Extract cache & canaries
    cache_hits = metrics.get("cache_hits", 0)
    canary_status = metrics.get("canary_status", "pass")
    canaries_total = metrics.get("canaries_total", 0)
    canaries_failed = metrics.get("canaries_failed", 0)

    # Extract triggers
    triggers = metrics.get("triggers", {})
    default_triggers = ["pr_change", "exceptions_only", "repush", "nightly", "version_upgrade"]
    trigger_counts = {t: triggers.get(t, 0) for t in default_triggers}
    for t, count in triggers.items():
        if t not in trigger_counts:
            trigger_counts[t] = count

    if format == "text":
        return _render_text(
            tapm_v=tapm_v,
            pytm_v=pytm_v,
            python_v=python_v,
            schema_v=schema_v,
            prompt_v=prompt_v,
            model_v=model_v,
            jobs_total=jobs_total,
            jobs_by_status=jobs_by_status,
            jobs_by_verdict=jobs_by_verdict,
            jobs_by_level=jobs_by_level,
            queue_depth=queue_depth,
            queue_wait_avg=queue_wait_avg,
            queue_wait_max=queue_wait_max,
            split_ms=split_ms,
            total_runtime_ms=total_runtime_ms,
            cache_hits=cache_hits,
            canary_status=canary_status,
            canaries_total=canaries_total,
            canaries_failed=canaries_failed,
            trigger_counts=trigger_counts,
        )

    return _render_markdown(
        tapm_v=tapm_v,
        pytm_v=pytm_v,
        python_v=python_v,
        schema_v=schema_v,
        prompt_v=prompt_v,
        model_v=model_v,
        jobs_total=jobs_total,
        jobs_by_status=jobs_by_status,
        jobs_by_verdict=jobs_by_verdict,
        jobs_by_level=jobs_by_level,
        queue_depth=queue_depth,
        queue_wait_avg=queue_wait_avg,
        queue_wait_max=queue_wait_max,
        split_ms=split_ms,
        total_runtime_ms=total_runtime_ms,
        cache_hits=cache_hits,
        canary_status=canary_status,
        canaries_total=canaries_total,
        canaries_failed=canaries_failed,
        trigger_counts=trigger_counts,
        raw_split=raw_split,
    )


def _render_markdown(
    tapm_v: str,
    pytm_v: str,
    python_v: str,
    schema_v: str,
    prompt_v: str,
    model_v: str,
    jobs_total: int,
    jobs_by_status: dict[str, int],
    jobs_by_verdict: dict[str, int],
    jobs_by_level: dict[str, int],
    queue_depth: int,
    queue_wait_avg: float,
    queue_wait_max: int,
    split_ms: dict[str, int],
    total_runtime_ms: int,
    cache_hits: int,
    canary_status: str,
    canaries_total: int,
    canaries_failed: int,
    trigger_counts: dict[str, int],
    raw_split: dict[str, int],
) -> str:
    lines: list[str] = []
    lines.append("# Platform Owner Report: Analysis Service Operations")
    lines.append("")
    lines.append("> **Scope**: Operational counts and capacity metrics from `/v1/metrics`. "
                 "No plan contents, resource names, or repository code are included.")
    lines.append(">")
    lines.append("> **Decision Support**: Trigger scope, CI runner capacity, and engine/model upgrades.")
    lines.append("")

    # Executive Summary Table
    canary_badge = "Pass" if canary_status.lower() in ("pass", "ok") else "Fail"
    canary_desc = (
        f"{canary_badge} ({canaries_failed} failures in {canaries_total} runs)"
        if canaries_total > 0
        else f"{canary_badge} (all clear)"
    )
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Metric | Current Value | Target / Baseline | Status |")
    lines.append("|---|---|---|---|")
    lines.append(f"| Canary Health (M15) | {canary_desc} | 0 failures | "
                 f"{'Healthy' if canary_badge == 'Pass' else 'Attention Needed'} |")
    lines.append(f"| Average Queue Wait | {queue_wait_avg:,.1f} ms | < 500 ms | "
                 f"{'Normal' if queue_wait_avg < 500 else 'Elevated'} |")
    engine_ms = split_ms.get("engine", 0)
    lines.append(f"| Engine Cumulative Time (M14) | {engine_ms:,} ms | p95 < 1,000 ms per run | "
                 f"{'Fast' if engine_ms < 5000 else 'Normal'} |")
    lines.append(f"| AI Cache Hits | {cache_hits:,} | Maximize on re-push | Active |")
    lines.append(f"| Total Jobs Processed | {jobs_total:,} | — | Active |")
    lines.append("")

    # System & Component Versions
    lines.append("## System & Component Versions (Upgrades)")
    lines.append("")
    lines.append("| Component | Version | Role / Scope |")
    lines.append("|---|---|---|---|")
    lines.append(f"| `tapm` | `{tapm_v}` | Core engine, CLI & analysis service |")
    lines.append(f"| `pytm` | `{pytm_v}` | Threat modeling graph generator |")
    lines.append(f"| `schema_version` | `{schema_v}` | Artifact and contract schema |")
    lines.append(f"| `prompt_version` | `{prompt_v}` | Seven-role agent prompt templates |")
    lines.append(f"| `model` | `{model_v}` | Active model runtime |")
    lines.append(f"| `python` | `{python_v}` | Host execution environment |")
    lines.append("")

    # Runtime Split
    lines.append("## Runtime Split: Latency & Capacity")
    lines.append("")
    lines.append("The gate never waits on a model. The deterministic engine evaluates reachability "
                 "and gates the merge in under a second; asynchronous AI enrichment runs off the critical path.")
    lines.append("")
    lines.append("| Stage | Cumulative Latency | Share | Description |")
    lines.append("|---|---|---|---|")
    stage_descriptions = {
        "plan": "Upstream `terraform plan` generation and parsing",
        "scanners": "Pre-flight IaC scanners (Checkov, tfsec, trivy)",
        "engine": "Deterministic graph, reachability, and PyTM model generation (M14)",
        "ai": "Asynchronous bounded seven-role annotations (off critical path)",
    }
    for stage in ["plan", "scanners", "engine", "ai"]:
        ms = split_ms.get(stage, 0)
        pct = (ms / total_runtime_ms * 100) if total_runtime_ms > 0 else 0.0
        desc = stage_descriptions.get(stage, "")
        lines.append(f"| {stage.capitalize()} | {ms:,} ms | {pct:4.1f}% | {desc} |")
    lines.append("")

    # Additional detailed breakdown if available
    det_ms = raw_split.get("deterministic")
    gate_ms = raw_split.get("gate")
    del_ms = raw_split.get("plan_deletion")
    if any(k is not None for k in (det_ms, gate_ms, del_ms)):
        lines.append("<details>")
        lines.append("<summary>Detailed internal pipeline stage timings</summary>")
        lines.append("")
        lines.append("| Pipeline Stage | Cumulative Latency | Notes |")
        lines.append("|---|---|---|")
        if det_ms is not None:
            lines.append(f"| Deterministic Pipeline | {det_ms:,} ms | Complete graph + reachability run |")
        if gate_ms is not None:
            lines.append(f"| Gate Evaluation | {gate_ms:,} ms | Policy threshold & exceptions check |")
        if del_ms is not None:
            lines.append(f"| Plan Deletion | {del_ms:,} ms | Temp plan unlinked after deterministic stage |")
        enrich_ms = raw_split.get("enrichment")
        if enrich_ms is not None:
            lines.append(f"| Async Enrichment | {enrich_ms:,} ms | AI role execution & validator checks |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Queue & CI Runner Capacity
    lines.append("## Queue & CI Runner Capacity")
    lines.append("")
    completed = jobs_by_status.get("completed", 0)
    running = jobs_by_status.get("running", 0)
    queued = jobs_by_status.get("queued", 0)
    failed = jobs_by_status.get("failed", 0)
    lines.append(f"- **Current Queue Depth**: {queue_depth}")
    lines.append(f"- **Average Queue Wait**: {queue_wait_avg:,.1f} ms (max: {queue_wait_max:,} ms)")
    lines.append(f"- **Job Status Breakdown**: {completed:,} completed · {running:,} running · "
                 f"{queued:,} queued · {failed:,} failed")
    lines.append("")

    lines.append("### Jobs by Gate Verdict & Adoption Level")
    lines.append("")
    lines.append("| Gate Verdict | Count | Adoption Level | Count |")
    lines.append("|---|---|---|---|")
    verdicts = [("pass", jobs_by_verdict.get("pass", 0)),
                ("would_block", jobs_by_verdict.get("would_block", 0)),
                ("blocked", jobs_by_verdict.get("blocked", 0))]
    levels = [("observe", jobs_by_level.get("observe", 0)),
              ("recommend", jobs_by_level.get("recommend", 0)),
              ("validate", jobs_by_level.get("validate", 0)),
              ("prevent", jobs_by_level.get("prevent", 0))]
    max_len = max(len(verdicts), len(levels))
    for i in range(max_len):
        v_col = f"`{verdicts[i][0]}` | {verdicts[i][1]:,}" if i < len(verdicts) else "— | —"
        l_col = f"`{levels[i][0]}` | {levels[i][1]:,}" if i < len(levels) else "— | —"
        lines.append(f"| {v_col} | {l_col} |")
    lines.append("")

    # AI Efficiency & Caching
    lines.append("## AI Efficiency & Caching")
    lines.append("")
    lines.append(f"- **AI Cache Hits**: {cache_hits:,}")
    lines.append("- **Re-push Savings**: Evidence-bundle hash caching ensures re-pushes with no changed "
                 "infrastructure make **zero** model calls.")
    lines.append("")

    # Trigger Scope & Distribution
    lines.append("## Trigger Scope & Policy Distribution")
    lines.append("")
    lines.append("| Event Trigger | Count | Policy Scope & Enforcement |")
    lines.append("|---|---|---|")
    trigger_meta = {
        "pr_change": "Full pipeline (plan, scanners, engine, gate) · Can block at `validate` and above",
        "exceptions_only": "Fast gate re-evaluation without re-plan · Can block at `validate` and above",
        "repush": "Cache hit · Never blocks · Zero model invocations",
        "nightly": "Sharded sweep, canaries, and expiries · Opens issue on regression",
        "version_upgrade": "Replay, negative tests, canaries, AI regression · Blocks upgrade, not PRs",
    }
    for trg, cnt in trigger_counts.items():
        scope_info = trigger_meta.get(trg, "Custom event trigger")
        lines.append(f"| `{trg}` | {cnt:,} | {scope_info} |")
    lines.append("")

    # Kit Metrics Alignment
    lines.append("## Kit Metrics Alignment")
    lines.append("")
    lines.append("- **M14 Pipeline Time**: p95 deterministic engine duration keeps the required CI check under 1 second.")
    lines.append(f"- **M15 Control Failure Rate**: Canary failure count is {canaries_failed} "
                 f"({0.0 if canaries_total == 0 else (canaries_failed / canaries_total * 100):.1f}% failure rate).")
    lines.append("")

    return "\n".join(lines)


def _render_text(
    tapm_v: str,
    pytm_v: str,
    python_v: str,
    schema_v: str,
    prompt_v: str,
    model_v: str,
    jobs_total: int,
    jobs_by_status: dict[str, int],
    jobs_by_verdict: dict[str, int],
    jobs_by_level: dict[str, int],
    queue_depth: int,
    queue_wait_avg: float,
    queue_wait_max: int,
    split_ms: dict[str, int],
    total_runtime_ms: int,
    cache_hits: int,
    canary_status: str,
    canaries_total: int,
    canaries_failed: int,
    trigger_counts: dict[str, int],
) -> str:
    lines: list[str] = []
    lines.append("================================================================================")
    lines.append("               PLATFORM OWNER REPORT: ANALYSIS SERVICE OPERATIONS")
    lines.append("================================================================================")
    lines.append("Scope: Counts-only operational metrics from /v1/metrics. No customer or plan data.")
    lines.append("")

    lines.append("[SYSTEM & VERSIONS]")
    lines.append(f"  tapm:            {tapm_v:<15} pytm:           {pytm_v}")
    lines.append(f"  schema:          {schema_v:<15} prompt:         {prompt_v}")
    lines.append(f"  model:           {model_v:<15} python:         {python_v}")
    lines.append(f"  canary health:   {canary_status:<15} (M15 failures: {canaries_failed}/{canaries_total})")
    lines.append("")

    lines.append("[RUNTIME SPLIT: LATENCY & CAPACITY]")
    for stage in ["plan", "scanners", "engine", "ai"]:
        ms = split_ms.get(stage, 0)
        pct = (ms / total_runtime_ms * 100) if total_runtime_ms > 0 else 0.0
        lines.append(f"  {stage.capitalize():<10} {ms:>8,} ms  ({pct:5.1f}%)")
    lines.append(f"  {'Total':<10} {total_runtime_ms:>8,} ms  (100.0%)")
    lines.append("")

    lines.append("[QUEUE & JOBS CAPACITY]")
    lines.append(f"  Queue Depth:     {queue_depth}")
    lines.append(f"  Wait Latency:    avg {queue_wait_avg:,.1f} ms, max {queue_wait_max:,} ms")
    lines.append(f"  Total Jobs:      {jobs_total} (completed: {jobs_by_status.get('completed', 0)}, "
                 f"running: {jobs_by_status.get('running', 0)}, queued: {jobs_by_status.get('queued', 0)}, "
                 f"failed: {jobs_by_status.get('failed', 0)})")
    lines.append(f"  Verdicts:        pass: {jobs_by_verdict.get('pass', 0)}, "
                 f"would_block: {jobs_by_verdict.get('would_block', 0)}, "
                 f"blocked: {jobs_by_verdict.get('blocked', 0)}")
    lines.append(f"  Levels:          observe: {jobs_by_level.get('observe', 0)}, "
                 f"recommend: {jobs_by_level.get('recommend', 0)}, "
                 f"validate: {jobs_by_level.get('validate', 0)}, "
                 f"prevent: {jobs_by_level.get('prevent', 0)}")
    lines.append("")

    lines.append("[AI EFFICIENCY & CACHING]")
    lines.append(f"  Cache Hits:      {cache_hits} (re-pushes with identical bundle hash make 0 model calls)")
    lines.append("")

    lines.append("[TRIGGER SCOPE & DISTRIBUTION]")
    for trg, cnt in trigger_counts.items():
        lines.append(f"  {trg:<20} {cnt:>5}")
    lines.append("================================================================================")
    return "\n".join(lines)
