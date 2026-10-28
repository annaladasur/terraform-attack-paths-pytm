"""Reproducibility: run the deterministic pipeline N times and compare artifact hashes (Plan §18).

Each run writes to a fresh directory in a fresh process-independent state (new
ledger, new graph), so identical hashes mean the stages are deterministic by
construction, not because of caching.
"""

from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path

from ..pipeline import run_deterministic
from ..util import sha256

TRACKED = ("resource-graph.json", "iam-relationships.json", "threat-model.py", "attack-paths.json", "evidence.json",
           "terraform-plan.json", "dfd.dot")


def replay(cfg, n: int = 10) -> dict:
    hashes: dict[str, list[str]] = {a: [] for a in TRACKED}
    with tempfile.TemporaryDirectory(prefix="tapm-replay-") as tmp:
        for i in range(n):
            out = Path(tmp) / f"run{i:02d}"
            run_deterministic(replace(cfg, out_dir=out))
            for a in TRACKED:
                p = out / a
                hashes[a].append(sha256(p.read_bytes()) if p.exists() else "absent")
    per_run = list(zip(*[hashes[a] for a in TRACKED]))
    identical_runs = sum(1 for r in per_run if r == per_run[0])
    return {
        "runs": n,
        "artifacts": {a: {"distinct": len(set(h)), "identical": len(set(h)) == 1, "hash": h[0][:16]} for a, h in hashes.items()},
        "identical_runs": identical_runs,
    }


def ai_variability(res, cfg: dict, n: int = 10, llm_factory=None) -> dict:
    """Run the AI stage N times on the same deterministic result; measure text variation and grounding.

    ``llm_factory`` returns the model for each run (so recorded runs can be kept apart)."""
    from ..ai.harness import run_ai

    texts: dict[str, list[str]] = {}
    statuses: dict[str, list[str]] = {}
    unsupported = 0
    total = 0
    for _ in range(n):
        out = run_ai(res, cfg, llm=llm_factory() if llm_factory else None)
        for a in out["annotations"]:
            k = f"{a['path_ref']}:{a['agent']}"
            texts.setdefault(k, []).append(a.get("statement", ""))
            statuses.setdefault(k, []).append(a["status"])
            total += 1
            unsupported += a["status"] == "rejected"
    return {
        "runs": n,
        "per_annotation": {k: {"distinct_texts": len(set(v)), "statuses": sorted(set(statuses[k]))} for k, v in texts.items()},
        "annotations_total": total,
        "rejected_total": unsupported,
        "unsupported_rate": round(unsupported / total, 4) if total else None,
    }
