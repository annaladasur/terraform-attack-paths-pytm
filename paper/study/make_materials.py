"""Build the study materials, the answer key and the participant assignments from the fixtures.

    python paper/study/make_materials.py        # writes paper/study/materials/, answer-key.yaml, assignments.csv

All three conditions describe the same plan and come from the same pipeline run, so they differ only in how they
present it. Fixture names are never shown to participants.
"""

from __future__ import annotations

import csv
import itertools
import re
import shutil
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

TASKS = {  # task -> fixture (hidden from participants)
    "practice": "002-public-s3",
    "plan-1": "006-public-workload-iam-sensitive-bucket",
    "plan-2": "009-resource-policy",
    "plan-3": "015-dynamic-blocks",
}
CONDITIONS = ("A", "B", "C")
N_QUESTIONS = 6
_SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5, "": 5}


def run(fixture: str, out: Path):
    from tapm.cli import fixture_config
    from tapm.pipeline import run_deterministic

    return run_deterministic(fixture_config(ROOT / "fixtures" / fixture, str(out)))


def cond_a(res) -> str:
    rows = sorted(res.findings, key=lambda f: (f.tool, _SEV.get((f.severity or "").upper(), 5), f.file, f.start_line, f.rule_id))
    L = ["# Scanner findings", "", f"{len(rows)} findings from Checkov, tfsec and Trivy on this plan.", "",
         "| Tool | Rule | Severity | Resource | Location | Finding |", "|---|---|---|---|---|---|"]
    for f in rows:
        loc = f"{f.file}:{f.start_line}" if f.file else ""
        L.append(f"| {f.tool} | {f.rule_id} | {f.severity or '-'} | {f.resource} | {loc} | {f.title} |")
    return "\n".join(L) + "\n"


def cond_b(res) -> str:
    rows = [r for r in res.pytm["classification"]["findings"] if r.get("in_generic")]
    rows.sort(key=lambda r: (r["element"], r["threat_id"]))
    L = ["# Threat model", "", f"{len(rows)} threats for the architecture described by this plan.", "",
         "| Element | Threat | Title | Severity |", "|---|---|---|---|"]
    for r in rows:
        el = r["element"] if not r.get("flow") else f"{r['flow']['source']} → {r['flow']['sink']}"
        L.append(f"| {el} | {r['threat_id']} | {r['description']} | {r.get('severity') or '-'} |")
    return "\n".join(L) + "\n"


def cond_c(res) -> str:
    from tapm.report.story import path_story, render_story

    L = ["# Attack paths", ""]
    if not res.paths:
        L.append("No way in: nothing in this configuration lets someone on the internet reach the sensitive data.")
    for i, p in enumerate(res.paths, start=1):
        L += [f"## Path {i}", "", render_story(path_story(res, p, "developer")).rstrip("\n"), ""]
    qs = (res.pytm.get("questions") or {}).get("questions", [])[:N_QUESTIONS]
    if qs:
        L += ["## Questions for the team that runs the application", ""]
        L += [f"{q['n']}. {q['question']}" for q in qs]
    return "\n".join(L) + "\n"


def _fix_site(rec) -> bool:
    """Evidence that sits where a fix is made: a network rule, a policy statement, or the IMDS setting."""
    if rec is None or not rec.source or not rec.source.get("file"):
        return False
    return rec.kind in ("NET", "IAM") or (rec.kind == "TF" and "http_tokens" in (rec.data or {}))


def key(res) -> dict:
    """Per path: target, nodes, and the source ranges where a fix breaks or downgrades it."""
    recs = res.build.ledger.by_id()
    paths = []
    for p in res.paths:
        fixes = []
        for r in res.remedies:
            if r.path != p.id or r.effect not in ("breaks_path", "downgrades_path"):
                continue
            locs = sorted({(x.source["file"], x.source["start_line"], x.source["end_line"])
                           for e in r.evidence if _fix_site(x := recs.get(e))})
            fixes.append({"hop": r.hop, "effect": "breaks" if r.effect == "breaks_path" else "downgrades",
                          "change": re.sub(r"\s+", " ", r.change),
                          "locations": [{"file": f, "start": a, "end": b} for f, a, b in locs]})
        paths.append({"target": p.target, "nodes": p.nodes, "priority": p.priority, "fixes": fixes})
    return {"has_path": bool(res.paths), "paths": paths}


def assignments(n: int = 24) -> list[dict]:
    seqs = [list(p) for p in itertools.permutations(CONDITIONS)]  # 6 sequences: a balanced Latin square for 3
    tasks = ["plan-1", "plan-2", "plan-3"]
    out = []
    for i in range(n):
        conds = seqs[i % 6]
        rot = (i // 6) % 3
        order = tasks[rot:] + tasks[:rot]
        out.append({"participant": f"P{i + 1:02d}", **{f"slot{k + 1}": f"{order[k]}:{conds[k]}" for k in range(3)}})
    return out


def main() -> None:
    mat = HERE / "materials"
    shutil.rmtree(mat, ignore_errors=True)
    answer = {}
    work = ROOT / "artifacts" / "study"
    for task, fx in TASKS.items():
        res = run(fx, work / task)
        d = mat / task
        (d / "terraform").mkdir(parents=True)
        for tf in sorted((ROOT / "fixtures" / fx).glob("*.tf")):
            shutil.copyfile(tf, d / "terraform" / tf.name)
        for c, text in zip(CONDITIONS, (cond_a(res), cond_b(res), cond_c(res))):
            (d / f"condition-{c}.md").write_text(text, encoding="utf-8")
        answer[task] = key(res)
    (HERE / "answer-key.yaml").write_text(
        "# Generated by make_materials.py from the pipeline's own what-if results. Freeze before the main study.\n"
        + yaml.safe_dump(answer, sort_keys=False, width=140), encoding="utf-8")
    with open(HERE / "assignments.csv", "w", newline="") as f:
        rows = assignments()
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"materials for {len(TASKS)} tasks x {len(CONDITIONS)} conditions -> {mat.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
