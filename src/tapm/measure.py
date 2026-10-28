"""Counts for the kit's metrics (kit/metrics.md), read from ``tapm run`` / ``tapm gate`` output directories.

    tapm measure attack-paths/                                    # one run
    tapm measure runs/*/ --worksheet kit/baseline-worksheet.csv --at baseline

Only counts leave this function: no resource names, no paths, nothing from the plan. The output is safe to paste into
a challenge report (CHALLENGE.md). Metrics that need people (false-path rate, time to a security decision,
threat-model freshness) stay manual; the worksheet marks them.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import statistics
from pathlib import Path

FIRST_SCREEN_QUESTIONS = 6  # the same first screen as `tapm ask` and the TerrARA comparison

# metric id -> (name, how it is aggregated over runs, key in the per-run record)
AUTO = {
    "M1": ("Review items per change, before (scanner findings + pytm generic threats)", "median", "review_items_before"),
    "M2": ("Review items per change, after (paths + first-screen questions)", "median", "review_items_first_screen"),
    "M3": ("Attack paths at or above the threshold (per run)", "sum", "paths_in_scope"),
    "M4": ("Runs with a path at or above the threshold", "count_nonzero", "paths_in_scope"),
    "M5": ("Paths at or above the threshold without a decision (on the default branch: merged without one)", "sum",
           "without_decision"),
    "M6": ("Paths at or above the threshold covered by a valid accepted risk", "ratio", ("accepted", "paths_in_scope")),
    "M7": ("Remediated paths with a verified fix (re-planned, path gone)", "ratio", ("verified_break", "remediated_paths")),
    "M8": ("False-path rate (disputed as not reachable)", "ratio", ("not_reachable", "paths")),
    "M10": ("First-screen questions answered in threat-answers.yaml", "ratio", ("answers_applied", "first_screen_questions")),
    "M11": ("Scanner findings on a reported path", "ratio", ("scanner_findings_on_path", "scanner_findings")),
    "M12": ("Accepted risks that are valid (owner, reason, unexpired)", "ratio", ("exceptions_valid", "exceptions_total")),
    "M13": ("AI statements held or rejected by the validator", "ratio", ("ai_not_accepted", "ai_generated")),
    "M14": ("Pipeline time per run, p95 (ms)", "p95", "runtime_ms"),
}


def compute_m1(scanner_findings_count: int = 0, pytm_generic_count: int = 0) -> int:
    """Canonical M1 definition (Audit F29, Tracker D4 / A15):
    Review items per change, before = scanner findings + PyTM generic threats.
    On PR #42 (conference-snapshot): 40 scanner findings + 122 generic threats = 162.
    """
    return int(scanner_findings_count) + int(pytm_generic_count)


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def run_counts(out_dir: str | Path) -> dict:
    """One run's counts. Missing files leave their counts out rather than guessing zero."""
    d = Path(out_dir)
    rec: dict = {}
    ap = _load(d / "attack-paths.json")
    if ap is None:
        raise FileNotFoundError(f"{d}: no attack-paths.json (run `tapm run ... --out {d}` first)")
    paths = ap.get("paths", [])
    rec["paths"] = len(paths)
    for pr in ("high", "medium", "low"):
        rec[f"paths_{pr}"] = sum(p.get("priority") == pr for p in paths)
    sf = _load(d / "scanner-findings.json")
    if sf is not None:
        rec["scanner_findings"] = len(sf.get("findings", []))
        rec["scanner_findings_on_path"] = sum(bool(f.get("paths")) for f in sf["findings"])
    pf = _load(d / "pytm-findings.json")
    if pf is not None:
        s = pf.get("summary", {})
        for k in ("generic", "confirmed", "mitigated", "needs_app_team", "ruled_out", "decided_by_answers"):
            if k in s:
                rec[f"pytm_{k}"] = s[k]
    q = _load(d / "questions.json")
    if q is not None:
        rec["questions"] = len(q.get("questions", []))
        rec["first_screen_questions"] = min(FIRST_SCREEN_QUESTIONS, rec["questions"])
        rec["data_questions"] = len(q.get("data_questions", []))
        rec["answers_applied"] = sum(a.get("status") == "applied" for a in q.get("answers", []))
    if "scanner_findings" in rec and "pytm_generic" in rec:
        rec["review_items_before"] = compute_m1(rec["scanner_findings"], rec["pytm_generic"])
    if "questions" in rec:
        rec["review_items_full"] = rec["paths"] + rec.get("pytm_confirmed", 0) + rec["questions"]
        rec["review_items_first_screen"] = rec["paths"] + rec["first_screen_questions"] + rec["data_questions"]
    rg = _load(d / "resource-graph.json")
    if rg is not None:
        from .graph.kinds import ASSET_TYPES

        nodes = rg.get("nodes", [])
        stores = [n for n in nodes if n.get("type") in ASSET_TYPES]
        classified = [n for n in stores if n.get("sensitivity", {}).get("level", "unclassified") != "unclassified"]
        rec["data_stores_total"] = len(stores)
        rec["data_stores_classified"] = len(classified)
        rec["data_stores_sensitive"] = len([n for n in stores if n.get("sensitivity", {}).get("level", "unclassified") in ("confidential", "restricted")])
        rec["data_stores_unclassified"] = len(stores) - len(classified)
    g = _load(d / "gate.json")
    if g is not None:
        rec["gate_level"], rec["gate_decision"] = g["level"], g["decision"]
        rec["paths_in_scope"], rec["accepted"] = g["in_scope"], g["accepted"]
        rec["not_reachable"] = g.get("not_reachable", 0)
        rec["without_decision"] = g["without_decision"]
        risks = [e for e in g.get("exceptions", []) if e.get("disposition") != "not_reachable"]
        disputes = [e for e in g.get("exceptions", []) if e.get("disposition") == "not_reachable"]
        rec["exceptions_total"] = len(risks)
        rec["exceptions_valid"] = sum(e["state"] == "valid" for e in risks)
        rec["exceptions_expired"] = sum(e["state"] == "expired" for e in risks)
        rec["disputes_total"] = len(disputes)
        rec["disputes_valid"] = sum(e["state"] == "valid" for e in disputes)
    rm = _load(d / "remediations.json")
    if rm is not None:
        s = rm.get("summary", {})
        rec["remediated_paths"] = s.get("paths", 0)
        rec["verified_break"] = s.get("verified_break", 0)
        rec["verified_downgrade_only"] = s.get("verified_downgrade_only", 0)
    v = _load(d / "validation.json")
    if v is not None:
        st = [a.get("status") for a in v.get("annotations", [])]
        rec["ai_generated"] = len(st)
        rec["ai_accepted"] = st.count("accepted")
        rec["ai_not_accepted"] = len(st) - st.count("accepted")
    m = _load(d / "run-manifest.json")
    if m is not None and m.get("timings_ms"):
        rec["runtime_ms"] = sum(m["timings_ms"].values())
    return rec


def _agg(how, key, runs: list[dict]):
    if how == "ratio":
        num, den = key
        rows = [r for r in runs if num in r and den in r]
        n, d = sum(r[num] for r in rows), sum(r[den] for r in rows)
        return (round(100 * n / d, 1) if d else None), f"{n}/{d}" if rows else None
    vals = [r[key] for r in runs if key in r]
    if not vals:
        return None, None
    if how == "median":
        return statistics.median(vals), f"n={len(vals)}"
    if how == "sum":
        return sum(vals), f"n={len(vals)}"
    if how == "count_nonzero":
        return sum(1 for x in vals if x), f"of {len(vals)}"
    if how == "p95":
        s = sorted(vals)
        return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))], f"n={len(vals)}"
    raise ValueError(how)


def summarize(out_dirs: list[str | Path]) -> dict:
    runs = [run_counts(d) for d in out_dirs]
    metrics = {}
    for mid, (name, how, key) in AUTO.items():
        value, n = _agg(how, key, runs)
        metrics[mid] = {"metric": name, "value": value, "n": n, "unit": "%" if how == "ratio" else ""}
    return {"runs": len(runs), "metrics": metrics, "per_run": runs}


def fill_worksheet(worksheet: str | Path, summary: dict, at: str, on: dt.date | None = None) -> int:
    """Write the automatic metrics into the worksheet column ``at`` (baseline, day30, day90, day180). Returns the
    number of cells written; manual metrics are left as they are."""
    col = {"baseline": "baseline_value", "day30": "day30_value", "day90": "day90_value", "day180": "day180_value"}[at]
    path = Path(worksheet)
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
        fields = list(rows[0].keys()) if rows else []
    written = 0
    for r in rows:
        m = summary["metrics"].get(r["metric_id"])
        if m and m["value"] is not None:
            r[col] = m["value"]
            if at == "baseline":
                r["baseline_date"] = str(on or dt.date.today())
                r["baseline_n"] = m["n"]
            written += 1
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    return written
