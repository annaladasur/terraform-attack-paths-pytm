"""Score the developer study against the answer key and run the pre-stated tests (protocol.md, "Analysis").

    python paper/study/score.py responses.csv participants.csv [--key answer-key.yaml] [--json out.json]

Standard library only (no scipy), so the numbers can be checked by hand:
  exact two-sided sign test, Wilcoxon signed-rank (normal approximation, tie and continuity corrected),
  Holm correction over the two planned comparisons, Cohen's kappa for the two fix coders, SUS.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
FIX_VALUE = {"breaks": 1.0, "downgrades": 0.5, "none": 0.0}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def found(row: dict, key: dict) -> bool:
    if str(row.get("q1_found", "")).strip().lower() not in ("yes", "y", "true", "1"):
        return False
    ans = _norm(row.get("q1_target", ""))
    return any(_norm(p["target"].split(".")[-1]) in ans for p in key["paths"]) if ans else False


def located(row: dict, key: dict) -> bool:
    m = re.match(r"\s*([\w./-]+\.tf)\s*:\s*(\d+)", row.get("q2_line", "") or "")
    if not m:
        return False
    f, line = m.group(1).split("/")[-1], int(m.group(2))
    return any(loc["file"] == f and loc["start"] <= line <= loc["end"]
               for p in key["paths"] for fx in p["fixes"] for loc in fx["locations"])


def fix_code(row: dict) -> str | None:
    """The adjudicated code if present, else the coders' code when they agree; None means 'adjudicate me'."""
    if row.get("fix_code"):
        return row["fix_code"].strip().lower()
    a, b = (row.get("fix_code_r1") or "").strip().lower(), (row.get("fix_code_r2") or "").strip().lower()
    return a if a and a == b else None


def score_row(row: dict, key: dict) -> dict:
    code = fix_code(row)
    f, l = found(row, key), located(row, key)
    fixed = FIX_VALUE.get(code) if code else None
    return {"participant": row["participant"], "task": row["task"], "condition": row["condition"],
            "sec_training": row.get("sec_training", ""), "found": f, "located": l, "fixed": fixed,
            "score": None if fixed is None else f + l + fixed,
            "time_s": float(row["time_s"]) if row.get("time_s") else None,
            "confidence": int(row["confidence"]) if row.get("confidence") else None}


# ---------------------------------------------------------------- statistics
def sign_test(diffs: list[float]) -> dict:
    nz = [d for d in diffs if d != 0]
    n, k = len(nz), sum(1 for d in nz if d > 0)
    if n == 0:
        return {"n": 0, "positive": 0, "p": 1.0}
    tail = sum(math.comb(n, i) for i in range(0, min(k, n - k) + 1)) / 2 ** n
    return {"n": n, "positive": k, "p": min(1.0, 2 * tail)}


def wilcoxon(diffs: list[float]) -> dict:
    nz = [d for d in diffs if d != 0]
    n = len(nz)
    if n == 0:
        return {"n": 0, "w_plus": 0.0, "z": 0.0, "p": 1.0}
    order = sorted(range(n), key=lambda i: abs(nz[i]))
    ranks = [0.0] * n
    ties = []
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(nz[order[j + 1]]) == abs(nz[order[i]]):
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        ties.append(j - i + 1)
        i = j + 1
    w_plus = sum(r for r, d in zip(ranks, nz) if d > 0)
    mean = n * (n + 1) / 4
    var = n * (n + 1) * (2 * n + 1) / 24 - sum(t ** 3 - t for t in ties) / 48
    if var <= 0:
        return {"n": n, "w_plus": w_plus, "z": 0.0, "p": 1.0}
    z = (abs(w_plus - mean) - 0.5) / math.sqrt(var)
    return {"n": n, "w_plus": w_plus, "z": round(z, 4), "p": min(1.0, math.erfc(max(z, 0) / math.sqrt(2)))}


def holm(ps: dict[str, float]) -> dict[str, float]:
    items = sorted(ps.items(), key=lambda kv: kv[1])
    m, out, running = len(items), {}, 0.0
    for i, (k, p) in enumerate(items):
        running = max(running, min(1.0, (m - i) * p))
        out[k] = running
    return out


def cohen_kappa(a: list[str], b: list[str]) -> float | None:
    pairs = [(x, y) for x, y in zip(a, b) if x and y]
    if not pairs:
        return None
    n = len(pairs)
    cats = sorted({c for p in pairs for c in p})
    po = sum(1 for x, y in pairs if x == y) / n
    pe = sum((sum(1 for x, _ in pairs if x == c) / n) * (sum(1 for _, y in pairs if y == c) / n) for c in cats)
    return 1.0 if pe == 1 else round((po - pe) / (1 - pe), 4)


def sus(row: dict) -> float | None:
    try:
        x = [int(row[f"sus_{i}"]) for i in range(1, 11)]
    except (KeyError, ValueError):
        return None
    return 2.5 * sum((v - 1) if i % 2 == 0 else (5 - v) for i, v in enumerate(x))


# ---------------------------------------------------------------- report
def analyse(responses: list[dict], participants: list[dict], key: dict) -> dict:
    scored = [score_row(r, key[r["task"]]) for r in responses if r["task"] in key and r["task"] != "practice"]
    pending = [(s["participant"], s["task"]) for s in scored if s["fixed"] is None]
    by_cond: dict[str, list[dict]] = defaultdict(list)
    for s in scored:
        by_cond[s["condition"]].append(s)
    per_condition = {}
    for c, rows in sorted(by_cond.items()):
        times = [r["time_s"] for r in rows if r["time_s"] is not None]
        per_condition[c] = {
            "n": len(rows),
            "found": round(sum(r["found"] for r in rows) / len(rows), 3),
            "located": round(sum(r["located"] for r in rows) / len(rows), 3),
            "fixed": round(statistics.mean(r["fixed"] for r in rows if r["fixed"] is not None), 3) if any(r["fixed"] is not None for r in rows) else None,
            "time_median_s": statistics.median(times) if times else None,
            "time_iqr_s": (statistics.quantiles(times, n=4)[2] - statistics.quantiles(times, n=4)[0]) if len(times) >= 2 else None,
            "confidence_median": statistics.median(r["confidence"] for r in rows if r["confidence"] is not None) if rows else None,
        }
    score = {(s["participant"], s["condition"]): s["score"] for s in scored if s["score"] is not None}
    people = sorted({p for p, _ in score})
    tests, raw_p = {}, {}
    for other in ("A", "B"):
        diffs = [score[(p, "C")] - score[(p, other)] for p in people if (p, "C") in score and (p, other) in score]
        tests[f"C_vs_{other}"] = {"pairs": len(diffs), "mean_diff": round(statistics.mean(diffs), 3) if diffs else None,
                                  "sign": sign_test(diffs), "wilcoxon": wilcoxon(diffs)}
        raw_p[f"C_vs_{other}"] = tests[f"C_vs_{other}"]["wilcoxon"]["p"]
    for k, p in holm(raw_p).items():
        tests[k]["wilcoxon"]["p_holm"] = p
    kappa = cohen_kappa([(r.get("fix_code_r1") or "").lower() for r in responses if r["task"] != "practice"],
                        [(r.get("fix_code_r2") or "").lower() for r in responses if r["task"] != "practice"])
    sus_scores = [v for v in (sus(p) for p in participants) if v is not None]
    return {"responses": len(scored), "participants": len(people), "pending_adjudication": pending,
            "per_condition": per_condition, "tests": tests, "fix_coder_kappa": kappa,
            "sus_C": {"n": len(sus_scores), "mean": round(statistics.mean(sus_scores), 1) if sus_scores else None}}


def markdown(r: dict) -> str:
    L = [f"# Study results ({r['participants']} participants, {r['responses']} scored tasks)", ""]
    if r["pending_adjudication"]:
        L += [f"**{len(r['pending_adjudication'])} fix answers need adjudication** (coders disagree or are missing).", ""]
    L += ["| Condition | n | Found | Located | Fixed | Median time (s) | Median confidence |", "|---|---|---|---|---|---|---|"]
    for c, v in r["per_condition"].items():
        fixed = "" if v["fixed"] is None else f"{v['fixed']:.2f}"
        L.append(f"| {c} | {v['n']} | {v['found']:.0%} | {v['located']:.0%} | {fixed} | {v['time_median_s']} | {v['confidence_median']} |")
    L += ["", "| Comparison | Pairs | Mean score difference | Sign test p | Wilcoxon z | p | p (Holm) |", "|---|---|---|---|---|---|---|"]
    for k, t in r["tests"].items():
        w = t["wilcoxon"]
        L.append(f"| {k.replace('_', ' ')} | {t['pairs']} | {t['mean_diff']} | {t['sign']['p']:.4f} | {w['z']} | {w['p']:.4f} | {w.get('p_holm', w['p']):.4f} |")
    L += ["", f"Fix coders: Cohen's kappa = {r['fix_coder_kappa']}. SUS for C: {r['sus_C']['mean']} (n = {r['sus_C']['n']})."]
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("responses")
    ap.add_argument("participants")
    ap.add_argument("--key", default=str(HERE / "answer-key.yaml"))
    ap.add_argument("--json")
    a = ap.parse_args()
    key = yaml.safe_load(Path(a.key).read_text())
    with open(a.responses, newline="") as f:
        responses = list(csv.DictReader(f))
    with open(a.participants, newline="") as f:
        participants = list(csv.DictReader(f))
    r = analyse(responses, participants, key)
    if a.json:
        Path(a.json).write_text(json.dumps(r, indent=1, sort_keys=True) + "\n")
    print(markdown(r))


if __name__ == "__main__":
    main()
