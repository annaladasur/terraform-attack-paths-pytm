"""Write paper/numbers.tex from the committed results, so no number in the paper is typed by hand.

    python paper/make_numbers.py          # after `make benchmark`, `tapm tier2`, `python -m tapm.eval.terrara`, `make snapshot`

Every macro is \\Num<Name>. A missing input yields "\\textbf{??}" and a warning, never a guess.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "evaluations" / "results"
SNAP = ROOT / "conference-snapshot"
MISSING: list[str] = []


def load(p: Path) -> dict:
    if not p.exists():
        MISSING.append(str(p.relative_to(ROOT)))
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def get(d: dict, path: str):
    cur = d
    for k in path.split("."):
        if not isinstance(cur, dict) or k not in cur:
            MISSING.append(path)
            return None
        cur = cur[k]
    return cur


def pct(x) -> str | None:
    return None if x is None else f"{100 * x:.1f}\\%"


def main() -> None:
    t1 = load(RES / "metrics.json")
    t2 = load(RES / "tier2.json")
    tb = load(RES / "terrara.json")
    tb0 = load(RES / "terrara-first-run.json")
    q = load(SNAP / "questions.json")
    cls = load(SNAP / "pytm-findings.json")
    ai = load(SNAP / "ai-annotations.json")

    pack = json.loads((ROOT / "src" / "tapm" / "pytm_gen" / "cloud_threats.json").read_text(encoding="utf-8"))
    s = lambda p: get(t1, "summary." + p)  # noqa: E731
    n: dict[str, object] = {
        # Tier 1: synthetic fixtures
        "TOneFixtures": s("fixtures"),
        "TOnePathTP": s("paths.tp"), "TOnePathFP": s("paths.fp"), "TOnePathFN": s("paths.fn"),
        "TOnePathPrecision": pct(s("path_precision")), "TOnePathRecall": pct(s("path_recall")),
        "TOneMedianMs": s("median_runtime_ms"), "TOnePNinetyFiveMs": s("p95_runtime_ms"),
        "TOneCheckov": s("scanner_findings.checkov"), "TOneTfsec": s("scanner_findings.tfsec"), "TOneTrivy": s("scanner_findings.trivy"),
        "TOneHopCheckov": pct(s("scanner_hop_coverage_on_gold_paths.checkov")),
        "TOneHopTfsec": pct(s("scanner_hop_coverage_on_gold_paths.tfsec")),
        "TOneHopTrivy": pct(s("scanner_hop_coverage_on_gold_paths.trivy")),
        "TOnePytmOnly": s("pytm_only.threats"),
        "TOnePytmFed": s("pytm_evidence.threats"),
        "TOnePytmDecided": (s("pytm_evidence.confirmed") or 0) + (s("pytm_evidence.mitigated") or 0) if s("pytm_evidence.confirmed") is not None else None,
        "TOnePytmAppTeam": s("pytm_evidence.needs_app_team"), "TOnePytmRuledOut": s("pytm_evidence.ruled_out"),
        "TOnePackFindings": s("pytm_evidence.pack"), "PackThreats": len(pack),
        "TOneAIGenerated": s("ai.generated"), "TOneAIAccepted": s("ai.accepted"), "TOneAIHeld": s("ai.human_review"),
        "TOneRemPaths": s("remediation.paths"), "TOneRemBreak": s("remediation.break"), "TOneRemRejected": s("remediation.rejected"),
        "TOneRemWhatIfAgree": s("remediation.whatif_agree"), "TOneRemWhatIfChecked": s("remediation.whatif_checked"),
        # Tier 2: public repositories
        "TTwoCases": get(t2, "summary.cases"), "TTwoTP": get(t2, "summary.tp"), "TTwoFN": get(t2, "summary.fn"),
        "TTwoFP": get(t2, "summary.fp"), "TTwoTN": get(t2, "summary.tn"),
        "TTwoPrecision": pct(get(t2, "summary.reachability_precision")), "TTwoRecall": pct(get(t2, "summary.reachability_recall")),
        # TerrARA benchmark
        "TBVulns": get(tb, "summary.known_vulns"), "TBSamples": get(tb, "summary.samples"),
        "TBScoredSamples": get(tb, "summary.scored_samples"),
        "TBTerraraThreatsAll": get(tb, "summary.terrara.threats_all"), "TBTerraraThreats": get(tb, "summary.terrara.threats_scored"),
        "TBTerraraCovered": get(tb, "summary.terrara.covered_scored"),
        "TBTerraraPerVuln": get(tb, "summary.terrara.threats_per_covered_vuln"),
        "TBPath": get(tb, "summary.ours.by.path"), "TBAsked": get(tb, "summary.ours.by.asked"),
        "TBConfirmed": get(tb, "summary.ours.by.confirmed"), "TBNone": get(tb, "summary.ours.by.none"),
        "TBStrict": get(tb, "summary.ours.covered_strict"), "TBDeveloper": get(tb, "summary.ours.covered_developer"),
        "TBFirstScreen": get(tb, "summary.ours.covered_first_screen"),
        "TBItems": get(tb, "summary.ours.items_full"), "TBItemsFirst": get(tb, "summary.ours.items_first_screen"),
        "TBItemsPerVuln": get(tb, "summary.ours.items_per_covered_vuln"),
        "TBScannerFindings": get(tb, "summary.ours.scanner_findings_scored"),
        "TBFirstRunCovered": get(tb0, "summary.ours.covered_developer"),
        "TBFirstRunPaths": sum(x.get("paths", 0) for x in tb0.get("samples", [])) if tb0 else None,
        # the demo plan (fixture 006)
        "DemoOpen": get(q, "open"),
        "DemoSixSettle": (q.get("questions") or [{}])[:6][-1].get("cumulative") if q.get("questions") else None,
        "DemoQuestions": len(q.get("questions", [])) if q else None,
        "DemoGeneric": get(cls, "summary.generic"), "DemoPublished": get(cls, "summary.published"),
        "DemoConfirmed": get(cls, "summary.confirmed"), "DemoRuledOut": get(cls, "summary.ruled_out"),
        "DemoAIGenerated": get(ai, "summary.generated"), "DemoAIAccepted": get(ai, "summary.accepted"),
    }
    lines = ["% Generated by paper/make_numbers.py from evaluations/results and conference-snapshot. Do not edit."]
    for k, v in n.items():
        val = "\\textbf{??}" if v is None else str(v)
        lines.append(f"\\newcommand{{\\Num{k}}}{{{val}\\xspace}}")
    (Path(__file__).parent / "numbers.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if MISSING:
        print("missing (rendered as ??):", ", ".join(sorted(set(MISSING))), file=sys.stderr)
    print(f"wrote paper/numbers.tex ({len(n)} numbers)")


if __name__ == "__main__":
    main()
