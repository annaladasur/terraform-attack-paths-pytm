"""Verified remediation: a model proposes a Terraform patch, deterministic code proves what it does.

For one attack path:

    patch bundle (the path's evidence + the source blocks it cites, comments masked)
      -> patch_author (LLM, no tools): one find/replace in one cited block
      -> edit policy (deterministic): confined to cited blocks, no new blocks, providers,
         provisioners, external data, file reads, comments/suppressions, classification or
         multiplicity changes
      -> apply to a temporary copy -> offline plan (plan cache, else Terraform, no credentials)
      -> the whole deterministic pipeline and pytm on the patched plan
      -> compare with the original: accepted only as a *proven* effect
         (the path is gone or downgraded, no new path, no resource removed, pytm not worse)

Up to MAX_ATTEMPTS, each rejection fed back to the model. Nothing is ever applied to
the repository: the output is a diff for a human. The model is a proposer; the
pipeline is the verifier; nobody here is an actuator.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..evidence.comments import detect
from ..graph.build import LEVEL_ORDER
from ..terraform.offline_plan import source_key, strip_comments
from ..util import digest, dump_json
from .bundle import path_bundle

MAX_ATTEMPTS = 3
RANK = {"high": 3, "medium": 2, "low": 1}
ACCEPTED = ("PROVEN_BREAK", "PROVEN_DOWNGRADE", "ROUTE_BROKEN")

# the edit policy: what a proposed replacement may never contain
FORBIDDEN = [
    ("new block", re.compile(r"(?m)^\s*(resource|data|provider|module|terraform|provisioner|locals|variable|output|"
                             r"backend|moved|import|removed|check)\b\s*(\"|\{)")),
    ("command execution", re.compile(r"local-exec|remote-exec|\bexternal\b", re.I)),
    ("file or path read", re.compile(r"\b(file|templatefile|filebase64|fileset|filemd5|filesha256|pathexpand)\s*\(|\$\{?\s*path\.")),
    ("scanner suppression", re.compile(r"\bnosec\b|tfsec:ignore|checkov:skip|trivy:ignore|kics-scan", re.I)),
    ("classification change", re.compile(r"classification", re.I)),
    ("resource multiplicity change", re.compile(r"\b(count|for_each)\s*=")),
    ("lifecycle change", re.compile(r"\b(lifecycle|prevent_destroy|ignore_changes|create_before_destroy)\b")),
]
MAX_REPLACE_CHARS = 600
MAX_CHANGED_LINES = 12


# --------------------------------------------------------------------------- bundle
def _mask(line: str) -> str:
    """The line without its comment, spacing kept (a `find` is copied from it verbatim)."""
    if detect(line):
        return "[withheld: instruction-like text]"
    in_str, i = False, 0
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            in_str = c != '"'
        elif c == '"':
            in_str = True
        elif c == "#" or line.startswith(("//", "/*"), i):
            return line[:i].rstrip()
        i += 1
    return line


def editable_blocks(res, path) -> list[dict]:
    """The source blocks the path's hop evidence cites: the only places a patch may touch."""
    recs = res.build.ledger.by_id()
    ids: set[str] = set()
    for h in path.hops:
        ids |= set(h.evidence)
        if h.edge in recs:
            ids |= set(recs[h.edge].refs)
    out = []
    for i in sorted(ids, key=lambda x: (x.split("-")[0], int(x.split("-")[1]))):
        r = recs.get(i)
        if r is None or r.kind not in ("TF", "NET", "IAM") or not (r.source or {}).get("file"):
            continue
        f = Path(res.cfg.tf_dir) / r.source["file"]
        if not f.exists():
            continue
        lines = f.read_text(encoding="utf-8").splitlines()
        s = int(r.source["start_line"])
        e = int(r.source.get("end_line") or s)
        out.append({"id": i, "file": r.source["file"], "start_line": s, "end_line": e,
                    "summary": r.summary if not detect(r.summary) else "[withheld]",
                    "lines": {str(n): _mask(lines[n - 1]) for n in range(s, min(e, len(lines)) + 1)}})
    return out


def candidate_resources(res, path) -> list[dict]:
    """Non-sensitive resources a path's grants also reach: what a narrowed grant may keep."""
    g = res.build.graph
    out = {}
    for h in path.hops:
        if h.type != "ALLOWS":
            continue
        for e in g.out_edges(h.src, ("ALLOWS",)):
            n = g.nodes[e.dst]
            if e.dst != path.target and LEVEL_ORDER.get(n.sensitivity.get("level", "unclassified"), 0) < 2 and not n.synthetic:
                out[e.dst] = {"address": e.dst, "type": n.type, "sensitivity": n.sensitivity.get("level"), "via": e.id}
    return [out[k] for k in sorted(out)]


def patch_bundle(res, path, remedies, attempts: list[dict]) -> dict:
    b = path_bundle(res, path, remedies)
    b["subject"]["task"] = "propose one Terraform edit that breaks or downgrades this path"
    b["editable_blocks"] = editable_blocks(res, path)
    b["candidate_resources"] = candidate_resources(res, path)
    b["previous_attempts"] = [{"n": a["n"], "patch": {k: a["patch"].get(k) for k in ("hop", "file", "find", "replace")},
                               "status": a["status"], "reasons": a["reasons"]} for a in attempts]
    b["edit_rules"] = [
        "Exactly one find/replace. `find` must appear exactly once in `file`, entirely inside one editable block, "
        "and `evidence_refs` must include that block's ID.",
        "Edit existing arguments only: no new resource/data/provider/module/provisioner blocks, no external data, "
        "no file reads, no comments or scanner suppressions, no classification tags, no count/for_each/lifecycle.",
        "Prefer the least invasive change that keeps the service working. The pipeline will re-plan and re-run the "
        "path engine and pytm on your patch; only a proven effect is accepted.",
        "If no further safe change exists, reply with hop 0 and empty strings.",
    ]
    b.pop("bundle_hash", None)
    b["bundle_hash"] = digest(b, 16)
    return b


# --------------------------------------------------------------------------- policy
def _has_comment(text: str) -> bool:
    """String-aware: ``"${aws_s3_bucket.x.arn}/*"`` is not a comment, ``# note`` is."""
    squash = lambda t: re.sub(r"\s+", "", t)  # noqa: E731
    return squash(strip_comments(text + "\n")) != squash(text)


def check_patch(patch: dict, bundle: dict, tf_dir: Path) -> list[str]:
    reasons: list[str] = []
    for k, t in (("hop", int), ("file", str), ("find", str), ("replace", str), ("evidence_refs", list)):
        if not isinstance(patch.get(k), t):
            return [f"schema: {k} missing or not {t.__name__}"]
    allowed = set(bundle["allowed_ids"])
    bad = [x for x in patch["evidence_refs"] if x not in allowed]
    if bad:
        reasons.append(f"cites evidence not in the bundle: {', '.join(bad)}")
    if not 1 <= patch["hop"] <= len(bundle["subject"]["hops"]):
        reasons.append(f"hop {patch['hop']} is not a hop of {bundle['subject']['id']}")
    blocks = [b for b in bundle["editable_blocks"] if b["file"] == patch["file"]]
    f = (Path(tf_dir) / patch["file"]).resolve()
    if not blocks or Path(tf_dir).resolve() not in f.parents or not f.exists():
        return reasons + [f"{patch['file']} is not a file the path's evidence cites"]
    text = f.read_text(encoding="utf-8")
    if not patch["find"].strip():
        return reasons + ["empty find"]
    if text.count(patch["find"]) != 1:
        return reasons + [f"find appears {text.count(patch['find'])} times in {patch['file']} (must be exactly once)"]
    start = text[: text.index(patch["find"])].count("\n") + 1
    end = start + patch["find"].count("\n")
    inside = [b for b in blocks if b["start_line"] <= start and end <= b["end_line"]]
    if not inside:
        reasons.append(f"lines {start}-{end} of {patch['file']} are outside every cited block")
    elif not any(b["id"] in patch["evidence_refs"] for b in inside):
        reasons.append(f"evidence_refs must cite the edited block ({', '.join(b['id'] for b in inside)})")
    if patch["replace"] == patch["find"]:
        reasons.append("replace is identical to find")
    for name, rx in FORBIDDEN:
        if rx.search(patch["replace"]) or (name == "classification change" and rx.search(patch["find"])):
            reasons.append(f"edit policy: {name}")
    if _has_comment(patch["replace"]):
        reasons.append("edit policy: comment in the replacement (comments are how suppressions and instructions travel)")
    if detect(patch["replace"]):
        reasons.append("edit policy: instruction-like text")
    if len(patch["replace"]) > MAX_REPLACE_CHARS:
        reasons.append(f"edit policy: replacement longer than {MAX_REPLACE_CHARS} characters")
    changed = sum(1 for d in difflib.ndiff(patch["find"].splitlines(), patch["replace"].splitlines()) if d[:1] in "+-")
    if changed > MAX_CHANGED_LINES:
        reasons.append(f"edit policy: changes {changed} lines (at most {MAX_CHANGED_LINES})")
    if not reasons:
        import hcl2

        try:
            hcl2.loads(text.replace(patch["find"], patch["replace"], 1))
        except Exception as e:  # noqa: BLE001 - any parse failure rejects the patch
            reasons.append(f"patched file does not parse: {str(e).splitlines()[0][:120]}")
    return reasons


# --------------------------------------------------------------------------- verification
def _copy_sources(src: Path, dst: Path) -> None:
    for f in sorted(Path(src).rglob("*.tf")):
        rel = f.relative_to(src)
        if any(p.startswith(".") for p in rel.parts):
            continue
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, dst / rel)


def _confirmed(res) -> set[tuple[str, str]] | None:
    cls = (res.pytm or {}).get("classification")
    if not cls:
        return None
    return {(r["threat_id"], re.sub(r" \(GRAPH-\d+\)$", "", r["element"])) for r in cls["findings"] if r["class"] == "confirmed"}


def diff_text(tf_dir: Path, patch: dict) -> str:
    before = (Path(tf_dir) / patch["file"]).read_text(encoding="utf-8")
    after = before.replace(patch["find"], patch["replace"], 1)
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        f"a/{patch['file']}", f"b/{patch['file']}"))


def verify_patch(res, path, patch: dict, work: Path, write_cache: bool = False) -> dict:
    """Apply to a copy, re-plan offline, re-run everything, compare. Never touches ``res.cfg.tf_dir``."""
    from ..pipeline import run_deterministic
    from ..terraform.offline_plan import plan_fixture

    src = work / "src"
    _copy_sources(Path(res.cfg.tf_dir), src)
    f = src / patch["file"]
    f.write_text(f.read_text(encoding="utf-8").replace(patch["find"], patch["replace"], 1), encoding="utf-8")
    out = {"diff": diff_text(Path(res.cfg.tf_dir), patch)}
    if source_key(src) == source_key(res.cfg.tf_dir):
        return {**out, "status": "REJECTED", "reasons": ["no effective change (formatting or comments only)"]}
    try:
        info = plan_fixture(src, work / "plan.json", use_cache=True, write_cache=write_cache)
    except RuntimeError as e:
        return {**out, "status": "UNVERIFIED", "reasons": [f"no plan for the patched sources: {str(e).splitlines()[0]}"]}
    out["plan_source"] = info["source"]
    after = run_deterministic(replace(res.cfg, tf_dir=src, plan_path=work / "plan.json", out_dir=work / "out",
                                      baselines_dir=None, ai=None, render_dfd=res.pytm.get("threat_count") is not None))
    out.update(compare(res, after, path))
    return out


RELATIONSHIPS = ("EXPOSES", "ROUTES_TO", "ASSUMES", "TRUSTS", "ESCALATES", "ALLOWS", "READS", "WRITES")


def _relationships(res) -> dict[tuple[str, str, str], set[str]]:
    g = getattr(res.build, "graph", None)
    if g is None:
        return {}
    return {(e.type, e.src, e.dst): set(e.data.get("access", []) or []) for e in g.edges_of(*RELATIONSHIPS)}


def _added_relationships(before, after) -> list[str]:
    """A remediation may only take capability away: no new grant, exposure, route or trust, no wider access."""
    b, a = _relationships(before), _relationships(after)
    out = [f"{t} {s} -> {d}" for (t, s, d) in sorted(a) if (t, s, d) not in b]
    out += [f"{t} {s} -> {d} gains {','.join(sorted(acc - b[(t, s, d)]))}" for (t, s, d), acc in sorted(a.items())
            if (t, s, d) in b and acc - b[(t, s, d)]]
    return out


def compare(before, after, path) -> dict:
    reasons: list[str] = []
    removed = sorted(set(before.build.plan.resources) - set(after.build.plan.resources))
    if removed:
        reasons.append(f"removes resources: {', '.join(removed)}")
    added = _added_relationships(before, after)
    if added:
        reasons.append("does not only narrow: adds " + "; ".join(added[:3]))
    bkeys = {tuple(p.nodes) for p in before.paths}
    new = [p for p in after.paths if tuple(p.nodes) not in bkeys]
    if new:
        reasons.append(f"introduces {len(new)} new path(s): " + "; ".join(" -> ".join(p.nodes) for p in new[:3]))
    same = next((p for p in after.paths if tuple(p.nodes) == tuple(path.nodes)), None)
    others = [p for p in after.paths if p.target == path.target and tuple(p.nodes) != tuple(path.nodes)]
    if same is None:
        effect, prio = ("breaks_path" if not others else "breaks_route"), None
    elif RANK[same.priority] < RANK[path.priority]:
        effect, prio = "downgrades_path", same.priority
    else:
        effect, prio = "no_effect", same.priority
        reasons.append(f"no effect on {path.id}: still {same.priority}")
    b, a = _confirmed(before), _confirmed(after)
    pytm = None
    if b is not None and a is not None:
        pytm = {"resolved": sorted(f"{t} on {e}" for t, e in b - a), "new": sorted(f"{t} on {e}" for t, e in a - b)}
        if pytm["new"]:
            reasons.append("pytm: new threats the plan decides: " + ", ".join(pytm["new"]))
    status = "REJECTED" if reasons else {"breaks_path": "PROVEN_BREAK", "downgrades_path": "PROVEN_DOWNGRADE",
                                         "breaks_route": "ROUTE_BROKEN"}[effect]
    return {"status": status, "reasons": reasons, "effect": effect, "priority_before": path.priority,
            "priority_after": prio, "preconditions_after": same.preconditions if same else [],
            "new_paths": [p.nodes for p in new], "other_paths_to_target": len(others),
            "resources_removed": removed, "pytm": pytm}


# --------------------------------------------------------------------------- loop
def _parse(text: str) -> dict | None:
    try:
        d = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return d if isinstance(d, dict) else None


def remediate_path(res, path, llm, max_attempts: int = MAX_ATTEMPTS, write_cache: bool = False) -> dict:
    from .agents import SCHEMAS, system_prompt, user_message

    attempts: list[dict] = []
    remedies = res.remedies
    predicted = {r.hop: r.effect for r in remedies if r.path == path.id}
    with tempfile.TemporaryDirectory(prefix="tapm-remediate-") as tmp:
        for n in range(1, max_attempts + 1):
            bundle = patch_bundle(res, path, remedies, attempts)
            r = llm.complete("patch_author", system_prompt("patch_author"), user_message(bundle), SCHEMAS["patch_author"],
                             {"bundle": bundle, "bundle_hash": bundle["bundle_hash"]})
            patch = _parse(r.text)
            row: dict[str, Any] = {
                "n": n,
                "backend": r.backend,
                "latency_ms": r.latency_ms,
                "input_tokens": r.input_tokens,
                "output_tokens": r.output_tokens,
                "cost_usd": r.cost_usd,
                "patch": patch or {"raw": (r.text or "")[:500]},
            }
            if patch is None:
                attempts.append({**row, "status": "REJECTED", "reasons": ["reply is not a JSON object"]})
                continue
            if patch.get("hop") == 0:
                attempts.append({**row, "status": "GAVE_UP", "reasons": [patch.get("rationale") or "no further safe change"]})
                break
            reasons = check_patch(patch, bundle, Path(res.cfg.tf_dir))
            if reasons:
                attempts.append({**row, "status": "REJECTED", "stage": "edit policy", "reasons": reasons})
                continue
            v = verify_patch(res, path, patch, Path(tmp) / f"attempt-{n}", write_cache=write_cache)
            row.update({"stage": "verification", **v})
            if patch["hop"] in predicted:
                row["what_if_predicted"] = predicted[patch["hop"]]
            attempts.append(row)
            if v["status"] == "PROVEN_BREAK":
                break
    best = next((a for s in ACCEPTED for a in attempts if a["status"] == s), None)
    return {"path": path.id, "priority": path.priority, "nodes": path.nodes, "attempts": attempts,
            "result": best["status"] if best else "NO_VERIFIED_FIX", "recommended_attempt": best["n"] if best else None,
            "recommended_diff": best["diff"] if best else None}


def run_remediation(res, cfg: dict, llm=None) -> dict:
    """Remediate the top ``max_paths`` paths; write remediations.json and one .diff per verified fix."""
    from .. import PROMPT_VERSION
    from .llm import SimulatedLLM, make_llm

    fallback = SimulatedLLM() if cfg.get("allow_fallback") else None
    llm = llm or make_llm(cfg.get("llm", "simulated"), cfg.get("model"), cfg.get("cassette_dir", "cassettes"),
                          record=cfg.get("record", False), prompt_version=PROMPT_VERSION,
                          fallback=fallback, num_ctx=cfg.get("num_ctx"), seed=cfg.get("seed"))
    max_p = cfg.get("max_paths")
    max_paths_slice = 3 if max_p is None else max_p
    results = [remediate_path(res, p, llm, cfg.get("max_attempts", MAX_ATTEMPTS), cfg.get("write_cache", False))
               for p in res.paths[:max_paths_slice]]
    out_dir = Path(res.cfg.out_dir)
    for f in out_dir.glob("remediation-PATH-*.diff"):
        f.unlink()
    for r in results:
        if r["recommended_diff"]:
            (out_dir / f"remediation-{r['path']}.diff").write_text(r["recommended_diff"], encoding="utf-8")
    summary = {"paths": len(results), "verified_break": sum(1 for r in results if r["result"] == "PROVEN_BREAK"),
               "verified_downgrade_only": sum(1 for r in results if r["result"] in ("PROVEN_DOWNGRADE", "ROUTE_BROKEN")),
               "no_verified_fix": sum(1 for r in results if r["result"] == "NO_VERIFIED_FIX"),
               "attempts": sum(len(r["attempts"]) for r in results),
               "rejected": sum(1 for r in results for a in r["attempts"] if a["status"] == "REJECTED"),
               "unverified": sum(1 for r in results for a in r["attempts"] if a["status"] == "UNVERIFIED")}
    doc = {"manifest": {"patch_author": llm.name, "max_attempts": cfg.get("max_attempts", MAX_ATTEMPTS),
                        "applied_to_repository": False,
                        "acceptance": "path gone or downgraded after re-planning; no new path; no resource removed; "
                                      "no new pytm threat decided by the plan"},
           "summary": summary, "paths": results}
    dump_json(doc, out_dir / "remediations.json")
    return doc
