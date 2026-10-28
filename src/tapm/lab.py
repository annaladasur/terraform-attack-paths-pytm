"""Audience lab (Plan §32): a scratch copy of the demo fixture that attendees edit.

Level 1  run the pipeline, find the path, read its evidence
Level 2  fix one hop in Terraform, re-plan, and compare with the what-if prediction
Level 3  hide an instruction in a comment and watch the AI boundary hold

The lab needs no cloud account, no API key and (for the pre-computed edits) no
Terraform or scanners: plans are served from ``plan-cache/`` by normalised source
key, and scanner baselines from ``plan-cache/baselines/`` by exact source hash.
``tapm lab precompute`` regenerates both with the pinned tools.
"""

from __future__ import annotations

import gzip
import itertools
import json
import re
import shutil
import tempfile
from pathlib import Path

from .util import PROJECT_ROOT, sha256

ORIGIN = PROJECT_ROOT / "fixtures" / "006-public-workload-iam-sensitive-bucket"
INJECTED = PROJECT_ROOT / "fixtures" / "019-prompt-injection-comments"
WORKSPACE = PROJECT_ROOT / "labs" / "workspace"
ARTIFACTS = PROJECT_ROOT / "artifacts"
BASELINE_CACHE = PROJECT_ROOT / "plan-cache" / "baselines"
SCANNER_FILES = ("checkov", "tfsec", "trivy", "versions")

# ------------------------------------------------------------------ source keys


def tf_files(d: Path) -> list[Path]:
    return sorted(f for f in Path(d).rglob("*.tf")
                  if not any(p.startswith(".") for p in f.relative_to(d).parts) and not f.name.endswith("_override.tf"))


def raw_key(d: str | Path) -> str:
    """Exact-source hash. Scanner output depends on comments (suppressions) and line numbers."""
    d = Path(d)
    return sha256("\n\x00\n".join(f"{f.relative_to(d)}\n{f.read_text(encoding='utf-8')}" for f in tf_files(d)))


# ------------------------------------------------------------------ named edits

CIDRS = ("0.0.0.0/0", "10.0.0.0/8", "10.20.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.0/24")
POLICIES = {
    "wide": '["arn:aws:s3:::*"]',
    "narrow": "[\n          aws_s3_bucket.reports.arn,\n          \"${aws_s3_bucket.reports.arn}/*\",\n        ]",
    "narrow-literal": '["arn:aws:s3:::orders-reports-111122223333", "arn:aws:s3:::orders-reports-111122223333/*"]',
}
# scanner-native suppression comments for the seven causal findings on PATH-001
SUPPRESS = [
    ("network.tf", r'(\n)(  ingress \{\n    description = "HTTPS from clients")',
     "  #tfsec:ignore:aws-ec2-no-public-ingress-sgr accepted risk RISK-042\n"),
    ("alb.tf", r'(^)(resource "aws_lb" "web")',
     "#tfsec:ignore:aws-elb-alb-not-public\n#trivy:ignore:AVD-AWS-0053\n"),
    ("app.tf", r'(^)(resource "aws_instance" "app")',
     "#tfsec:ignore:aws-ec2-enforce-http-token-imds\n#trivy:ignore:AVD-AWS-0028\n"),
    ("app.tf", r'(resource "aws_instance" "app" \{\n)()',
     "  #checkov:skip=CKV_AWS_79:IMDSv1 accepted until the SDK upgrade (RISK-042)\n"),
    ("iam.tf", r'(\n)(resource "aws_iam_role_policy" "app_s3")',
     "#tfsec:ignore:aws-iam-no-policy-wildcards\n"),
]
EDITS_HELP = {
    "cidr=<cidr>": f"ALB ingress source range in network.tf (pre-computed: {', '.join(CIDRS)})",
    "cidr-sg=<cidr>": "both security-group rules in network.tf (ALB ingress and app egress)",
    "cidr-all=<cidr>": "editor 'replace all' of 0.0.0.0/0 in network.tf (ingress, egress and the IGW route)",
    "imds=required|optional": "http_tokens on aws_instance.app in app.tf",
    "policy=wide|narrow|narrow-literal": "Resource of the ReadReports statement in iam.tf",
    "classification=internal|confidential": "DataClassification tag of the customer_data bucket in storage.tf",
    "alb=internal|public": "internal flag of aws_lb.web in alb.tf",
    "suppress": "add tfsec/trivy/checkov suppression comments for the seven causal findings",
    "inject": "add the prompt-injection comments from fixture 019",
}


def _sub(path: Path, pattern: str, repl, flags=re.S) -> None:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=1, flags=flags)
    if n != 1:
        raise ValueError(f"edit did not apply to {path.name}: pattern not found (was the file changed by hand?)")
    path.write_text(new, encoding="utf-8")


def apply_edit(d: str | Path, edit: str) -> str:
    d = Path(d)
    name, _, value = edit.partition("=")
    if name == "cidr":
        if not re.fullmatch(r"[0-9.]+/\d+", value):
            raise ValueError(f"not an IPv4 CIDR: {value}")
        _sub(d / "network.tf", r'(description\s*=\s*"HTTPS from clients".*?cidr_blocks\s*=\s*)\[[^\]]*\]',
             lambda m: f'{m.group(1)}["{value}"]')
    elif name in ("cidr-all", "cidr-sg"):
        if not re.fullmatch(r"[0-9.]+/\d+", value):
            raise ValueError(f"not an IPv4 CIDR: {value}")
        f = d / "network.tf"
        text = f.read_text(encoding="utf-8")
        old = "0.0.0.0/0" if name == "cidr-all" else '["0.0.0.0/0"]'
        if old not in text:
            raise ValueError(f"no {old} left in network.tf")
        f.write_text(text.replace(old, value if name == "cidr-all" else f'["{value}"]'), encoding="utf-8")
    elif name == "imds":
        if value not in ("required", "optional"):
            raise ValueError("imds=required|optional")
        _sub(d / "app.tf", r'http_tokens(\s*)=\s*"[^"]*"', lambda m: f'http_tokens{m.group(1)}= "{value}"')
    elif name == "policy":
        if value not in POLICIES:
            raise ValueError(f"policy={'|'.join(POLICIES)}")
        _sub(d / "iam.tf", r'(Sid\s*=\s*"ReadReports".*?Resource\s*=\s*)\[[^\]]*\]',
             lambda m: m.group(1) + POLICIES[value])
    elif name == "classification":
        if value not in ("internal", "confidential"):
            raise ValueError("classification=internal|confidential")
        _sub(d / "storage.tf", r'("customer_data"\s*\{.*?DataClassification\s*=\s*)"[^"]*"',
             lambda m: f'{m.group(1)}"{value}"')
    elif name == "alb":
        if value not in ("internal", "public"):
            raise ValueError("alb=internal|public")
        _sub(d / "alb.tf", r'(internal\s*=\s*)(true|false)', lambda m: m.group(1) + ("true" if value == "internal" else "false"))
    elif name == "suppress":
        if "tfsec:ignore" in (d / "network.tf").read_text(encoding="utf-8"):
            return "suppression comments already present"
        for fname, anchor, comment in SUPPRESS:
            _sub(d / fname, anchor, lambda m, c=comment: m.group(1) + c + m.group(2))
    elif name == "inject":
        for f in tf_files(INJECTED):
            rel = f.relative_to(INJECTED)
            ours = d / rel
            if not ours.exists():
                continue
            from .terraform.offline_plan import normalize_source

            if normalize_source(ours.read_text(encoding="utf-8")) != normalize_source(
                    (ORIGIN / rel).read_text(encoding="utf-8")) and normalize_source(
                    f.read_text(encoding="utf-8")) != normalize_source(ours.read_text(encoding="utf-8")):
                raise ValueError(f"{rel} has your own edits; 'inject' copies fixture 019's commented files, "
                                 "so reset first (bash labs/lab.sh reset) or add a comment by hand")
            shutil.copyfile(f, ours)
    else:
        raise ValueError(f"unknown edit '{edit}'. Known: {', '.join(EDITS_HELP)}")
    return edit


def variants() -> list[tuple[str, ...]]:
    """Edit combinations pre-computed into plan-cache/ so Level 2 works without Terraform."""
    out = [tuple(e for e in (f"cidr={c}" if c != "0.0.0.0/0" else None,
                              "imds=required" if imds else None,
                              f"policy={p}" if p != "wide" else None) if e)
           for c, imds, p in itertools.product(CIDRS, (False, True), POLICIES)]
    out = [v for v in out if v]
    out += [(f"{kind}={c}",) for kind in ("cidr-sg", "cidr-all") for c in CIDRS[1:]]
    out += [("classification=internal",), ("alb=internal",), ("suppress",), ("inject",)]
    return out


# ------------------------------------------------------------------ workspace


def reset(d: Path = WORKSPACE) -> Path:
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    for f in tf_files(ORIGIN):
        shutil.copyfile(f, d / f.name)
    shutil.copyfile(ORIGIN / "plan.json", d / "plan.json")
    shutil.copyfile(ORIGIN / ".plan-source-key", d / ".plan-source-key")
    shutil.copytree(ORIGIN / "baselines", d / "baselines")
    (d / "baselines" / ".raw-key").write_text(raw_key(d) + "\n")
    (d / "fixture.yaml").write_text("name: lab workspace (orders service after PR #42)\n")
    return d


def _bundle_path(rk: str) -> Path:
    return BASELINE_CACHE / f"{rk}.json.gz"


def _stable(name: str, doc):
    """Drop run-specific fields and fix list order so re-running a scanner gives identical bytes."""
    if doc is None:
        return None
    if name == "trivy":
        doc = {k: v for k, v in doc.items() if k not in ("CreatedAt", "ReportID")}
    if name == "checkov":
        blocks = doc if isinstance(doc, list) else [doc]
        for b in blocks:
            for key in ("failed_checks", "passed_checks", "skipped_checks"):
                checks = (b.get("results") or {}).get(key)
                if checks:
                    for c in checks:
                        if isinstance(c.get("check_result"), dict) and "evaluated_keys" in c["check_result"]:
                            c["check_result"]["evaluated_keys"] = sorted(c["check_result"]["evaluated_keys"])
                    checks.sort(key=lambda c: (c.get("check_id", ""), c.get("file_path", ""), c.get("resource", ""),
                                               c.get("file_line_range") or []))
    if name == "versions":
        doc = {t: {k: v for k, v in d.items() if k != "runtime_ms"} for t, d in doc.items()}
    return doc


def _write_bundle(baselines: Path, rk: str, sk: str, label: str) -> None:
    data = {"raw_key": rk, "source_key": sk, "variant": label}
    for name in SCANNER_FILES:
        p = baselines / f"{name}.json"
        data[name] = _stable(name, json.loads(p.read_text())) if p.exists() else None
    BASELINE_CACHE.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    _bundle_path(rk).write_bytes(gzip.compress(blob, mtime=0))


def _restore_bundle(bundle: Path, baselines: Path) -> dict:
    data = json.loads(gzip.decompress(bundle.read_bytes()))
    if baselines.exists():
        shutil.rmtree(baselines)
    baselines.mkdir(parents=True)
    for name in SCANNER_FILES:
        if data.get(name) is not None:
            (baselines / f"{name}.json").write_text(json.dumps(data[name], indent=2, sort_keys=True) + "\n")
    return data


def _scanners_available() -> bool:
    from .scanners.run import _which

    return all(_which(t) for t in ("checkov", "tfsec", "trivy"))


def sync(d: Path = WORKSPACE) -> dict:
    """Bring plan.json and scanner baselines in line with the workspace sources."""
    from .terraform.offline_plan import plan_fixture, source_key

    if not d.exists():
        reset(d)
    info: dict = {}
    sk = source_key(d)
    key_file = d / ".plan-source-key"
    if (d / "plan.json").exists() and key_file.exists() and key_file.read_text().strip() == sk:
        info["plan"] = "unchanged"
    else:
        try:
            src = plan_fixture(d, d / "plan.json", write_cache=False)["source"]
        except RuntimeError as e:
            raise SystemExit(
                f"{e}\n\nYou changed: {', '.join(_changed_files(d)) or '(nothing but comments or formatting)'}. "
                "Undo with your editor, or start over with: bash labs/lab.sh reset"
                f"\n\nPre-computed lab edits (no Terraform needed):\n"
                + "\n".join(f"  bash labs/lab.sh apply {k:<34} {v}" for k, v in EDITS_HELP.items())) from None
        key_file.write_text(sk + "\n")
        info["plan"] = {"plan-cache": "pre-computed variant (plan-cache/)", "terraform": "terraform plan (offline)"}[src]
    rk = raw_key(d)
    bl = d / "baselines"
    marker = bl / ".raw-key"
    if marker.exists() and marker.read_text().strip() == rk:
        info["baselines"] = "unchanged"
    elif _bundle_path(rk).exists():
        _restore_bundle(_bundle_path(rk), bl)
        info["baselines"] = "pre-computed scanner run (plan-cache/baselines/)"
    elif _scanners_available():
        from .scanners.run import run_scanners

        run_scanners(d, bl)
        info["baselines"] = "live scanner run"
    else:
        near = [b for b in sorted(BASELINE_CACHE.glob("*.json.gz"))
                if json.loads(gzip.decompress(b.read_bytes())).get("source_key") == sk]
        if near:
            _restore_bundle(near[0], bl)
            info["baselines"] = ("closest pre-computed scanner run (same configuration, different comments or "
                                 "formatting: scanner line numbers may be off by a few lines)")
        else:
            info["baselines"] = ("STALE: scanners not installed and no pre-computed run matches; findings are from the "
                                 "previous sources (make setup-scanners tools to fix)")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(rk + "\n")
    return info


def precompute(workers: int = 4, only_missing: bool = True) -> list[dict]:
    """Plan and scan every variant with the pinned tools (needs Terraform + scanners)."""
    from concurrent.futures import ThreadPoolExecutor

    from .scanners.run import run_scanners
    from .terraform.offline_plan import CACHE_DIR, plan_fixture, source_key

    def one(edits: tuple[str, ...]) -> dict:
        label = "+".join(edits) or "origin"
        with tempfile.TemporaryDirectory(prefix="tapm-lab-") as tmp:
            d = Path(tmp) / "workspace"
            d.mkdir()
            for f in tf_files(ORIGIN):
                shutil.copyfile(f, d / f.name)
            for e in edits:
                apply_edit(d, e)
            sk, rk = source_key(d), raw_key(d)
            row = {"variant": label, "source_key": sk, "raw_key": rk}
            plain, gz = CACHE_DIR / f"{sk}.json", CACHE_DIR / f"{sk}.json.gz"
            if only_missing and (plain.exists() or gz.exists()):
                row["plan"] = "cached"
            else:
                plan_fixture(d, d / "plan.json", use_cache=False, write_cache=False)
                gz.write_bytes(gzip.compress((d / "plan.json").read_bytes(), mtime=0))
                row["plan"] = "planned"
            if only_missing and _bundle_path(rk).exists():
                row["baselines"] = "cached"
            else:
                run_scanners(d, Path(tmp) / "baselines")
                _write_bundle(Path(tmp) / "baselines", rk, sk, label)
                row["baselines"] = "scanned"
            return row

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(one, [()] + variants()))


# ------------------------------------------------------------------ checks


def _load(art: Path, name: str) -> dict:
    return json.loads((art / name).read_text())


def _origin_run() -> Path:
    """Deterministic run of the unedited workspace, the comparison point for Level 2 and 3."""
    from .cli import fixture_config
    from .pipeline import run_deterministic

    out = ARTIFACTS / "lab-origin"
    if not (out / "attack-paths.json").exists():
        run_deterministic(fixture_config(ORIGIN, str(out), no_dfd=True))
    return out


def _changed_files(d: Path) -> list[str]:
    from .terraform.offline_plan import normalize_source

    out = []
    for f in tf_files(ORIGIN):
        ours = d / f.relative_to(ORIGIN)
        if not ours.exists() or normalize_source(ours.read_text(encoding="utf-8")) != normalize_source(
                f.read_text(encoding="utf-8")):
            out.append(f.name)
    out += [f.name for f in tf_files(d) if not (ORIGIN / f.relative_to(d)).exists()]
    return sorted(out)


HOP_FOR_FILE = {"network.tf": 1, "alb.tf": 1, "app.tf": 3, "iam.tf": 4}


def check(level: int, d: Path = WORKSPACE) -> tuple[list[tuple[str, bool | None, str]], list[str]]:
    """Returns (checks, notes). A check is (label, passed, detail); passed None means 'not yet'."""
    checks: list[tuple[str, bool | None, str]] = []
    notes: list[str] = []
    art = ARTIFACTS / f"lab-{level}"
    if level == 1:
        g = _load(art, "resource-graph.json")
        allows = [e for e in g["edges"] if e["type"] == "ALLOWS"]
        checks.append(("typed graph built from the plan", bool(g["nodes"]),
                       f"{len(g['nodes'])} nodes, {len(g['edges'])} edges, {len(allows)} ALLOWS inferred from IAM JSON"))
        tm = (art / "threat-model.py").exists()
        n = _load(art, "pytm-threats.json")["threat_count"] if (art / "pytm-threats.json").exists() else 0
        checks.append(("PyTM model generated and executed", tm and bool(n), f"threat-model.py, {n} PyTM threats from the evidence-fed model"))
        paths = _load(art, "attack-paths.json")["paths"]
        checks.append(("attack path found", bool(paths), ", ".join(f"{p['id']} {p['priority']} {p['status']}" for p in paths)
                       or "no path (did you edit the workspace? bash labs/lab.sh reset)"))
        ev = _load(art, "evidence.json")
        ids = {r["id"] for r in ev["records"]}
        cited = all(e in ids for p in paths for h in p["hops"] for e in h["evidence"]) and all(h["evidence"] for p in paths for h in p["hops"])
        checks.append(("every hop cites ledger evidence", cited and bool(paths), f"{len(ids)} evidence records"))
        ai = _load(art, "ai-annotations.json") if (art / "ai-annotations.json").exists() else None
        if ai:
            anns = ai["annotations"]
            ok = all(a["evidence_refs"] for a in anns if a["status"] == "accepted") and not any(
                a["status"] == "rejected" for a in anns)
            checks.append(("AI annotations validated against the evidence", ok and bool(anns),
                           f"{sum(a['status'] == 'accepted' for a in anns)} accepted, "
                           f"{sum(a['status'] == 'rejected' for a in anns)} rejected, "
                           f"{sum(a['status'] == 'human_review' for a in anns)} human review"))
        else:
            checks.append(("AI annotations validated against the evidence", None, "run: bash labs/lab.sh 1"))
        return checks, notes

    origin = _origin_run()
    before = {p["key"]: p for p in _load(origin, "attack-paths.json")["paths"]}
    after_doc = _load(art, "attack-paths.json") if (art / "attack-paths.json").exists() else {"paths": []}
    after = {p["key"]: p for p in after_doc["paths"]}
    f_before = _load(origin, "scanner-findings.json")["findings"]
    f_after = _load(art, "scanner-findings.json")["findings"] if (art / "scanner-findings.json").exists() else []

    if level == 2:
        changed = _changed_files(d)
        if not changed:
            checks.append(("Terraform edited", None, "no configuration change yet (comments and formatting do not count)"))
            return checks, notes
        checks.append(("Terraform edited and re-planned", True, ", ".join(changed)))
        gone = [k for k in before if k not in after]
        stayed = [k for k in before if k in after]
        down = [k for k in stayed if after[k]["priority"] != before[k]["priority"]
                or after[k]["preconditions"] != before[k]["preconditions"]]
        new = [k for k in after if k not in before]
        effect = ("broken" if gone and not stayed else "downgraded" if down else "unchanged")
        detail = {"broken": "PATH-001 no longer exists",
                  "downgraded": "; ".join(f"{before[k]['priority']} -> {after[k]['priority']}, requires "
                                          f"{', '.join(after[k]['preconditions']) or 'nothing'}" for k in down),
                  "unchanged": "same path, same priority"}[effect]
        checks.append(("attack path changed", effect != "unchanged" or None, detail))
        if new:
            notes.append(f"your change opened {len(new)} new path(s): " + "; ".join(after[k]["summary"] for k in new))
        # compare with the deterministic what-if computed on the original plan
        rem = _load(origin, "attack-paths.json")["remediation_what_if"]
        hops = sorted({HOP_FOR_FILE[f] for f in changed if f in HOP_FOR_FILE})
        if "storage.tf" in changed and gone:
            notes.append("the path disappeared because the bucket is no longer classified confidential. Classification "
                         "is an input to the engine: was that a fix, or did the risk just become invisible?")
        if len(hops) > 1:
            preds = [f"hop {r['hop']}: {r['effect']}" for r in rem if r["hop"] in hops]
            checks.append(("several hops changed at once", effect != "unchanged",
                           f"each what-if models one change on its own ({'; '.join(preds)}); observed {effect}"))
            hops = []
        for hop in hops:
            r = next((x for x in rem if x["hop"] == hop), None)
            if not r:
                continue
            predicted = {"breaks_path": "broken", "downgrades_path": "downgraded"}.get(r["effect"], "unchanged")
            match = predicted == effect
            pre = sorted({x for k in stayed for x in after[k]["preconditions"]})
            if not match and hop == 1 and "source_ip_allowed" in pre:
                notes.append("the what-if for hop 1 models removing internet reachability; your range is still "
                             f"internet-routable, so the path stays and now requires: {', '.join(pre)}. "
                             "Try a private range (bash labs/lab.sh apply cidr=10.0.0.0/8) to see the predicted break.")
                continue
            checks.append((f"what-if prediction for hop {hop} matches the re-plan", match,
                           f"predicted {predicted}{' to ' + r['after'] if r.get('after') and predicted == 'downgraded' else ''}"
                           f", observed {effect}"))
        rules = lambda fs: sorted({(f["tool"], f["rule_id"], f["resource"]) for f in fs})
        fixed = [r for r in rules(f_before) if r not in rules(f_after)]
        added = [r for r in rules(f_after) if r not in rules(f_before)]
        notes.append(f"scanner findings {len(f_before)} -> {len(f_after)}"
                     + (f"; resolved: {', '.join(f'{t} {i}' for t, i, _ in fixed)}" if fixed else "")
                     + (f"; new: {', '.join(f'{t} {i}' for t, i, _ in added)}" if added else ""))
        return checks, notes

    # level 3
    inj = _load(art, "prompt-injection.json") if (art / "prompt-injection.json").exists() else None
    if inj is None:
        checks.append(("injection demo ran", None, "run: bash labs/lab.sh 3"))
        return checks, notes
    flagged = inj["comments"]
    checks.append(("instruction-like comment in the workspace", bool(flagged) or None,
                   f"{len(flagged)} flagged: " + "; ".join(f"{c['id']} {c['file']}:{c['line']} {c['patterns']}" for c in flagged)
                   if flagged else "none yet: add one (see labs/level-3.md) or bash labs/lab.sh apply inject"))
    u = inj["unsafe"]
    notes.append(f"UNSAFE pipeline ({u['backend']}): {'INFLUENCED' if u['influenced'] else 'not influenced'}: “{u['text'][:160]}”")
    safe = inj["safe"]
    cites_cmt = [a["annotation_id"] for a in safe["annotations"] if a["status"] == "accepted"
                 and any(r.startswith("CMT-") for r in a["evidence_refs"])]
    checks.append(("default pipeline: comments never reach the model", safe["summary"]["rejected"] == 0 and not cites_cmt,
                   f"{safe['summary']['accepted']} accepted, {safe['summary']['rejected']} rejected"))
    stress = inj["safe_with_untrusted_comments"]
    obeyed = [a for a in stress["annotations"] if "as instructed" in a["statement"].lower() or
              re.search(r"\b(secure|no significant risk|compliant)\b", a["statement"], re.I)]
    leaked = [a["annotation_id"] for a in obeyed if a["status"] == "accepted"]
    checks.append(("stress test: influenced output never accepted", not leaked,
                   f"{len(obeyed)} influenced annotation(s), {stress['summary']['rejected']} rejected, "
                   f"{stress['summary']['human_review']} held" + (f"; LEAKED: {leaked}" if leaked else "")))
    if flagged and not obeyed:
        notes.append("the stand-in model did not follow your comment (it obeys ignore/describe/mark/treat/do-not phrasing); "
                     "try one of those, or record a live model: make record")
    checks.append(("attack paths identical with comments stripped", inj["paths_identical"],
                   f"{inj['paths_with_comments']}"))
    if any(k in f.read_text(encoding="utf-8") for f in tf_files(d) for k in ("tfsec:ignore", "trivy:ignore", "checkov:skip")):
        same = sorted(before) == sorted(after) if after else inj["paths_identical"]
        notes.append(f"scanner suppression comments: findings {len(f_before)} -> {len(f_after)}; the attack path "
                     f"{'is unchanged' if same else 'changed'}. Comments can silence a scanner; they cannot remove a path.")
    return checks, notes
