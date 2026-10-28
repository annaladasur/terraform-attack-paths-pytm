"""End-to-end pipeline: Terraform plan -> graph -> IAM -> PyTM -> paths -> evidence -> (AI) -> report.

Stages 1-6 are deterministic and write byte-stable artifacts. Stage 7 (AI) is
optional, reads only the evidence bundle, and its output is admitted to the
report only through the validator.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import PROMPT_VERSION, SCHEMA_VERSION, SCOPE_STATEMENT, __version__
from .evidence.comments import register_comments
from .graph.build import BuildOptions, BuildResult, build_graph
from .paths.engine import AttackPath, PathOptions, find_paths, register_paths
from .paths.whatif import what_if
from .pytm_gen.classify import link_paths
from .pytm_gen.generator import PYTM_VERSION, generate, model_facts, threat_library, with_open_questions
from .pytm_gen.questions import ANSWERS_FILE, answer_status, load_answers, register_answers, select_questions
from .pytm_gen.runner import run_model
from .scanners.normalize import Finding, attach, join_paths, load_findings
from .terraform.plan import parse_plan
from .terraform.sanitize import sanitize_plan
from .util import dump_json, sha256, write_text


@dataclass
class RunConfig:
    tf_dir: Path
    plan_path: Path
    out_dir: Path
    name: str
    baselines_dir: Path | None = None
    heuristic_sensitivity: bool = False
    user_entries: bool = False
    render_dfd: bool = True
    ai: dict | None = None  # see tapm.ai.harness.AiConfig
    remediate: dict | None = None  # see tapm.ai.remediate.run_remediation (patch author backend, attempts)
    answers_file: Path | None = None  # default: <tf_dir>/threat-answers.yaml (see pytm_gen/questions.py)
    extra_targets: tuple[str, ...] = ()
    sarif_uri_prefix: str = ""  # path of tf_dir relative to the repository root, for code-scanning locations


@dataclass
class RunResult:
    cfg: RunConfig
    build: BuildResult
    paths: list[AttackPath]
    findings: list[Finding]
    comments: list[dict]
    remedies: list
    pytm: dict
    hashes: dict[str, str] = field(default_factory=dict)
    timings_ms: dict[str, int] = field(default_factory=dict)
    ai: dict | None = None
    remediation: dict | None = None


def run_deterministic(cfg: RunConfig) -> RunResult:
    t: dict[str, int] = {}
    clock = time.monotonic()

    def lap(name: str) -> None:
        nonlocal clock
        now = time.monotonic()
        t[name] = int((now - clock) * 1000)
        clock = now

    raw_text = Path(cfg.plan_path).read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw.pop("timestamp", None)
    plan = parse_plan(raw, str(cfg.plan_path))
    lap("parse_plan")
    result = build_graph(plan, cfg.tf_dir, BuildOptions(heuristic_sensitivity=cfg.heuristic_sensitivity))
    lap("graph_iam")
    popts = PathOptions(user_entries=cfg.user_entries, extra_targets=tuple(cfg.extra_targets))
    paths = find_paths(result, popts)
    lap("paths")
    findings: list[Finding] = []
    if cfg.baselines_dir and Path(cfg.baselines_dir).exists():
        findings = load_findings(cfg.baselines_dir)
        attach(result, findings)
        join_paths(result, findings, paths)
    lap("scanner_join")
    register_paths(result, paths)
    comments = register_comments(result)
    remedies = what_if(result, paths, popts)
    lap("whatif")

    out = Path(cfg.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    h: dict[str, str] = {}
    h["terraform-plan.json"] = dump_json(sanitize_plan(raw), out / "terraform-plan.json")
    h["resource-graph.json"] = dump_json({"schema_version": SCHEMA_VERSION, **result.graph.to_json(),
                                          "notes": sorted(result.notes, key=lambda n: (n["resource"], n["note"])),
                                          "unresolved_policies": result.unresolved_policies}, out / "resource-graph.json")
    iam_edges = [e.to_json() for e in result.graph.edges_of("ALLOWS", "TRUSTS", "ASSUMES", "ESCALATES", "ATTACHES")]
    iam_recs = [r for r in result.ledger.to_json()["records"] if r["kind"] == "IAM"]
    h["iam-relationships.json"] = dump_json({"schema_version": SCHEMA_VERSION, "edges": iam_edges, "statements": iam_recs,
                                             "scope": SCOPE_STATEMENT},
                                            out / "iam-relationships.json")
    answers = load_answers(cfg.answers_file or Path(cfg.tf_dir) / ANSWERS_FILE)
    answer_facts = register_answers(result, answers)
    model_src = generate(result, cfg.name, sha256(raw_text), paths, answer_facts)
    h["threat-model.py"] = write_text(out / "threat-model.py", model_src)
    controls = model_facts(result, answer_facts)
    h["pytm-controls.json"] = dump_json(controls, out / "pytm-controls.json")
    h["threat-library.json"] = dump_json(threat_library(), out / "threat-library.json")
    lap("pytm_generate")
    pytm_res = {"threat_count": None}
    if cfg.render_dfd:
        pytm_res = run_model(out / "threat-model.py", out)
        h["pytm-threats.json"] = dump_json({"threat_count": pytm_res["threat_count"], "threats": pytm_res["threats"]},
                                           out / "pytm-threats.json")
        h["dfd.dot"] = sha256((out / "dfd.dot").read_text(encoding="utf-8"))
        h["seq.puml"] = sha256((out / "seq.puml").read_text(encoding="utf-8"))
        for kind in ("overview", "risk"):
            if (out / f"dfd-{kind}.dot").exists():
                h[f"dfd-{kind}.dot"] = sha256((out / f"dfd-{kind}.dot").read_text(encoding="utf-8"))
        if "classification" in pytm_res:
            link_paths(pytm_res["classification"], paths)
            h["pytm-findings.json"] = dump_json(pytm_res["classification"], out / "pytm-findings.json")
            pytm_res["questions"] = select_questions(pytm_res["classification"])
            pytm_res["questions"]["answers"] = answer_status(answers, answer_facts, controls)
            h["questions.json"] = dump_json(pytm_res["questions"], out / "questions.json")
            model_src = with_open_questions(model_src, pytm_res["questions"])  # comments only; pytm already ran
            h["threat-model.py"] = write_text(out / "threat-model.py", model_src)
    lap("pytm_run")
    h["attack-paths.json"] = dump_json({"schema_version": SCHEMA_VERSION,
                                        "definition": "docs/methodology.md#attack-path",
                                        "scope": SCOPE_STATEMENT,
                                        "paths": [p.to_json() for p in paths],
                                        "remediation_what_if": [r.to_json() for r in remedies]}, out / "attack-paths.json")
    h["scanner-findings.json"] = dump_json({"findings": [f.to_json() for f in findings]}, out / "scanner-findings.json")
    if cfg.baselines_dir:
        for tool in ("checkov", "tfsec", "trivy"):
            p = Path(cfg.baselines_dir) / f"{tool}.json"
            if p.exists():
                shutil.copyfile(p, out / f"baseline-{tool}.json")
    h["evidence.json"] = dump_json({"schema_version": SCHEMA_VERSION, **result.ledger.to_json()}, out / "evidence.json")
    lap("write")
    return RunResult(cfg, result, paths, findings, comments, remedies, pytm_res, h, t)


def run(cfg: RunConfig) -> RunResult:
    from .report.markdown import render_report

    res = run_deterministic(cfg)
    if cfg.ai:
        from .ai.harness import run_ai

        t0 = time.monotonic()
        res.ai = run_ai(res, cfg.ai)
        res.timings_ms["ai"] = int((time.monotonic() - t0) * 1000)
    if cfg.remediate:
        from .ai.remediate import run_remediation

        t0 = time.monotonic()
        res.remediation = run_remediation(res, cfg.remediate)
        res.timings_ms["remediation"] = int((time.monotonic() - t0) * 1000)
    report = render_report(res)
    res.hashes["report.md"] = write_text(Path(cfg.out_dir) / "report.md", report)
    from .report.story import render_stories

    write_text(Path(cfg.out_dir) / "story.md", render_stories(res, "everyone"))
    from .report.appsec import render_appsec_report

    write_text(Path(cfg.out_dir) / "report-appsec.md", render_appsec_report(res))
    from .report.executive import render_executive_report

    write_text(Path(cfg.out_dir) / "report-executive.md", render_executive_report(res))
    from .report.sarif import to_sarif

    dump_json(to_sarif(res, cfg.sarif_uri_prefix), Path(cfg.out_dir) / "attack-paths.sarif")
    manifest = run_manifest(res)
    dump_json(manifest, Path(cfg.out_dir) / "run-manifest.json")
    return res


def run_manifest(res: RunResult) -> dict:
    from .scanners.run import PINNED

    versions = {}
    if res.cfg.baselines_dir and (Path(res.cfg.baselines_dir) / "versions.json").exists():
        versions = json.loads((Path(res.cfg.baselines_dir) / "versions.json").read_text())
    return {
        "tapm": __version__,
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE_STATEMENT,
        "prompt_version": PROMPT_VERSION,
        "terraform_version_in_plan": res.build.plan.terraform_version,
        "pytm": PYTM_VERSION,
        "scanners_pinned": PINNED,
        "scanner_baselines": versions,
        "ai": (res.ai or {}).get("manifest"),
        "deterministic_hashes": {k: v for k, v in sorted(res.hashes.items()) if k != "report.md"},
        "timings_ms": res.timings_ms,
    }
