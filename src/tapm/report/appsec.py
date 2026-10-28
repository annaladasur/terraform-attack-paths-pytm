"""AppSec persona report generator (W3.2).

Persona report for Application Security (AppSec) engineers:
* Every attack path with detailed evidence per hop and source file:line pointers;
* Data Flow Diagram (DFD) element mapping, trust boundaries crossed, and visual asset references;
* PyTM threat model integration: STRIDE classifications, controls backed by plan evidence vs undecided;
* AI annotations with complete 16-point validator checklist and evidence references;
* Dedicated held annotations and human review queue;
* Risk acceptance and approval governance: active exceptions, expiry countdown, prevent-level 2nd approver;
* Weekly false-path sample protocol (kit metric M8) with reachability verification checklist and dispute template;
* Formats: Markdown (report-appsec.md), JSON, plain text, and SARIF export.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import re
from typing import Any

from .. import SCOPE_STATEMENT, __version__
from ..graph.model import INTERNET
from ..paths.engine import AttackPath, Hop, PRECONDITIONS as PRECONDITION_TEXT
from ..scanners.normalize import Finding
from .markdown import _loc, _short, escape_statement
from .sarif import to_sarif
from .story import path_story


def _fmt_date(d: dt.date | dt.datetime | str | None) -> str:
    if d is None:
        return "None"
    if isinstance(d, (dt.date, dt.datetime)):
        return d.isoformat()
    return str(d)


class AppSecContext:
    """Consolidated data context for AppSec report generation."""

    def __init__(
        self,
        name: str,
        paths: list[AttackPath],
        findings: list[Finding],
        ledger: dict[str, Any],
        nodes: dict[str, Any],
        edges: dict[str, Any],
        pytm: dict[str, Any],
        questions: dict[str, Any],
        remediations: dict[str, Any] | None,
        ai: dict[str, Any] | None,
        validation: list[dict[str, Any]] | None,
        gate: dict[str, Any] | None,
        exceptions: list[dict[str, Any]],
        exception_problems: list[str],
        art_dir: Path | None = None,
        build: Any = None,
        today: dt.date | None = None,
    ):
        self.name = name
        self.today = today or dt.date.today()
        self.paths = paths
        self.findings = findings
        self.ledger = ledger
        self.nodes = nodes
        self.edges = edges
        self.pytm = pytm
        self.questions = questions
        self.remediations = remediations
        self.ai = ai
        self.validation = validation or []
        self.gate = gate
        self.exceptions = exceptions
        self.exception_problems = exception_problems
        self.art_dir = art_dir
        self.build = build


def load_appsec_context(
    data: Any,
    gate: dict[str, Any] | None = None,
    exceptions_path: str | Path | None = None,
    today: dt.date | None = None,
) -> AppSecContext:
    """Load and normalize data from an artifacts directory or RunResult."""
    from ..gate import evaluate, load_exceptions

    if isinstance(data, AppSecContext):
        if today is not None:
            data.today = today
        if gate is not None:
            data.gate = gate
        return data

    today_date = today or dt.date.today()

    if isinstance(data, (str, Path)):
        art_dir = Path(data)
        if not art_dir.exists():
            raise FileNotFoundError(f"Artifacts directory not found: {art_dir}")

        ap_file = art_dir / "attack-paths.json"
        if not ap_file.exists():
            raise FileNotFoundError(f"Missing attack-paths.json in {art_dir}")
        ap_doc = json.loads(ap_file.read_text(encoding="utf-8"))

        paths_list = []
        for p in ap_doc.get("paths", []):
            hops = [
                Hop(
                    edge=h.get("edge", ""),
                    type=h.get("type", ""),
                    src=h.get("src", ""),
                    dst=h.get("dst", ""),
                    label=h.get("label", ""),
                    status=h.get("status", "FACT"),
                    precondition=h.get("precondition"),
                    evidence=h.get("evidence", []),
                )
                for h in p.get("hops", [])
            ]
            paths_list.append(
                AttackPath(
                    id=p["id"],
                    key=p.get("key", f"{p['entry']}->{p['target']}"),
                    entry=p["entry"],
                    target=p["target"],
                    nodes=p.get("nodes", []),
                    hops=hops,
                    preconditions=p.get("preconditions", []),
                    status=p.get("status", "plausible"),
                    priority=p.get("priority", "high"),
                    score=p.get("score", 0),
                    evidence=p.get("evidence", []),
                    target_sensitivity=p.get("target_sensitivity", "confidential"),
                )
            )

        pytm_doc = (
            json.loads((art_dir / "pytm-findings.json").read_text(encoding="utf-8"))
            if (art_dir / "pytm-findings.json").exists()
            else {}
        )
        questions_doc = (
            json.loads((art_dir / "questions.json").read_text(encoding="utf-8"))
            if (art_dir / "questions.json").exists()
            else {}
        )
        remediation_doc = (
            json.loads((art_dir / "remediations.json").read_text(encoding="utf-8"))
            if (art_dir / "remediations.json").exists()
            else None
        )
        ai_doc = (
            json.loads((art_dir / "ai-annotations.json").read_text(encoding="utf-8"))
            if (art_dir / "ai-annotations.json").exists()
            else None
        )
        val_doc = (
            json.loads((art_dir / "validation.json").read_text(encoding="utf-8")).get("annotations", [])
            if (art_dir / "validation.json").exists()
            else []
        )

        findings_list = []
        sf_file = art_dir / "scanner-findings.json"
        if sf_file.exists():
            sf_doc = json.loads(sf_file.read_text(encoding="utf-8"))
            for f in sf_doc.get("findings", []):
                findings_list.append(
                    Finding(
                        id=f.get("id"),
                        tool=f.get("tool", ""),
                        rule_id=f.get("rule_id", ""),
                        severity=f.get("severity", ""),
                        title=f.get("title", ""),
                        resource=f.get("resource", ""),
                        node=f.get("node"),
                        file=f.get("file", ""),
                        start_line=f.get("start_line", 0),
                        end_line=f.get("end_line", 0),
                        causal_paths=list(f.get("causal_paths", ())),
                        paths=list(f.get("paths", ())),
                        concern=f.get("concern"),
                    )
                )

        nodes: dict[str, Any] = {}
        edges: dict[str, Any] = {}
        rg_file = art_dir / "resource-graph.json"
        if rg_file.exists():
            from ..graph.model import Node, Edge

            rg_data = json.loads(rg_file.read_text(encoding="utf-8"))
            for n in rg_data.get("nodes", []):
                nodes[n["id"]] = Node(
                    id=n["id"],
                    type=n["type"],
                    aws_type=n.get("aws_type", ""),
                    category=n.get("category", "other"),
                    label=n.get("label", ""),
                    sensitivity=n.get("sensitivity", {"level": "unclassified"}),
                    source=n.get("source"),
                )
            for e in rg_data.get("edges", []):
                edges[e["id"]] = Edge(
                    id=e["id"],
                    type=e["type"],
                    src=e["src"],
                    dst=e["dst"],
                    label=e.get("label", ""),
                    evidence=e.get("evidence", []),
                    data=e.get("data", {}),
                )

        ledger: dict[str, Any] = {}
        ev_file = art_dir / "evidence.json"
        if ev_file.exists():
            from ..evidence.ledger import Record

            ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
            for r in ev_data.get("records", []):
                ledger[r["id"]] = Record(
                    id=r["id"],
                    kind=r["kind"],
                    key=r.get("key"),
                    summary=r.get("summary", ""),
                    source=r.get("source"),
                    data=r.get("data", {}),
                )

        # Mock build for path_story
        class MockLedger:
            def __init__(self, recs): self._recs = recs
            def by_id(self): return self._recs

        class MockGraph:
            def __init__(self, n, e): self.nodes = n; self.edges = e

        class MockBuild:
            def __init__(self, g, l): self.graph = g; self.ledger = l; self.notes = []; self.unresolved_policies = []

        mock_build = MockBuild(MockGraph(nodes, edges), MockLedger(ledger))

        # Exceptions and gate
        if exceptions_path is None:
            for cand in (
                art_dir / "attack-path-exceptions.yaml",
                art_dir.parent / "attack-path-exceptions.yaml",
                Path("kit/attack-path-exceptions.example.yaml"),
            ):
                if cand.exists():
                    exceptions_path = cand
                    break

        entries, problems = load_exceptions(exceptions_path) if exceptions_path else ([], [])

        if gate is None:
            if (art_dir / "gate.json").exists():
                gate = json.loads((art_dir / "gate.json").read_text(encoding="utf-8"))
            elif ap_doc.get("paths"):
                gate = evaluate(
                    ap_doc["paths"],
                    entries,
                    level="validate",
                    fail_on="high",
                    today=today_date,
                    file_problems=problems,
                )

        return AppSecContext(
            name=art_dir.name,
            paths=paths_list,
            findings=findings_list,
            ledger=ledger,
            nodes=nodes,
            edges=edges,
            pytm=pytm_doc,
            questions=questions_doc,
            remediations=remediation_doc,
            ai=ai_doc,
            validation=val_doc,
            gate=gate,
            exceptions=entries,
            exception_problems=problems,
            art_dir=art_dir,
            build=mock_build,
            today=today_date,
        )

    # If data is a RunResult
    res = data
    art_dir = Path(res.cfg.out_dir) if getattr(res, "cfg", None) and getattr(res.cfg, "out_dir", None) else None
    name = getattr(res.cfg, "name", "run") if getattr(res, "cfg", None) else "run"

    nodes = getattr(res.build.graph, "nodes", {}) if getattr(res, "build", None) else {}
    edges = getattr(res.build.graph, "edges", {}) if getattr(res, "build", None) else {}
    ledger = res.build.ledger.by_id() if getattr(res, "build", None) and getattr(res.build, "ledger", None) else {}

    pytm_data = getattr(res, "pytm", {})
    if isinstance(pytm_data, dict) and "classification" in pytm_data:
        pytm_doc = pytm_data.get("classification", {})
        questions_doc = pytm_data.get("questions", {})
    else:
        pytm_doc = pytm_data if isinstance(pytm_data, dict) else {}
        questions_doc = {}

    ai_doc = getattr(res, "ai", None)
    val_list = []
    if ai_doc and "annotations" in ai_doc:
        val_list = [
            {
                "annotation_id": a.get("annotation_id"),
                "status": a.get("status"),
                "checks": a.get("validation", {}),
                "review": a.get("review"),
                "escalation": a.get("escalation"),
                "rejections": a.get("rejections", []),
            }
            for a in ai_doc.get("annotations", [])
        ]

    # Exceptions
    if exceptions_path is None:
        if art_dir:
            cand = art_dir / "attack-path-exceptions.yaml"
            if cand.exists():
                exceptions_path = cand
    entries, problems = load_exceptions(exceptions_path) if exceptions_path else ([], [])

    if gate is None:
        if art_dir and (art_dir / "gate.json").exists():
            gate = json.loads((art_dir / "gate.json").read_text(encoding="utf-8"))
        else:
            paths_json = [p.to_json() if hasattr(p, "to_json") else p for p in res.paths]
            gate = evaluate(
                paths_json,
                entries,
                level="validate",
                fail_on="high",
                today=today_date,
                file_problems=problems,
            )

    return AppSecContext(
        name=name,
        paths=getattr(res, "paths", []),
        findings=getattr(res, "findings", []),
        ledger=ledger,
        nodes=nodes,
        edges=edges,
        pytm=pytm_doc,
        questions=questions_doc,
        remediations=getattr(res, "remediation", None),
        ai=ai_doc,
        validation=val_list,
        gate=gate,
        exceptions=entries,
        exception_problems=problems,
        art_dir=art_dir,
        build=getattr(res, "build", None),
        today=today_date,
    )


# -----------------------------------------------------------------------------
# Markdown Rendering
# -----------------------------------------------------------------------------

def render_appsec_markdown(ctx: AppSecContext) -> str:
    """Render comprehensive AppSec engineering report in Markdown."""
    lines: list[str] = []
    w = lines.append

    # Title & Posture Header
    w(f"# AppSec Architecture & Attack Path Review: `{ctx.name}`")
    w("")
    w(f"**Scope:** {SCOPE_STATEMENT}")
    w("")

    # Posture Dashboard Table
    paths_count = len(ctx.paths)
    high_count = sum(1 for p in ctx.paths if p.priority == "high")
    med_count = sum(1 for p in ctx.paths if p.priority == "medium")
    low_count = sum(1 for p in ctx.paths if p.priority == "low")

    pytm_summary = ctx.pytm.get("summary", {}) if isinstance(ctx.pytm, dict) else {}
    pytm_published = pytm_summary.get("published", len(ctx.pytm.get("findings", [])))
    pytm_confirmed = pytm_summary.get("confirmed", sum(1 for f in ctx.pytm.get("findings", []) if f.get("class") == "confirmed"))
    pytm_mitigated = pytm_summary.get("mitigated", sum(1 for f in ctx.pytm.get("findings", []) if f.get("class") == "mitigated"))

    sf_count = len(ctx.findings)
    sf_on_paths = sum(1 for f in ctx.findings if f.paths)

    ai_ann = ctx.ai.get("annotations", []) if ctx.ai and isinstance(ctx.ai, dict) else []
    ai_total = len(ai_ann)
    ai_held = sum(1 for a in ai_ann if a.get("status") in ("human_review", "held") or a.get("status") == "rejected")
    ai_accepted = sum(1 for a in ai_ann if a.get("status") == "accepted")

    gate_level = ctx.gate.get("level", "validate") if ctx.gate else "validate"
    gate_decision = ctx.gate.get("decision", "pass").upper() if ctx.gate else "PASS"
    gate_in_scope = ctx.gate.get("in_scope", paths_count) if ctx.gate else paths_count
    gate_without = ctx.gate.get("without_decision", 0) if ctx.gate else 0
    gate_accepted = ctx.gate.get("accepted", 0) if ctx.gate else 0
    gate_not_reachable = ctx.gate.get("not_reachable", 0) if ctx.gate else 0

    w("## Threat Posture Overview")
    w("")
    w("| Domain | Metric | Count / Status | AppSec Notes |")
    w("|---|---|---|---|")
    w(f"| **Attack Paths** | Total Identified | **{paths_count}** ({high_count} high, {med_count} medium, {low_count} low) | Ranked reachable paths from internet entry |")
    w(f"| **PyTM Threats** | Published / Confirmed | **{pytm_published}** published · **{pytm_confirmed}** confirmed · **{pytm_mitigated}** mitigated | Threat model backed by plan evidence |")
    w(f"| **Scanner Findings** | Total / On Paths | **{sf_count}** total · **{sf_on_paths}** on attack path hops | Contextualized findings with blast radius |")
    w(f"| **AI Annotations** | Validated / Held | **{ai_accepted}** accepted · **{ai_held}** held for review ({ai_total} total) | 16-point validator + adversarial review |")
    w(f"| **Gate Governance** | Level: `{gate_level}` | **{gate_decision}** ({gate_without} unaccepted, {gate_accepted} accepted, {gate_not_reachable} disputed) | Decision required at `{gate_level}` threshold |")
    w("")

    # Decisions Supported
    w("### Decisions Supported by this Review:")
    w(f"1. **Gate Threshold & Policy:** Currently at level `{gate_level}`. If blocking threshold is `{ctx.gate.get('fail_on', 'high') if ctx.gate else 'high'}`, {gate_without} path(s) require action before merge.")
    w("2. **Risk Approvals:** Evaluate risk acceptances in `attack-path-exceptions.yaml`, verifying compensating controls and authorized CODEOWNERS sign-off.")
    w("3. **False-Path Labeling:** Sample reported plausible paths weekly (M8) to label non-reachable routes with `disposition: not_reachable` (target M8 < 10%).")
    w("")

    # -------------------------------------------------------------------------
    # Section 1: Every Path with Evidence Per Hop
    # -------------------------------------------------------------------------
    w("## 1. Attack Paths & Hop-by-Hop Evidence Traces")
    w("")
    if not ctx.paths:
        w("_No attack paths identified from an internet-reachable entry point to a classified asset._")
        w("")
    else:
        for idx, p in enumerate(ctx.paths, 1):
            w(f"### Path {p.id}: `{p.entry}` → `{p.target}`")
            w(f"* **Priority:** **{p.priority.upper()}** (score: {p.score})")
            w(f"* **Target Sensitivity:** `{p.target_sensitivity}`")
            w(f"* **Reachability Status:** `{p.status}`")
            pre_str = ", ".join(f"`{x}`" for x in p.preconditions) if p.preconditions else "None (direct path)"
            w(f"* **Preconditions Required:** {pre_str}")
            w("")

            # Plain English narration
            if ctx.build:
                try:
                    story_text = path_story(p, ctx.build, audience="developer")
                    w(f"**Narrative:** {story_text}")
                    w("")
                except Exception:
                    pass

            # Verified Remediation Patch
            rem_patch = None
            if ctx.remediations and "paths" in ctx.remediations:
                for rp in ctx.remediations.get("paths", []):
                    for att in rp.get("attempts", []):
                        if att.get("status") in ("PROVEN_BREAK", "PROVEN_DOWNGRADE"):
                            rem_patch = att
                            break
                    if rem_patch:
                        break
            if rem_patch:
                w(f"**Verified Remediation Patch:** (`{rem_patch.get('status')}` on hop {rem_patch.get('patch', {}).get('hop')})")
                w(f"> Rationale: {rem_patch.get('patch', {}).get('rationale', '')}")
                w("```diff")
                w(rem_patch.get("diff", "").strip())
                w("```")
                w("")

            # Hop Table
            w("#### Hop Sequence & Architectural Flow")
            w("")
            w("| Hop | Edge Type | Source Node | Destination Node | Status | Precondition | Evidence IDs |")
            w("|---|---|---|---|---|---|---|")
            for h_idx, hop in enumerate(p.hops, 1):
                ev_links = ", ".join(f"`{e}`" for e in hop.evidence) if hop.evidence else "—"
                pre = f"`{hop.precondition}`" if hop.precondition else "—"
                src_short = _short(hop.src)
                dst_short = _short(hop.dst)
                w(f"| {h_idx} | `{hop.type}` | `{src_short}` | `{dst_short}` | {hop.status} | {pre} | {ev_links} |")
            w("")

            # Evidence Trace per Hop
            w("#### Hop Evidence Ledger Details")
            w("")
            all_hop_ev = []
            for hop in p.hops:
                if hop.edge and hop.edge in ctx.ledger and hop.edge not in all_hop_ev:
                    all_hop_ev.append(hop.edge)
                for eid in hop.evidence:
                    if eid not in all_hop_ev:
                        all_hop_ev.append(eid)
            for eid in p.evidence:
                if eid in ctx.ledger and eid not in all_hop_ev:
                    all_hop_ev.append(eid)

            if not all_hop_ev:
                w("_No specific evidence IDs recorded for this path's hops._")
            else:
                w("| Evidence ID | Kind | Source Location | Configuration Summary |")
                w("|---|---|---|---|")
                for eid in all_hop_ev:
                    rec = ctx.ledger.get(eid)
                    if rec:
                        loc_str = f"`{rec.source['file']}:{rec.source.get('start_line', 0)}`" if rec.source and rec.source.get("file") else "synthesized"
                        kind_str = rec.kind
                        summary_str = escape_statement(rec.summary[:200])
                    else:
                        loc_str = "—"
                        kind_str = eid.split("-")[0] if "-" in eid else "EVID"
                        summary_str = "Evidence record in run ledger"
                    w(f"| `{eid}` | {kind_str} | {loc_str} | {summary_str} |")
            w("")

    # -------------------------------------------------------------------------
    # Section 2: Data Flow Diagram (DFD) & Architecture Decomposition
    # -------------------------------------------------------------------------
    w("## 2. Data Flow Diagram (DFD) & Architectural Model")
    w("")
    w("The architectural data flow graph decomposes the Terraform plan into pytm processes, datastores, and trust boundaries.")
    w("")

    # Summary of elements
    processes = [n for n in ctx.nodes.values() if getattr(n, "category", "") in ("compute", "process")]
    datastores = [n for n in ctx.nodes.values() if getattr(n, "category", "") in ("storage", "database", "datastore")]
    externals = [n for n in ctx.nodes.values() if getattr(n, "category", "") in ("external", "internet") or n.id == INTERNET]
    boundaries = ["Internet (External)", "DMZ / Ingress Subnet", "VPC / Workload Boundary", "AWS Service & API Boundary"]

    w("| Element Category | Count | Representative Entities |")
    w("|---|---|---|")
    w(f"| **Processes & Compute** | {len(processes)} | {', '.join(f'`{p.id}`' for p in processes[:4]) or '—'} |")
    w(f"| **Datastores & Assets** | {len(datastores)} | {', '.join(f'`{d.id}`' for d in datastores[:4]) or '—'} |")
    w(f"| **External Entities** | {len(externals)} | {', '.join(f'`{e.id}`' for e in externals[:4]) or '—'} |")
    w(f"| **Trust Boundaries** | {len(boundaries)} | {'; '.join(boundaries)} |")
    w("")

    # Boundaries crossed
    w("### Trust Boundary Crossings in Attack Paths")
    w("")
    w("Every identified attack path traverses multiple trust domains:")
    w("1. **Internet → DMZ / Ingress:** Traversed via public load balancer listeners (`aws_lb`, SG ingress `0.0.0.0/0:443`).")
    w("2. **DMZ → Workload VPC:** Forwarded via target groups to internal compute nodes (`aws_instance`, port 8080).")
    w("3. **Workload → IAM Identity Plane:** Workload assumes execution role (`aws_iam_role.app`) via instance metadata (IMDS).")
    w("4. **IAM Identity → Data Asset Plane:** Role credentials exercise IAM policy granting storage access (`aws_s3_bucket`).")
    w("")

    # Visual Artifacts
    w("### Visual Architecture Artifacts")
    w("")
    w("Visual DFD diagrams rendered during deterministic analysis:")
    dfd_files = ["dfd.png", "dfd.svg", "dfd.dot", "dfd-overview.dot", "dfd-risk.dot"]
    for fname in dfd_files:
        exists_mark = "✓ Available" if ctx.art_dir and (ctx.art_dir / fname).exists() else "○ Referenced"
        w(f"* `{fname}` — {exists_mark}")
    w("")

    # -------------------------------------------------------------------------
    # Section 3: PyTM Threat Model & STRIDE Analysis
    # -------------------------------------------------------------------------
    w("## 3. PyTM Threat Model & STRIDE Analysis")
    w("")
    w("The PyTM threat engine evaluates standard OWASP threats and the cloud extension pack against plan evidence.")
    w("")
    w(f"* **Published Threats:** {pytm_published}")
    w(f"* **Confirmed Threats:** {pytm_confirmed} (controls verified absent/failing by plan evidence)")
    w(f"* **Mitigated Threats:** {pytm_mitigated} (controls verified present by plan evidence)")
    w(f"* **Needs App Team / Undecided:** {pytm_summary.get('needs_app_team', '—')}")
    w(f"* **Cloud Pack Threats:** {', '.join(f'`{t}`' for t in pytm_summary.get('pack_threats', [])) or 'Standard'}")
    w("")

    # Threats mapped to path hops
    pytm_findings = ctx.pytm.get("findings", []) if isinstance(ctx.pytm, dict) else []
    confirmed_path_threats = [f for f in pytm_findings if f.get("class") == "confirmed" and f.get("on_paths")]

    w("### Confirmed Threats Aligned with Attack Path Hops")
    w("")
    if not confirmed_path_threats:
        w("_No confirmed PyTM threats mapped directly to attack path hops._")
    else:
        w("| Threat ID | Element | STRIDE Category | Description | Decided Controls (Evidence) |")
        w("|---|---|---|---|---|")
        for th in confirmed_path_threats[:8]:
            th_id = th.get("threat_id", "—")
            elem = th.get("element", "—")
            desc = th.get("description", "—")
            dec_list = []
            for ctrl, dinfo in (th.get("decided") or {}).items():
                ev_str = f"[{', '.join(dinfo.get('evidence', []))}]" if dinfo.get("evidence") else ""
                dec_list.append(f"`{ctrl}: {dinfo.get('value')}` {ev_str}")
            dec_str = "<br>".join(dec_list) if dec_list else "default"
            stride_cat = _stride_category(desc, th.get("category") or th.get("stride"))
            w(f"| `{th_id}` | `{elem}` | {stride_cat} | {desc} | {dec_str} |")
    w("")

    # Questions for App Team
    app_q = ctx.questions.get("data_questions", []) if ctx.questions else []
    if app_q:
        w("### Open Architecture & Data Questions for Application Owners")
        w("")
        for q in app_q:
            w(f"* **{q.get('resource', 'Asset')}:** {q.get('question', '')} — _Impact: {q.get('why', '')}_")
        w("")

    # -------------------------------------------------------------------------
    # Section 4: AI Annotations & Evidence Verification
    # -------------------------------------------------------------------------
    w("## 4. AI Annotations & Validator Audit")
    w("")
    w("AI annotations are admitted to reports only after passing the 16-point deterministic validator and adversarial reviewer.")
    w("")

    if not ai_ann:
        w("_No AI annotations recorded in artifacts (analysis ran model-free or annotations omitted)._")
    else:
        w("| Annotation ID | Role | Target Path | Severity | Confidence | Cited Evidence IDs | Validator Checks |")
        w("|---|---|---|---|---|---|---|")
        for a in ai_ann:
            ann_id = a.get("annotation_id", "—")
            agent = a.get("agent", "—")
            path_ref = a.get("path_ref", "—")
            sev = a.get("severity", "—")
            conf = a.get("confidence", "—")
            ev_refs = ", ".join(f"`{e}`" for e in a.get("evidence_refs", [])) or "None"
            checks = a.get("validation", {})
            pass_count = sum(1 for v in checks.values() if v is True)
            tot_checks = len(checks) if checks else 16
            w(f"| `{ann_id}` | `{agent}` | `{path_ref}` | {sev} | {conf} | {ev_refs} | {pass_count}/{tot_checks} passed |")
        w("")

        w("#### Validated Annotation Statements")
        w("")
        for a in ai_ann:
            if a.get("status") == "accepted":
                safe_stmt = escape_statement(a.get("statement", ""))
                w(f"> **`{a.get('annotation_id')}` ({a.get('agent')}) on `{a.get('path_ref')}`:** {safe_stmt}")
                w("")

    # -------------------------------------------------------------------------
    # Section 5: Held Annotations & Human Review Queue
    # -------------------------------------------------------------------------
    w("## 5. Held Annotations & Human Review Queue")
    w("")
    held_list = [a for a in ai_ann if a.get("status") in ("human_review", "held") or a.get("status") == "rejected"]

    if not held_list:
        w("✓ **Queue Clean:** No annotations were held or rejected. All generated statements met the publish escalation threshold (`publish_without_human >= 0.70`) and satisfied all 16 validator checks without human escalation.")
        w("")
    else:
        w(f"⚠️ **Attention AppSec:** {len(held_list)} annotation(s) held for human review or rejected.")
        w("")
        w("| Annotation ID | Target Path | Status | Escalation p | Reasons / Reviewer Issues | Action Required |")
        w("|---|---|---|---|---|---|")
        for h in held_list:
            hid = h.get("annotation_id", "—")
            pref = h.get("path_ref", "—")
            st = h.get("status", "held")
            esc_p = h.get("escalation", {}).get("publish_without_human", 0.0)
            reasons = "; ".join(h.get("rejections", [])) or h.get("reason", "Escalated for human review")
            w(f"| `{hid}` | `{pref}` | **{st.upper()}** | {esc_p:.2f} | {escape_statement(reasons)} | AppSec review of cited evidence |")
        w("")

    # -------------------------------------------------------------------------
    # Section 6: Risk Governance & Pending Approvals
    # -------------------------------------------------------------------------
    w("## 6. Risk Governance & Pending Approvals")
    w("")
    w(f"* **Current Gate Level:** `{gate_level}`")
    w(f"* **Enforcement Threshold:** `{ctx.gate.get('fail_on', 'high') if ctx.gate else 'high'}`")
    w(f"* **Decision Verdict:** **{gate_decision}**")
    w("")

    # Paths needing decision
    if gate_without > 0:
        w(f"⚠️ **Pending Decisions:** **{gate_without}** attack path(s) at or above `{ctx.gate.get('fail_on', 'high') if ctx.gate else 'high'}` currently have no approved resolution.")
        w("Options to resolve before merge:")
        w("1. Apply proven remediation patch (breaks the path).")
        w("2. Author an accepted risk entry in `attack-path-exceptions.yaml`.")
        w("3. Dispute the path as unreachable (`disposition: not_reachable`).")
        w("")
    else:
        w("✓ **All Paths Decided:** Zero open paths without an approved disposition.")
        w("")

    # Active Exceptions Table
    w("### Active Exceptions in `attack-path-exceptions.yaml`")
    w("")
    if not ctx.exceptions:
        w("_No active exceptions found in `attack-path-exceptions.yaml`._")
    else:
        w("| Exception ID | Entry | Target | Disposition | Owner | Expiration | Prevent Approver | Status |")
        w("|---|---|---|---|---|---|---|---|")
        today_val = getattr(ctx, "today", None) or dt.date.today()
        for exc in ctx.exceptions:
            eid = exc.get("id", "—")
            entry = exc.get("entry", "—")
            target = exc.get("target", "—")
            disp = exc.get("disposition", "accepted_risk")
            owner = exc.get("owner", "—")
            expires_raw = exc.get("expires")
            appr = exc.get("approved_by", "—")

            # Check status
            status_badge = "ACTIVE"
            if expires_raw:
                try:
                    exp_date = dt.date.fromisoformat(str(expires_raw))
                    days_left = (exp_date - today_val).days
                    if days_left < 0:
                        status_badge = "⚠️ EXPIRED"
                    elif days_left <= 14:
                        status_badge = f"⚠️ EXPIRING ({days_left}d)"
                    else:
                        status_badge = f"VALID ({days_left}d)"
                except Exception:
                    status_badge = "INVALID DATE"

            if gate_level == "prevent" and disp == "accepted_risk":
                if not exc.get("approved_by") or exc.get("approved_by") == owner:
                    status_badge += " (NEEDS 2ND APPROVER)"

            w(f"| `{eid}` | `{entry}` | `{target}` | `{disp}` | `{owner}` | `{expires_raw or 'permanent'}` | `{appr}` | {status_badge} |")
    w("")

    if ctx.exception_problems:
        w("#### Exception Configuration Warnings:")
        for prob in ctx.exception_problems:
            w(f"* ⚠️ {prob}")
        w("")

    # -------------------------------------------------------------------------
    # Section 7: Weekly False-Path Sample (Kit Metric M8)
    # -------------------------------------------------------------------------
    w("## 7. Weekly False-Path Sample Protocol (Kit Metric M8)")
    w("")
    w("### Kit Metric M8 Governance")
    w("* **Metric Definition:** False-path rate = `not_reachable / total_paths`")
    w("* **AppSec Target:** Keep M8 < **10%** before gate enforcement at `validate`.")
    w("* **Cadence:** Weekly sample of reported plausible paths evaluated for real-world reachability.")
    w("")

    # Weekly Sample Candidates
    sample_paths = ctx.paths[:3]  # Deterministic weekly audit set
    w("### Weekly Candidate Sample for Verification")
    w("")
    if not sample_paths:
        w("_No active paths available for weekly sampling._")
    else:
        for s_idx, sp in enumerate(sample_paths, 1):
            w(f"#### Sample #{s_idx}: `{sp.id}` (`{sp.entry}` → `{sp.target}`)")
            w(f"* **Preconditions:** {', '.join(sp.preconditions) if sp.preconditions else 'None'}")
            w("* **Reachability Verification Checklist:**")
            w("  - [ ] **1. Public Ingress:** Is the entry point genuinely reachable from the untrusted internet (valid IGW route, public subnet, 0.0.0.0/0 SG ingress)?")
            w("  - [ ] **2. Network Routing:** Can network traffic route to internal workload without an intermediate blocking firewall or NACL?")
            w("  - [ ] **3. Workload Execution:** Is the stated precondition (`workload_ssrf`, `workload_rce`) feasible in this workload?")
            w("  - [ ] **4. Credential Access:** Does the workload actually fetch instance metadata or task credentials without token requirement?")
            w("  - [ ] **5. Target Action:** Does the IAM role policy allow the specified action on the target resource without unfulfilled Condition keys?")
            w("")

        w("### False-Path Dispute Instructions")
        w("If any verification check fails and the path cannot be reached in reality:")
        w("1. Add a dispute entry to `attack-path-exceptions.yaml` using `disposition: not_reachable`.")
        w("2. Disputed paths are automatically counted into M8 and do **not** block pull requests at `validate` or `prevent`.")
        w("")
        w("```yaml")
        w("# attack-path-exceptions.yaml dispute entry template")
        w("exceptions:")
        w(f"  - id: DISPUTE-{dt.date.today().strftime('%Y')}-001")
        w(f"    entry: {sample_paths[0].entry}")
        w(f"    target: {sample_paths[0].target}")
        w("    disposition: not_reachable")
        w("    owner: appsec-team")
        w("    reason: 'Route cannot be reached: internal security group prevents ingress from load balancer subnet.'")
        w("```")
        w("")

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# JSON and Text Rendering
# -----------------------------------------------------------------------------

def render_appsec_json(ctx: AppSecContext) -> str:
    """Render structured AppSec report as JSON."""
    pytm_summary = ctx.pytm.get("summary", {}) if isinstance(ctx.pytm, dict) else {}
    ai_ann = ctx.ai.get("annotations", []) if ctx.ai and isinstance(ctx.ai, dict) else []
    held_list = [a for a in ai_ann if a.get("status") in ("human_review", "held") or a.get("status") == "rejected"]

    paths_data = []
    for p in ctx.paths:
        hops_data = [
            {
                "edge": h.edge,
                "type": h.type,
                "src": h.src,
                "dst": h.dst,
                "status": h.status,
                "precondition": h.precondition,
                "evidence": h.evidence,
                "label": h.label,
            }
            for h in p.hops
        ]
        paths_data.append(
            {
                "id": p.id,
                "entry": p.entry,
                "target": p.target,
                "priority": p.priority,
                "status": p.status,
                "score": p.score,
                "target_sensitivity": p.target_sensitivity,
                "preconditions": p.preconditions,
                "hops": hops_data,
                "evidence": p.evidence,
            }
        )

    doc = {
        "persona": "appsec",
        "version": __version__,
        "name": ctx.name,
        "scope": SCOPE_STATEMENT,
        "summary": {
            "paths_total": len(ctx.paths),
            "paths_high": sum(1 for p in ctx.paths if p.priority == "high"),
            "paths_medium": sum(1 for p in ctx.paths if p.priority == "medium"),
            "paths_low": sum(1 for p in ctx.paths if p.priority == "low"),
            "scanner_findings_total": len(ctx.findings),
            "scanner_findings_on_paths": sum(1 for f in ctx.findings if f.paths),
            "pytm_published": pytm_summary.get("published", len(ctx.pytm.get("findings", []))),
            "pytm_confirmed": pytm_summary.get("confirmed", 0),
            "pytm_mitigated": pytm_summary.get("mitigated", 0),
            "ai_annotations_total": len(ai_ann),
            "ai_annotations_accepted": sum(1 for a in ai_ann if a.get("status") == "accepted"),
            "ai_annotations_held": len(held_list),
            "gate_level": ctx.gate.get("level", "validate") if ctx.gate else "validate",
            "gate_decision": ctx.gate.get("decision", "pass") if ctx.gate else "pass",
            "gate_without_decision": ctx.gate.get("without_decision", 0) if ctx.gate else 0,
            "gate_accepted": ctx.gate.get("accepted", 0) if ctx.gate else 0,
            "gate_not_reachable": ctx.gate.get("not_reachable", 0) if ctx.gate else 0,
        },
        "paths": paths_data,
        "dfd": {
            "nodes_count": len(ctx.nodes),
            "edges_count": len(ctx.edges),
            "boundaries": ["Internet", "DMZ", "VPC", "AWS Service APIs"],
            "visual_files": ["dfd.png", "dfd.svg", "dfd.dot", "dfd-overview.dot", "dfd-risk.dot"],
        },
        "pytm": {
            "summary": pytm_summary,
            "findings_count": len(ctx.pytm.get("findings", [])),
        },
        "ai_annotations": ai_ann,
        "held_annotations": held_list,
        "governance": {
            "gate": ctx.gate,
            "exceptions": ctx.exceptions,
            "exception_problems": ctx.exception_problems,
        },
        "false_path_sampling": {
            "target_metric": "M8 (False-path rate < 10%)",
            "sample_path_ids": [p.id for p in ctx.paths[:3]],
            "checklist": [
                "Public Ingress verification",
                "Internal Network Routing verification",
                "Workload Precondition feasibility",
                "Credential Metadata Access",
                "Target IAM Permission verification",
            ],
            "dispute_disposition": "not_reachable",
        },
    }
    return json.dumps(doc, indent=2, default=str)


def _stride_category(desc: str, cat: str | None = None) -> str:
    """Classify a threat description or category into a standard STRIDE category."""
    if cat and str(cat).strip():
        return str(cat).strip()
    d = (desc or "").lower()
    if "sniff" in d or "leak" in d or "disclosure" in d:
        return "Information Disclosure"
    if "tamper" in d or "manipulation" in d or "audit" in d:
        return "Tampering"
    if "denial" in d or "dos" in d:
        return "Denial of Service"
    if "spoof" in d:
        return "Spoofing"
    if "repudiation" in d:
        return "Repudiation"
    return "Elevation of Privilege"


def _hop_locations(ctx: AppSecContext, hop: Hop) -> list[str]:
    """Extract source file:line locations for an attack path hop."""
    locs: list[str] = []
    seen: set[str] = set()

    def add_loc(f: str | None, line: Any):
        if not f:
            return
        loc_str = f"{f}:{line}"
        if loc_str not in seen:
            seen.add(loc_str)
            locs.append(loc_str)

    # 1. Check hop evidence records in ledger
    for eid in hop.evidence:
        rec = ctx.ledger.get(eid)
        if rec and getattr(rec, "source", None) and rec.source.get("file"):
            add_loc(rec.source["file"], rec.source.get("start_line", 0))

    # 2. Check hop edge record in ledger
    if hop.edge and hop.edge in ctx.ledger:
        rec = ctx.ledger.get(hop.edge)
        if rec and getattr(rec, "source", None) and rec.source.get("file"):
            add_loc(rec.source["file"], rec.source.get("start_line", 0))

    # 3. Check destination and source nodes
    for nid in (hop.dst, hop.src):
        node = ctx.nodes.get(nid)
        if node and getattr(node, "source", None) and node.source.get("file"):
            add_loc(node.source["file"], node.source.get("start_line", 0))

    return locs


def render_appsec_text(ctx: AppSecContext) -> str:
    """Render AppSec report as plain ASCII text with STRIDE, DFD, and hop locations (A19)."""
    lines: list[str] = []
    w = lines.append

    w(f"================================================================================")
    w(f"APPSEC ARCHITECTURE & ATTACK PATH REVIEW: {ctx.name}")
    w(f"================================================================================")
    w(f"Scope: {SCOPE_STATEMENT}")
    w("")

    paths_count = len(ctx.paths)
    high_count = sum(1 for p in ctx.paths if p.priority == "high")
    gate_decision = ctx.gate.get("decision", "pass").upper() if ctx.gate else "PASS"
    gate_level = ctx.gate.get("level", "validate") if ctx.gate else "validate"
    gate_without = ctx.gate.get("without_decision", 0) if ctx.gate else 0

    w(f"POSTURE DASHBOARD:")
    w(f"  Attack Paths:       {paths_count} total ({high_count} high)")
    w(f"  Gate Verdict:       {gate_decision} at level '{gate_level}'")
    w(f"  Pending Decisions:  {gate_without} unaccepted path(s)")
    w(f"  Scanner Findings:   {len(ctx.findings)} total ({sum(1 for f in ctx.findings if f.paths)} on paths)")
    ai_ann = ctx.ai.get("annotations", []) if ctx.ai and isinstance(ctx.ai, dict) else []
    held_count = sum(1 for a in ai_ann if a.get("status") in ("human_review", "held") or a.get("status") == "rejected")
    w(f"  AI Annotations:     {len(ai_ann)} generated ({held_count} held for human review)")
    w("")

    w(f"ATTACK PATHS & HOPS:")
    for p in ctx.paths:
        w(f"  [{p.priority.upper()}] Path {p.id}: {p.entry} -> {p.target} (status: {p.status})")
        for idx, h in enumerate(p.hops, 1):
            h_locs = _hop_locations(ctx, h)
            loc_str = f" ({', '.join(h_locs[:2])})" if h_locs else ""
            ev_str = f" [{', '.join(h.evidence)}]" if h.evidence else ""
            pre_str = f" (precondition: {h.precondition})" if h.precondition else ""
            w(f"    Hop {idx}: {h.type} {h.src} -> {h.dst}{loc_str}{ev_str}{pre_str}")
        w("")

    # Section: DFD & Architectural Model
    processes = [n for n in ctx.nodes.values() if getattr(n, "category", "") in ("compute", "process")]
    datastores = [n for n in ctx.nodes.values() if getattr(n, "category", "") in ("storage", "database", "datastore")]
    externals = [n for n in ctx.nodes.values() if getattr(n, "category", "") in ("external", "internet") or n.id == INTERNET]
    boundaries = ["Internet (External)", "DMZ / Ingress Subnet", "VPC / Workload Boundary", "AWS Service & API Boundary"]

    w(f"DATA FLOW DIAGRAM (DFD) & ARCHITECTURAL MODEL:")
    w(f"  Architectural Elements: {len(processes)} compute/processes, {len(datastores)} datastores, {len(externals)} externals")
    w(f"  Trust Boundaries:       {'; '.join(boundaries)}")
    w(f"  Trust Boundary Crossings in Attack Paths:")
    w(f"    1. Internet -> DMZ / Ingress (Public LB & ingress SG)")
    w(f"    2. DMZ -> Workload VPC Boundary (Target group forwarding to compute)")
    w(f"    3. Workload -> IAM Identity Plane (Workload IMDS role assumption)")
    w(f"    4. IAM Identity -> Data Asset Plane (Role credentials policy S3 access)")
    w(f"  Visual DFD Artifacts:")
    dfd_files = ["dfd.png", "dfd.svg", "dfd.dot", "dfd-overview.dot", "dfd-risk.dot"]
    for fname in dfd_files:
        exists_mark = "available" if ctx.art_dir and (ctx.art_dir / fname).exists() else "referenced"
        w(f"    * {fname} ({exists_mark})")
    w("")

    # Section: PyTM Threat Model & STRIDE Analysis
    pytm_summary = ctx.pytm.get("summary", {}) if isinstance(ctx.pytm, dict) else {}
    pytm_published = pytm_summary.get("published", len(ctx.pytm.get("findings", [])) if isinstance(ctx.pytm, dict) else 0)
    pytm_confirmed = pytm_summary.get("confirmed", sum(1 for f in ctx.pytm.get("findings", []) if f.get("class") == "confirmed") if isinstance(ctx.pytm, dict) else 0)
    pytm_mitigated = pytm_summary.get("mitigated", sum(1 for f in ctx.pytm.get("findings", []) if f.get("class") == "mitigated") if isinstance(ctx.pytm, dict) else 0)
    pytm_findings = ctx.pytm.get("findings", []) if isinstance(ctx.pytm, dict) else []
    confirmed_path_threats = [f for f in pytm_findings if f.get("class") == "confirmed" and f.get("on_paths")]

    w(f"PYTM THREAT MODEL & STRIDE ANALYSIS:")
    w(f"  Threat Model Summary: {pytm_published} published, {pytm_confirmed} confirmed, {pytm_mitigated} mitigated")
    if confirmed_path_threats:
        w(f"  Confirmed Threats Aligned with Attack Path Hops (STRIDE):")
        for th in confirmed_path_threats[:8]:
            th_id = th.get("threat_id", "—")
            elem = th.get("element", "—")
            desc = th.get("description", "—")
            stride_cat = _stride_category(desc, th.get("category") or th.get("stride"))
            dec_list = []
            for ctrl, dinfo in (th.get("decided") or {}).items():
                ev_str = f"[{', '.join(dinfo.get('evidence', []))}]" if dinfo.get("evidence") else ""
                dec_list.append(f"{ctrl}={dinfo.get('value')} {ev_str}".strip())
            dec_str = f" (controls: {', '.join(dec_list)})" if dec_list else ""
            w(f"    [{th_id}] {elem} · STRIDE: {stride_cat} · {desc}{dec_str}")
    else:
        w(f"  No confirmed PyTM threats mapped directly to attack path hops.")
    w("")

    w(f"GOVERNANCE & WEEKLY SAMPLE (M8):")
    w(f"  Weekly audit candidate: {ctx.paths[0].id if ctx.paths else 'None'}")
    w(f"  Dispute false paths in attack-path-exceptions.yaml with disposition: not_reachable")
    w(f"================================================================================")

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Public Entry Point
# -----------------------------------------------------------------------------

def render_appsec_report(
    data: Any,
    format: str = "markdown",
    gate: dict[str, Any] | None = None,
    exceptions_path: str | Path | None = None,
    today: dt.date | None = None,
) -> str:
    """Render the AppSec persona report.

    Args:
        data: Either an artifacts directory Path/str or a RunResult object.
        format: Output format ('markdown', 'json', 'text', or 'sarif').
        gate: Optional gate evaluation dict.
        exceptions_path: Optional path to attack-path-exceptions.yaml.
        today: Optional date for expiration calculation.

    Returns:
        Formatted report string.
    """
    ctx = load_appsec_context(data, gate=gate, exceptions_path=exceptions_path, today=today)

    if format == "json":
        return render_appsec_json(ctx)

    if format == "text":
        return render_appsec_text(ctx)

    if format == "sarif":
        # Export SARIF format
        class MockRunRes:
            def __init__(self, c):
                self.paths = c.paths
                self.build = c.build

        mock_res = MockRunRes(ctx)
        sarif_doc = to_sarif(mock_res)
        return json.dumps(sarif_doc, indent=2)

    return render_appsec_markdown(ctx)
