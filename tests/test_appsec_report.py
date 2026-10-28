"""Unit tests for AppSec persona report (W3.2).

Verifies:
1. Every path with evidence per hop and file:line pointers;
2. DFD element mapping, trust boundary crossings, and visual artifact references;
3. PyTM threat model integration with STRIDE classifications and confirmed path threats;
4. AI annotations with evidence IDs and validator verification audit;
5. Dedicated held annotations and human review queue;
6. Risk governance, active exceptions, expiration alerts, and prevent-level approver checks;
7. Weekly false-path sample protocol (M8) with reachability checklist and dispute template;
8. Markdown, JSON, Text, and SARIF output formats;
9. CLI tapm report --persona appsec;
10. End-to-end pipeline generation of report-appsec.md.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import pytest

from tapm import SCOPE_STATEMENT
from tapm.report.appsec import render_appsec_report, load_appsec_context
from tapm.report.developer import count_first_screen_items

ROOT = Path(__file__).resolve().parents[1]
CONF_SNAP = ROOT / "conference-snapshot"


def test_conference_snapshot_appsec_markdown():
    """Verify all 7 AppSec sections and requirements in Markdown format on conference-snapshot."""
    assert CONF_SNAP.exists()
    report_md = render_appsec_report(CONF_SNAP, format="markdown")

    # Title & Canonical Scope line
    assert "# AppSec Architecture & Attack Path Review: `conference-snapshot`" in report_md
    assert f"**Scope:** {SCOPE_STATEMENT}" in report_md

    # Posture Dashboard
    assert "## Threat Posture Overview" in report_md
    assert "| **Attack Paths** |" in report_md
    assert "| **PyTM Threats** |" in report_md
    assert "| **Scanner Findings** |" in report_md
    assert "| **AI Annotations** |" in report_md
    assert "| **Gate Governance** |" in report_md

    # 1. Attack Paths & Hop-by-Hop Evidence Trace
    assert "## 1. Attack Paths & Hop-by-Hop Evidence Traces" in report_md
    assert "### Path PATH-001: `internet` → `aws_s3_bucket.customer_data`" in report_md
    assert "#### Hop Sequence & Architectural Flow" in report_md
    assert "| 1 | `EXPOSES` | `Internet` | `aws_lb.web` |" in report_md
    assert "| 2 | `ROUTES_TO` | `aws_lb.web` | `aws_instance.app` |" in report_md
    assert "#### Hop Evidence Ledger Details" in report_md
    assert "| `GRAPH-017` |" in report_md
    assert "| `IAM-001` |" in report_md
    assert "alb.tf:" in report_md
    assert "iam.tf:" in report_md

    # Proven fix diff
    assert "**Verified Remediation Patch:**" in report_md
    assert "```diff" in report_md

    # 2. DFD & Architecture Decomposition
    assert "## 2. Data Flow Diagram (DFD) & Architectural Model" in report_md
    assert "### Trust Boundary Crossings in Attack Paths" in report_md
    assert "Internet → DMZ / Ingress" in report_md
    assert "Workload → IAM Identity Plane" in report_md
    assert "### Visual Architecture Artifacts" in report_md
    assert "`dfd.png`" in report_md
    assert "`dfd.svg`" in report_md

    # 3. PyTM Threat Model & STRIDE Analysis
    assert "## 3. PyTM Threat Model & STRIDE Analysis" in report_md
    assert "### Confirmed Threats Aligned with Attack Path Hops" in report_md
    assert "`DE03`" in report_md
    assert "`TAPM-EC2-01`" in report_md
    assert "`TAPM-IAM-02`" in report_md
    assert "Information Disclosure" in report_md
    assert "Elevation of Privilege" in report_md

    # 4. AI Annotations & Validator Audit
    assert "## 4. AI Annotations & Validator Audit" in report_md
    assert "| `ANN-001` | `path_narrator` |" in report_md
    assert "| `ANN-005` | `framework_mapper` |" in report_md
    assert "#### Validated Annotation Statements" in report_md

    # 5. Held Annotations Queue
    assert "## 5. Held Annotations & Human Review Queue" in report_md
    assert "✓ **Queue Clean:** No annotations were held or rejected." in report_md

    # 6. Risk Governance & Pending Approvals
    assert "## 6. Risk Governance & Pending Approvals" in report_md
    assert "### Active Exceptions in `attack-path-exceptions.yaml`" in report_md

    # 7. Weekly False-Path Sample (M8)
    assert "## 7. Weekly False-Path Sample Protocol (Kit Metric M8)" in report_md
    assert "Kit Metric M8 Governance" in report_md
    assert "False-path rate = `not_reachable / total_paths`" in report_md
    assert "Keep M8 < **10%**" in report_md
    assert "Reachability Verification Checklist:" in report_md
    assert "1. Public Ingress:" in report_md
    assert "### False-Path Dispute Instructions" in report_md
    assert "disposition: not_reachable" in report_md


def test_held_annotations_queue_escalation():
    """When an annotation is held for human review or rejected, it appears in Section 5."""
    ctx = load_appsec_context(CONF_SNAP)
    
    # Inject a held annotation
    held_ann = {
        "annotation_id": "ANN-HELD-001",
        "agent": "path_narrator",
        "path_ref": "PATH-001",
        "status": "human_review",
        "statement": "Workload might be vulnerable to remote command execution.",
        "escalation": {"publish_without_human": 0.45, "threshold": 0.70},
        "review": {"verdict": "needs_review", "issues": [{"claim": "RCE unevidenced"}]},
        "reason": "Escalated for human review: reviewer verdict needs_review, publish p=0.45",
    }
    ctx.ai["annotations"].append(held_ann)

    md = render_appsec_report(ctx, format="markdown")
    assert "⚠️ **Attention AppSec:** 1 annotation(s) held for human review or rejected." in md
    assert "`ANN-HELD-001`" in md
    assert "**HUMAN_REVIEW**" in md
    assert "0.45" in md
    assert "AppSec review of cited evidence" in md


def test_pending_approvals_and_expiring_exceptions():
    """Active exceptions show expiration countdowns and prevent-level second approver flags."""
    ctx = load_appsec_context(CONF_SNAP)
    
    # Inject an expiring exception and an expired exception
    today = dt.date(2026, 10, 9)
    ctx.exceptions = [
        {
            "id": "RISK-SOON",
            "entry": "internet",
            "target": "aws_s3_bucket.customer_data",
            "disposition": "accepted_risk",
            "owner": "alice",
            "expires": "2026-10-15",  # 6 days
            "approved_by": "bob",
        },
        {
            "id": "RISK-EXPIRED",
            "entry": "internet",
            "target": "aws_s3_bucket.logs",
            "disposition": "accepted_risk",
            "owner": "alice",
            "expires": "2026-10-01",  # expired
            "approved_by": "bob",
        },
        {
            "id": "RISK-PREVENT-NEED",
            "entry": "internet",
            "target": "aws_s3_bucket.secrets",
            "disposition": "accepted_risk",
            "owner": "alice",
            "expires": "2026-11-01",
            "approved_by": "alice",  # owner is approver -> invalid at prevent
        },
    ]
    ctx.gate = {"level": "prevent", "decision": "fail", "fail_on": "high", "in_scope": 1, "without_decision": 0, "accepted": 3, "not_reachable": 0}

    md = render_appsec_report(ctx, format="markdown", today=today)
    assert "⚠️ EXPIRING (6d)" in md
    assert "⚠️ EXPIRED" in md
    assert "NEEDS 2ND APPROVER" in md


def test_appsec_report_json_format():
    """Verify structured JSON output includes all domain sections and metadata."""
    out_json = render_appsec_report(CONF_SNAP, format="json")
    data = json.loads(out_json)

    assert data["persona"] == "appsec"
    assert data["scope"] == SCOPE_STATEMENT
    assert "summary" in data
    assert data["summary"]["paths_total"] == 1
    assert data["summary"]["paths_high"] == 1
    assert data["summary"]["scanner_findings_total"] > 0
    assert data["summary"]["pytm_published"] > 0
    assert data["summary"]["ai_annotations_total"] == 5

    assert "paths" in data
    assert len(data["paths"]) == 1
    p0 = data["paths"][0]
    assert p0["id"] == "PATH-001"
    assert len(p0["hops"]) == 4

    assert "dfd" in data
    assert data["dfd"]["nodes_count"] > 0
    assert "visual_files" in data["dfd"]

    assert "pytm" in data
    assert "ai_annotations" in data
    assert "held_annotations" in data
    assert "governance" in data
    assert "false_path_sampling" in data
    assert data["false_path_sampling"]["sample_path_ids"] == ["PATH-001"]


def test_appsec_report_text_format():
    """Verify ASCII plain text format output includes STRIDE, DFD, and file:line per hop (A19)."""
    out_txt = render_appsec_report(CONF_SNAP, format="text")
    assert "APPSEC ARCHITECTURE & ATTACK PATH REVIEW: conference-snapshot" in out_txt
    assert f"Scope: {SCOPE_STATEMENT}" in out_txt
    assert "POSTURE DASHBOARD:" in out_txt
    assert "Attack Paths:       1 total (1 high)" in out_txt
    assert "ATTACK PATHS & HOPS:" in out_txt
    assert "Path PATH-001: internet -> aws_s3_bucket.customer_data" in out_txt
    assert "GOVERNANCE & WEEKLY SAMPLE (M8):" in out_txt

    # Parity checks (Finding F19, Task A19):
    # 1. file:line per hop
    assert "alb.tf:3" in out_txt
    assert "network.tf:" in out_txt
    assert "iam.tf:4" in out_txt
    assert "iam.tf:25" in out_txt

    # 2. DFD & Architecture reference
    assert "DATA FLOW DIAGRAM (DFD) & ARCHITECTURAL MODEL:" in out_txt
    assert "Trust Boundary Crossings in Attack Paths:" in out_txt
    assert "dfd.png (available)" in out_txt
    assert "dfd.svg (available)" in out_txt

    # 3. PyTM Threat Model & STRIDE Analysis
    assert "PYTM THREAT MODEL & STRIDE ANALYSIS:" in out_txt
    assert "STRIDE: Information Disclosure" in out_txt
    assert "STRIDE: Elevation of Privilege" in out_txt
    assert "STRIDE: Tampering" in out_txt
    assert "DE03" in out_txt
    assert "TAPM-EC2-01" in out_txt


def test_appsec_report_sarif_format():
    """Verify SARIF format export for AppSec persona."""
    out_sarif = render_appsec_report(CONF_SNAP, format="sarif")
    sarif = json.loads(out_sarif)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "terraform-attack-paths-pytm"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "TAPM-PATH-HIGH"
    assert res["level"] == "error"
    assert res["properties"]["path_id"] == "PATH-001"
    assert res["properties"]["scope"] == SCOPE_STATEMENT


def test_appsec_report_sarif_validates_against_vendored_schema():
    """Verify SARIF output validates against vendored OASIS SARIF 2.1.0 JSON schema (A19, F19)."""
    import jsonschema
    from tapm.report.sarif import to_sarif

    schema_path = ROOT / "schemas" / "sarif-schema-2.1.0.json"
    assert schema_path.exists(), f"Missing vendored schema at {schema_path}"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    # 1. Validate conference-snapshot committed SARIF file
    snap_sarif_path = CONF_SNAP / "attack-paths.sarif"
    assert snap_sarif_path.exists()
    snap_sarif = json.loads(snap_sarif_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=snap_sarif, schema=schema)

    # 2. Validate live render_appsec_report sarif output
    out_sarif = render_appsec_report(CONF_SNAP, format="sarif")
    sarif_doc = json.loads(out_sarif)
    jsonschema.validate(instance=sarif_doc, schema=schema)

    # 3. Validate empty paths SARIF output
    class MockLedger:
        def by_id(self):
            return {}

    class MockBuild:
        ledger = MockLedger()

    class MockRunRes:
        paths = []
        build = MockBuild()

    empty_sarif = to_sarif(MockRunRes())
    jsonschema.validate(instance=empty_sarif, schema=schema)


def test_cli_tapm_report_persona_appsec(capsys):
    """Test CLI tapm report --persona appsec across formats."""
    from tapm.cli import main

    # 1. Markdown
    main(["report", "--persona", "appsec", str(CONF_SNAP), "--format", "markdown"])
    out_md = capsys.readouterr().out
    assert "# AppSec Architecture & Attack Path Review: `conference-snapshot`" in out_md
    assert "## 1. Attack Paths & Hop-by-Hop Evidence Traces" in out_md

    # 2. JSON
    main(["report", "--persona", "appsec", str(CONF_SNAP), "--format", "json"])
    out_json = capsys.readouterr().out
    doc = json.loads(out_json)
    assert doc["persona"] == "appsec"
    assert doc["summary"]["paths_total"] == 1

    # 3. Text
    main(["report", "--persona", "appsec", str(CONF_SNAP), "--format", "text"])
    out_txt = capsys.readouterr().out
    assert "APPSEC ARCHITECTURE & ATTACK PATH REVIEW:" in out_txt

    # 4. SARIF
    main(["report", "--persona", "appsec", str(CONF_SNAP), "--format", "sarif"])
    out_sarif = capsys.readouterr().out
    sar = json.loads(out_sarif)
    assert sar["version"] == "2.1.0"


def test_pipeline_generates_report_appsec_md(tmp_path):
    """Pipeline execution generates report-appsec.md alongside report.md and story.md."""
    from conftest import DEMO, config_for
    from tapm.pipeline import run

    cfg = config_for(DEMO, tmp_path, no_dfd=False)
    res = run(cfg)

    appsec_file = Path(cfg.out_dir) / "report-appsec.md"
    assert appsec_file.exists(), "report-appsec.md must be generated in out_dir"

    content = appsec_file.read_text(encoding="utf-8")
    assert f"**Scope:** {SCOPE_STATEMENT}" in content
    assert "## 1. Attack Paths & Hop-by-Hop Evidence Traces" in content
    assert "## 7. Weekly False-Path Sample Protocol (Kit Metric M8)" in content
