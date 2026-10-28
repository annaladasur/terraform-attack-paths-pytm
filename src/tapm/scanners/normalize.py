"""Normalise scanner output into SCAN records and join them to graph nodes and paths."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..graph.build import BuildResult
from ..terraform.source import SourceIndex

# Which evidence "concern" a scanner rule speaks to. Used only to decide whether a
# finding lies on a *causal* hop of an attack path; rules not listed fall back to
# precise line overlap. IDs are the tools' own identifiers.
CONCERNS: dict[str, str] = {
    # IMDSv1
    "CKV_AWS_79": "imds", "aws-ec2-enforce-http-token-imds": "imds", "AWS-0028": "imds",
    # internet-wide ingress
    "CKV_AWS_24": "public_ingress", "CKV_AWS_25": "public_ingress", "CKV_AWS_260": "public_ingress",
    "CKV_AWS_277": "public_ingress", "aws-ec2-no-public-ingress-sgr": "public_ingress", "AWS-0107": "public_ingress",
    # internet-facing load balancer
    "aws-elb-alb-not-public": "public_lb", "AWS-0053": "public_lb",
    # public instance / database
    "CKV_AWS_88": "public_ip", "aws-ec2-no-public-ip": "public_ip", "AWS-0009": "public_ip",
    "CKV_AWS_17": "public_db", "aws-rds-no-public-db-access": "public_db", "AWS-0180": "public_db",
    # IAM breadth
    "aws-iam-no-policy-wildcards": "iam_wildcard", "AWS-0057": "iam_wildcard",
    "CKV_AWS_288": "iam_wildcard", "CKV_AWS_290": "iam_wildcard", "CKV_AWS_355": "iam_wildcard",
    "CKV_AWS_289": "iam_wildcard", "CKV_AWS_286": "iam_wildcard", "CKV_AWS_287": "iam_wildcard",
    "CKV_AWS_62": "iam_wildcard", "CKV_AWS_63": "iam_wildcard", "CKV2_AWS_40": "iam_wildcard",
    "CKV_AWS_60": "iam_trust", "CKV_AWS_61": "iam_trust",
    # public buckets
    "CKV_AWS_20": "public_bucket", "CKV_AWS_57": "public_bucket", "CKV_AWS_70": "public_bucket",
    "CKV2_AWS_6": "public_bucket", "CKV_AWS_53": "public_bucket", "CKV_AWS_54": "public_bucket",
    "CKV_AWS_55": "public_bucket", "CKV_AWS_56": "public_bucket",
    "aws-s3-block-public-acls": "public_bucket", "aws-s3-block-public-policy": "public_bucket",
    "aws-s3-ignore-public-acls": "public_bucket", "aws-s3-no-public-buckets": "public_bucket",
    "aws-s3-no-public-access-with-acl": "public_bucket", "aws-s3-specify-public-access-block": "public_bucket",
    "AWS-0086": "public_bucket", "AWS-0087": "public_bucket", "AWS-0091": "public_bucket",
    "AWS-0092": "public_bucket", "AWS-0093": "public_bucket", "AWS-0094": "public_bucket",
    # lambda url
    "CKV_AWS_258": "public_function",
}

SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str
    title: str
    resource: str
    file: str
    start_line: int
    end_line: int
    node: str | None = None
    concern: str | None = None
    id: str | None = None
    paths: list[str] = field(default_factory=list)
    causal_paths: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return self.__dict__.copy()


def load_findings(baseline_dir: str | Path) -> list[Finding]:
    d = Path(baseline_dir)
    out: list[Finding] = []
    if (d / "checkov.json").exists():
        data = json.loads((d / "checkov.json").read_text())
        for block in data if isinstance(data, list) else [data]:
            if not isinstance(block, dict):
                continue
            for f in (block.get("results") or {}).get("failed_checks", []):
                rng = f.get("file_line_range") or [0, 0]
                out.append(Finding("checkov", f["check_id"], SEVERITY.get(str(f.get("severity")).upper(), "unrated"),
                                   f.get("check_name", ""), f.get("resource", ""), f.get("file_path", "").lstrip("/"),
                                   int(rng[0]), int(rng[1])))
    if (d / "tfsec.json").exists():
        data = json.loads((d / "tfsec.json").read_text())
        for f in data.get("results") or []:
            loc = f.get("location") or {}
            out.append(Finding("tfsec", f.get("long_id") or f.get("rule_id"), SEVERITY.get(f.get("severity", ""), "unrated"),
                               f.get("description", ""), f.get("resource", ""), loc.get("filename", ""),
                               int(loc.get("start_line") or 0), int(loc.get("end_line") or 0)))
    if (d / "trivy.json").exists():
        data = json.loads((d / "trivy.json").read_text())
        for r in data.get("Results") or []:
            for m in r.get("Misconfigurations") or []:
                if m.get("Status") != "FAIL":
                    continue
                cm = m.get("CauseMetadata") or {}
                out.append(Finding("trivy", m.get("ID") or m.get("AVDID"), SEVERITY.get(m.get("Severity", ""), "unrated"),
                                   m.get("Title", ""), cm.get("Resource", ""), r.get("Target", ""),
                                   int(cm.get("StartLine") or 0), int(cm.get("EndLine") or 0)))
    for f in out:
        f.file = _rel(f.file, d.parent)
        f.concern = CONCERNS.get(f.rule_id)
    out.sort(key=lambda f: (f.tool, f.file, f.start_line, f.rule_id, f.resource))
    return out


def _rel(path: str, fixture_dir: Path) -> str:
    """Scanner paths -> paths relative to the Terraform directory."""
    if path.startswith("./"):
        path = path[2:]
    p = Path(path)
    if p.is_absolute():
        try:
            return str(p.relative_to(fixture_dir.resolve()))
        except ValueError:
            marker = f"/{fixture_dir.name}/"
            return path.split(marker, 1)[1] if marker in path else p.name
    return path


def attach(result: BuildResult, findings: list[Finding]) -> None:
    """Map each finding to a graph node and register SCAN records in the ledger."""
    src: SourceIndex = result.source
    nodes = result.graph.nodes
    for f in findings:
        if f.resource in nodes:
            f.node = f.resource
        else:
            for addr, b in src.blocks.items():
                if b.file == f.file and b.start <= f.start_line <= max(b.end, b.start):
                    if addr in nodes:
                        f.node = addr
                    else:
                        inst = [n for n in nodes if n.startswith(addr + "[")]
                        f.node = inst[0] if inst else None
                    break
    for f in sorted(findings, key=lambda f: (f.tool, f.rule_id, f.resource, f.file, f.start_line)):
        f.id = result.ledger.append(
            "SCAN", (f.tool, f.rule_id, f.resource, f.file, f.start_line),
            f"{f.tool} {f.rule_id} ({f.severity}) on {f.resource}: {f.title}",
            source={"file": f.file, "start_line": f.start_line, "end_line": f.end_line},
            data={"tool": f.tool, "rule_id": f.rule_id, "severity": f.severity, "node": f.node, "concern": f.concern},
            refs=[result.ledger.id_of(result.tf[f.node])] if f.node in result.tf else [])


def _overlap(a: dict | None, f: Finding) -> bool:
    if not a or a.get("file") != f.file:
        return False
    return not (f.end_line < a["start_line"] or f.start_line > a["end_line"])


def evidence_concern(rec) -> str | None:
    d = rec.data or {}
    if rec.kind == "NET":
        if d.get("internet") or d.get("public_cidrs"):
            return "public_ingress"
        if "internet-facing" in rec.summary:
            return "public_lb"
        if "public address" in rec.summary:
            return "public_ip"
        if "publicly_accessible" in rec.summary:
            return "public_db"
        if "acl =" in rec.summary:
            return "public_bucket"
        if "authorization_type = NONE" in rec.summary:
            return "public_function"
    if rec.kind == "TF" and "http_tokens" in d:
        return "imds"
    if rec.kind == "IAM":
        st = d.get("statement", {})
        if d.get("policy_kind") == "trust":
            return "iam_trust"
        if d.get("policy_kind") == "resource" and "*" in str(st.get("principals", {})):
            return "public_bucket"
        if any("*" in r for r in st.get("resources", [])) or any("*" in a for a in st.get("actions", [])) or st.get("not_actions"):
            return "iam_wildcard"
        return "iam_grant"
    return None


def join_paths(result: BuildResult, findings: list[Finding], paths) -> None:
    """A finding is *on* a path if it targets a path node or a resource cited by the path's
    evidence; it is *causal* if it speaks to the same concern as a hop's evidence."""
    recs = result.ledger.by_id()
    tf_addr = {r.id: (r.key[0] if r.key else None) for r in recs.values() if r.kind == "TF"}
    for p in paths:
        closure: set[str] = set()
        frontier = set(p.evidence)
        for _ in range(3):
            nxt = set()
            for eid in frontier:
                if eid in closure or eid not in recs:
                    continue
                closure.add(eid)
                nxt.update(recs[eid].refs)
            frontier = nxt
        addrs = {tf_addr[e] for e in closure if e in tf_addr} | set(p.nodes)
        fine = [recs[e] for e in closure if recs[e].kind in ("NET", "IAM") or (recs[e].kind == "TF" and "http_tokens" in (recs[e].data or {}))]
        concerns = {(evidence_concern(r), _node_of(r, tf_addr)) for r in fine}
        for f in findings:
            if f.node not in addrs:
                continue
            f.paths.append(p.id)
            causal = False
            if f.concern:
                causal = any(c == f.concern for c, _ in concerns)
            else:
                narrow = [r for r in fine if _overlap(r.source, f)]
                causal = bool(narrow) and (f.end_line - f.start_line) <= 3
            if causal:
                f.causal_paths.append(p.id)
                p.findings.append(f.id)
        p.findings = sorted(set(p.findings))


def _node_of(rec, tf_addr) -> str | None:
    for r in rec.refs:
        if r in tf_addr:
            return tf_addr[r]
    return None
