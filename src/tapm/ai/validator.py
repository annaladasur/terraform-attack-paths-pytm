"""The leash: a deterministic acceptance gate for AI annotations.

    An AI statement without an evidence reference is not a finding.

Every annotation is checked against the ledger and the graph. It is rejected if it

 1. does not match its schema (malformed output),
 2. cites no evidence,
 3. cites an evidence ID that does not exist,
 4. cites evidence that was not in the bundle the agent was given,
 5. references an unknown path,
 6. names a resource that is not in the graph,
 7. names an IAM action that no cited evidence grants (invented permission),
 8. asserts a relationship that is not a graph edge (hallucinated edge),
 9. changes the deterministic priority or severity,
10. claims exploitability the path does not establish,
11. tries to suppress or downplay a deterministic finding,
12. tries to act (shell / terraform / cloud CLI / tool call),
13. maps to a framework identifier outside the controlled vocabulary,
14. repeats an instruction found in an untrusted comment,
15. omits a hop of the path it narrates, or downplays findings through paraphrasing,
16. contains URLs, markdown links/images, or HTML tags (egress / markup injection).

The validator never asks a model anything. Same input, same verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema

from .agents import SCHEMAS

VOCAB = json.loads((Path(__file__).parent / "vocab" / "frameworks.json").read_text())

_ID = re.compile(r"\b(TF|NET|IAM|GRAPH|SCAN|PATH|CMT)-\d{3}\b")
_ADDR = re.compile(r"\b((?:module\.[A-Za-z0-9_-]+(?:\[[^\]]+\])?\.)*(?:data\.)?aws_[a-z0-9_]+\.[A-Za-z0-9_-]+(?:\[[^\]]+\])?)")
_ACTION = re.compile(r"\b([a-z0-9-]{2,}:[A-Z][A-Za-z0-9*]*|[a-z0-9-]{2,}:\*)")
_HCL_RES = re.compile(r'resource\s+"([a-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"')
_CERTAINTY = re.compile(
    r"\b(attackers? (?:can|will) (?:steal|exfiltrate|read|access|obtain|dump)|will be (?:exploited|compromised|breached)|"
    r"(?<!not )is exploitable|has been (?:exploited|compromised|breached)|guaranteed|definitely|"
    r"(?<!not a )(?<!no )proven (?:exploit|breach)|(?<!not a )(?<!no )confirmed (?:breach|exploit))\b", re.I)
_SUPPRESS = re.compile(
    r"\b("
    r"(?:is|are|deemed|considered|marked as) (?:secure|safe|benign|harmless|acceptable|compliant)\b|"
    r"treat as (?:secure|safe|benign|compliant)\b|"
    r"no (?:significant|real|actual|meaningful|material|immediate)? ?(?:risks?|issues?|concerns?|threats?|findings?)(?: (?:were|was))? (?:found|identified|detected)?\b|"
    r"false positive|"
    r"can be (?:safely )?(?:ignored|suppressed|dismissed|bypassed|disregarded|waived)\b|"
    r"(?:ignore|suppress|dismiss|bypass|disregard|waive) (?:this|the) (?:finding|path|alert|issue|warning)\b|"
    r"not a (?:real|actual|true|valid|significant|material)? ?(?:risk|issue|concern|problem|threat|finding)\b|"
    r"low[- ]risk|"
    r"(?:exposure|risk|impact|threat) (?:here )?(?:is|remains) (?:minimal|negligible|trivial|minor|low|immaterial|inconsequential)\b|"
    r"(?:minimal|negligible|trivial|immaterial|inconsequential) (?:exposure|risk|impact|threat)\b|"
    r"within (?:the |our )?(?:approved |acceptable |established )?baseline\b|"
    r"within (?:acceptable |allowable )?(?:tolerance|limits|parameters|thresholds?)\b|"
    r"acceptable risk|"
    r"no action (?:is )?(?:needed|required|necessary|recommended|this sprint|warranted)\b|"
    r"(?:action|remediation|fix) (?:is )?not (?:needed|required|necessary|warranted)\b|"
    r"nothing to (?:fix|remediate|address)\b|"
    r"non[- ]issue|"
    r"(?:does not|doesn't|poses? no|presents? no) (?:pose |present )?(?:any |a )?(?:real |significant )?(?:risk|threat|danger|concern)"
    r")", re.I)
_ESCALATE = re.compile(r"\b(critical|catastrophic|severe)\b", re.I)
_ACTS = re.compile(
    r"(\bterraform\s+(?:apply|destroy|import|state)\b|\baws\s+[a-z0-9-]+\s+[a-z0-9-]+|\brm\s+-rf\b|\bcurl\s+https?://|"
    r"\bgit\s+(?:push|commit)\b|\bsudo\b|\bkubectl\s+(?:apply|delete)\b|\bbash\s+-c\b)", re.I)
_URL = re.compile(r"(?:https?|ftp|file)://|\b(?:javascript|data):", re.I)
_MARKUP = re.compile(r"!\[.*?\]|\[.*?\]\([^\)]*\)|\[.*?\]\[[^\]]*\]")
_HTML = re.compile(r"<\s*/*\s*[a-zA-Z][^>]*>")


@dataclass
class Verdict:
    accepted: bool
    reasons: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)


class Validator:
    def __init__(self, evidence: dict, graph: dict, paths: dict, comments: list[dict] | None = None):
        self.records = {r["id"]: r for r in evidence["records"]}
        self.nodes = {n["id"] for n in graph["nodes"]}
        self.edges = {(e["src"], e["type"], e["dst"]) for e in graph["edges"]}
        self.paths = {p["id"]: p for p in paths.get("paths", [])}
        self.comments = comments or [
            {"id": r["id"], "text": r["data"].get("text", ""), "suspicious": r["data"].get("suspicious")}
            for r in evidence["records"] if r["kind"] == "CMT"]

    @classmethod
    def from_artifacts(cls, art: str | Path) -> "Validator":
        art = Path(art)
        load = lambda n: json.loads((art / n).read_text())
        return cls(load("evidence.json"), load("resource-graph.json"), load("attack-paths.json"))

    @classmethod
    def from_run(cls, res) -> "Validator":
        ev = res.build.ledger.to_json()
        return cls(ev, res.build.graph.to_json(), {"paths": [p.to_json() for p in res.paths]}, res.comments)

    # -------------------------------------------------------------------------
    def validate(self, ann: dict, bundle_ids: set[str] | list[str] | None = None, agent: str | None = None,
                 raw: dict | None = None) -> Verdict:
        """``raw`` is the agent's own output; when given it is schema-checked as-is, so an agent
        cannot smuggle extra fields (for example ``status`` or ``path_ref``) past the gate."""
        reasons: list[str] = []
        checks: dict[str, bool] = {}

        def check(name: str, ok: bool, why: str) -> None:
            checks[name] = ok
            if not ok:
                reasons.append(f"{name}: {why}")

        agent = agent or {v: k for k, v in {
            "path_narrator": "attack_path_explanation", "remediation": "remediation",
            "framework_mapper": "framework_mapping", "finding_explainer": "finding_explanation"}.items()}.get(ann.get("type"))
        body = raw if raw is not None else {k: v for k, v in ann.items() if k in (SCHEMAS.get(agent or "", {}).get("properties") or {})}
        if ann.get("_refusal"):
            check("schema", False, "model refused; nothing to validate")
            return Verdict(False, reasons, checks)
        try:
            if agent in SCHEMAS:
                jsonschema.validate(body, SCHEMAS[agent])
            ok_schema = True
        except jsonschema.ValidationError as e:
            ok_schema = False
            check("schema", False, f"malformed output ({e.message[:120]})")
        if ok_schema:
            checks["schema"] = True
        if not isinstance(ann.get("statement"), str):
            return Verdict(False, reasons or ["schema: statement missing"], checks)

        text = self._all_text(ann)
        refs = ann.get("evidence_refs") if isinstance(ann.get("evidence_refs"), list) else []
        cited_in_text = set(_ID.findall(text)) and {m.group(0) for m in _ID.finditer(text)}
        all_refs = set(refs) | set(cited_in_text or [])

        check("evidence_present", bool(refs), "annotation cites no evidence")
        unknown = sorted(r for r in all_refs if r not in self.records and r not in self.paths)
        check("evidence_exists", not unknown, f"unknown evidence ID(s) {unknown}")
        if bundle_ids is not None:
            outside = sorted(r for r in all_refs if r not in set(bundle_ids) and r not in unknown)
            check("evidence_in_bundle", not outside, f"cites evidence not given to the agent {outside}")

        pref = ann.get("path_ref")
        if pref is not None:
            check("path_exists", pref in self.paths, f"unknown path ID {pref}")

        addrs = sorted({m.group(1) for m in _ADDR.finditer(text)})
        invented = [a for a in addrs if a not in self.nodes and re.sub(r"\[[^\]]+\]$", "", a) not in self.nodes]
        check("resources_exist", not invented, f"names resources not in the graph {invented}")

        granted = self._granted_actions(all_refs)
        acts = sorted({a for a in _ACTION.findall(text) if not a.lower().startswith(("http", "arn", "tf"))})
        bad_acts = [a for a in acts if not self._action_covered(a, granted)]
        check("permissions_exist", not bad_acts, f"names IAM actions no cited evidence grants {bad_acts}")

        rels = ann.get("relationships") or []
        fake = [r for r in rels if (r.get("src"), r.get("type"), r.get("dst")) not in self.edges]
        check("relationships_exist", not fake, f"asserts relationships that are not graph edges {fake}")

        path = self.paths.get(pref) if pref else None
        det = path["priority"] if path else None
        sev = ann.get("severity")
        if sev is not None:
            check("severity_unchanged", det is not None and sev == det, f"severity '{sev}' differs from deterministic priority '{det}'")
        if det or (path is None and ann.get("type") == "finding_explanation"):
            check("no_suppression", not _SUPPRESS.search(text),
                  "downplays or suppresses a deterministic finding")
        if det and det != "high":
            # quoting a scanner's own severity label, e.g. "(tfsec rule-x, critical)", is not escalation
            own = re.sub(r"\([^)]*\b(?:checkov|tfsec|trivy|CKV\w*|AWS-\d+)\b[^)]*\)", "", ann["statement"], flags=re.I)
            check("no_severity_escalation", not _ESCALATE.search(own),
                  f"escalates wording beyond deterministic priority '{det}'")
        if path is None or path.get("preconditions"):
            check("no_exploit_claim", not _CERTAINTY.search(text), "claims exploitability the path does not establish")

        check("no_actions", not _ACTS.search(text) and not any(k in ann for k in ("tool_calls", "tool_use", "commands")),
              "attempts to act (shell, terraform, cloud CLI or tool call)")

        if ann.get("terraform_example"):
            blocks = _HCL_RES.findall(ann["terraform_example"])
            new = [f"{t}.{n}" for t, n in blocks if f"{t}.{n}" not in self.nodes]
            check("remediation_targets_existing", not new, f"remediation introduces resources not in the plan {new}")

        for m in ann.get("mappings") or []:
            fw = VOCAB.get(m.get("framework"), {})
            known = m.get("id") in (fw.get("ids") or {})
            check("framework_ids_known", known, f"unknown framework identifier {m.get('framework')} {m.get('id')}")
            if known and not m.get("evidence_refs"):
                check("framework_mapping_evidence", False, f"mapping {m.get('id')} has no evidence")
            if not known:
                break

        echoes = [c["id"] for c in self.comments if c.get("suspicious") and _overlap(c.get("text", ""), ann["statement"])]
        check("no_untrusted_echo", not echoes, f"repeats instructions from untrusted comments {echoes}")

        # Check 15: a narration must cite every hop of its path (catches omission, e.g. "don't mention IAM")
        is_narration = (agent == "path_narrator" or ann.get("type") == "attack_path_explanation")
        if is_narration and path:
            missing_hops = []
            for i, h in enumerate(path.get("hops", []), start=1):
                hop_ev = ({h.get("edge")} | set(h.get("evidence", []))) - {None, ""}
                hop_rel = (h.get("src"), h.get("type"), h.get("dst"))
                rel_set = {(r.get("src"), r.get("type"), r.get("dst")) for r in (ann.get("relationships") or [])}
                has_ev = bool(all_refs & hop_ev)
                has_rel = hop_rel in rel_set if ann.get("relationships") is not None else True
                if not (has_ev and has_rel):
                    missing_hops.append(f"hop {i} ({h.get('src')} -> {h.get('dst')})")
            check("all_hops_cited", not missing_hops, f"narration omits path hops: {', '.join(missing_hops)}")

        # Check 16: no URLs, markdown links/images or HTML in AI statements (external egress / markup injection)
        has_markup = bool(_URL.search(text) or _MARKUP.search(text) or _HTML.search(text))
        check("no_markup_or_links", not has_markup, "statement contains URL, markdown link/image or HTML tags")

        return Verdict(not reasons, reasons, checks)

    # -------------------------------------------------------------------------
    @staticmethod
    def _all_text(ann: dict) -> str:
        parts = [ann.get("statement", "")]
        for k in ("recommended_change", "expected_effect", "tradeoff", "what_is_wrong", "why_it_matters", "terraform_example"):
            if isinstance(ann.get(k), str):
                parts.append(ann[k])
        for m in ann.get("mappings") or []:
            parts.append(str(m.get("rationale", "")))
        return "\n".join(parts)

    def _granted_actions(self, refs: set[str]) -> set[str]:
        seen: set[str] = set()
        frontier = set(refs)
        acts: set[str] = set()
        for _ in range(3):
            nxt = set()
            for r in frontier:
                if r in seen:
                    continue
                seen.add(r)
                rec = self.records.get(r)
                if rec is None and r in self.paths:
                    nxt.update(h["edge"] for h in self.paths[r]["hops"])
                    continue
                if not rec:
                    continue
                d = rec.get("data") or {}
                acts.update(d.get("actions") or [])
                acts.update((d.get("statement") or {}).get("actions") or [])
                nxt.update(rec.get("refs") or [])
            frontier = nxt
        return acts

    @staticmethod
    def _action_covered(action: str, granted: set[str]) -> bool:
        from ..util import glob_to_regex

        for g in granted:
            if g.lower() == action.lower():
                return True
            if "*" in g and glob_to_regex(g, case_insensitive=True).match(action):
                return True
            if "*" in action and action.lower() == g.lower():
                return True
        return False


def _overlap(a: str, b: str, n: int = 5) -> bool:
    """True if ``b`` contains any run of ``n`` consecutive words from ``a``."""
    wa = re.findall(r"[a-z0-9]+", a.lower())
    wb = " " + " ".join(re.findall(r"[a-z0-9]+", b.lower())) + " "
    return any(f" {' '.join(wa[i:i + n])} " in wb for i in range(0, max(0, len(wa) - n + 1)))
