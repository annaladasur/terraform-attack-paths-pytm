"""PR security report (Markdown, GitHub-flavoured, Mermaid path diagrams).

Rules the report follows (Plan §34-35):
* lead with the path count, not the finding count;
* say "plausible path" and name the precondition; never claim exploitation;
* every statement about the infrastructure carries an evidence ID;
* AI text appears only in its own section and only if the validator accepted it.
"""

from __future__ import annotations

from collections import Counter
import re

from .. import SCOPE_STATEMENT
from ..paths.engine import PRECONDITIONS as PRECONDITION_TEXT
from ..graph.model import INTERNET


def escape_statement(text: str) -> str:
    """Escape an AI statement for safe markdown PR comments (W0.2).

    Neutralizes markdown images, links, and HTML tags so that statements
    cannot be used as an exfiltration or markup injection channel.
    """
    if not text:
        return ""
    s = text.replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"!\[(.*?)\]\((.*?)\)", r"\\![\1](\2)", s)
    s = re.sub(r"(?<!\\!)\[(.*?)\]\((.*?)\)", r"\\[\1](\2)", s)
    return s


def _loc(src: dict | None) -> str:
    if not src or not src.get("file"):
        return ""
    a, b = src.get("start_line"), src.get("end_line")
    return f"{src['file']}:{a}" + (f"-{b}" if b and b != a else "")


def _short(node: str) -> str:
    return "Internet" if node == INTERNET else node


def _pytm_on_path(cls: dict | None, path_id: str) -> list[tuple[int, dict]]:
    out = []
    for r in (cls or {}).get("findings", []):
        if r["class"] in ("confirmed", "mitigated"):
            out += [(o["hop"], r) for o in r.get("on_paths", []) if o["path"] == path_id]
    return sorted(out, key=lambda x: (x[0], x[1]["threat_id"], x[1]["element"]))


def _pytm_section(w, cls: dict) -> None:
    s = cls["summary"]
    rows = cls["findings"]
    w("## PyTM threat model, fed with plan evidence")
    w("")
    w(f"`threat-model.py` is plain OWASP pytm. Controls the plan decides are set with the evidence behind them "
      f"(`pytm-controls.json`); everything else keeps pytm's default and is reported as undecided. pytm's threat "
      f"library plus a {len(s['pack_threats'])}-threat cloud pack (`threat-library.json`) then gives:")
    w("")
    w("| | Threats |")
    w("|---|---|")
    w(f"| Architecture only (the same model, no evidence-fed controls) | {s['generic']} |")
    w(f"| **Decided by the plan**: fire whatever the undecided controls are | **{s['confirmed']}**"
      + (f" (+{s['mitigated']} mitigated by an evidence-backed override)" if s["mitigated"] else "") + " |")
    w(f"| Questions for the app team: depend on controls Terraform cannot show | {s['needs_app_team']} |")
    w(f"| Ruled out by the plan (reported by the architecture-only model) | {s['ruled_out']} |")
    w("")
    ask: dict[str, set] = {}
    for r in rows:
        if r["class"] == "needs_app_team":
            for a in r["undecided"]:
                ask.setdefault(a, set()).add(r["threat_id"])
    if ask:
        top = sorted(ask.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:6]
        w("Most-asked undecided controls: " + " · ".join(f"`{a}` ({len(t)} threats)" for a, t in top) + ".")
        w("")
    ruled = [r for r in rows if r["class"] == "ruled_out"]
    decided = [r for r in rows if r["class"] in ("confirmed", "mitigated")]
    if decided or ruled:
        w("<details><summary>Decided and ruled-out threats, with the evidence</summary>")
        w("")
        w("| Class | Threat | Element | Decided by |")
        w("|---|---|---|---|")
        for r in decided + ruled:
            why = "; ".join(f"`{a.split('.')[-1]} = {v['value']}` ({', '.join(v['evidence']) or 'model'})" for a, v in r["decided"].items())
            if r.get("assumption"):
                why = f"assumption: {r['assumption']}"
            w(f"| {r['class'].replace('_', ' ')} | {r['threat_id']}: {r['description']} | `{r['element']}` | {why} |")
        w("")
        w("</details>")
        w("")


def _questions_section(w, q: dict, cls: dict | None, k: int = 6) -> None:
    from ..pytm_gen.questions import answer_effect

    shown = q["questions"][:k]
    if not shown and not q.get("answers"):
        return
    w("## Questions for the app team")
    w("")
    settled = shown[-1]["cumulative"] if shown else 0
    w(f"pytm has {q['open']} open threats that depend on things Terraform cannot show. "
      + (f"These {len(shown)} yes/no questions settle {settled} of them, whatever the answers are. " if shown else "")
      + "Answer in `threat-answers.yaml` next to the Terraform; each answer becomes an `APP-###` evidence record and "
        "the threat model is re-evaluated. Answers never change an attack path.")
    w("")
    if shown:
        w("| # | Question | Why it matters | Settles |")
        w("|---|---|---|---|")
        for x in shown:
            w(f"| {x['n']} | {x['question']} | {x['why']} | {x['settles']} |")
        for x in q.get("data_questions", []):
            w(f"| · | {x['question']} | {x['why']} | informs {x['informs']} |")
        w("")
    if q.get("answers"):
        eff = answer_effect(cls) if cls else {"confirmed": 0, "ruled_out": 0}
        w(f"**Answers applied** ({eff['ruled_out']} threats ruled out by a yes, {eff['confirmed']} confirmed by a no):")
        w("")
        for a in q["answers"]:
            ans = "yes" if a["answer"] else "no" if a["answer"] is not None else "?"
            w(f"- `{a['element']}` {a['control']} = **{ans}** ({a['by'] or 'unknown'}) · {a['status']}"
              + (f" · {', '.join(a['evidence'])}" if a["evidence"] else ""))
        w("")


def _remediation_section(w, doc: dict) -> None:
    s = doc["summary"]
    w("## Verified remediation (AI proposes, the pipeline proves)")
    w("")
    w(f"Patch author: `{doc['manifest']['patch_author']}`. Each proposal passed a deterministic edit policy, was applied to a "
      f"copy, re-planned offline and run through the whole pipeline and pytm again. Accepted only if: "
      f"{doc['manifest']['acceptance']}. **Nothing was applied to this repository.**")
    w("")
    w(f"{s['verified_break']} of {s['paths']} path(s) with a verified fix that breaks them · "
      f"{s['verified_downgrade_only']} with a verified downgrade only · {s['rejected']} proposal(s) rejected"
      + (f" · {s['unverified']} not verifiable here (no plan)" if s["unverified"] else ""))
    w("")
    for p in doc["paths"]:
        w(f"**{p['path']}**: {p['result'].replace('_', ' ').lower()}")
        w("")
        w("| # | Hop | Proposed change | Result | Why |")
        w("|---|---|---|---|---|")
        for a in p["attempts"]:
            pt = a["patch"]
            change = f"`{pt.get('file', '')}`: `{(pt.get('replace') or '').strip()[:80]}`".replace("|", "\\|").replace("\n", " ")
            if a["status"] in ("PROVEN_BREAK", "PROVEN_DOWNGRADE", "ROUTE_BROKEN"):
                why = {"breaks_path": "path gone after re-planning", "breaks_route": "route gone; other paths remain",
                       "downgrades_path": f"{a['priority_before']} → {a['priority_after']}"}[a["effect"]]
                py = (a.get("pytm") or {}).get("resolved")
                why += "; no new paths" + (f"; pytm resolved {', '.join(sorted({x.split(' on ')[0] for x in py}))}" if py else "")
            else:
                why = "; ".join(a["reasons"])[:160].replace("|", "\\|")
            w(f"| {a['n']} | {pt.get('hop', '')} | {change} | {a['status']} | {why} |")
        w("")
        if p["recommended_diff"]:
            w(f"Verified patch (`remediation-{p['path']}.diff`), for a human to review and apply:")
            w("")
            w("```diff")
            w(p["recommended_diff"].rstrip("\n"))
            w("```")
            w("")


def _plain_section(w, res, k: int = 3) -> None:
    """One screen per path for someone who has never done threat modeling (report/story.py)."""
    from .story import path_story, render_story

    w("## In plain words")
    w("")
    w("> What the paths below mean, without threat-modeling vocabulary. Every sentence is built from the same "
      "evidence as the tables; nothing here comes from a model.")
    w("")
    for p in res.paths[:k]:
        w(f"### {p.id}")
        w("")
        w(render_story(path_story(res, p, "developer")).rstrip("\n"))
        w("")
    if len(res.paths) > k:
        w(f"*{len(res.paths) - k} more path(s) below; `tapm story <fixture>` tells each one.*")
        w("")


def render_report(res) -> str:
    """Render developer PR comment v2 (W3.1)."""
    from .developer import render_developer_comment
    return render_developer_comment(res)


def render_legacy_report(res) -> str:
    b = res.build
    recs = b.ledger.by_id()
    paths = res.paths
    findings = res.findings
    n_res = sum(1 for n in b.graph.nodes.values() if not n.synthetic)
    n_mod = sum(1 for n in b.graph.nodes.values() if not n.synthetic and n.modeled)
    by_tool = Counter(f.tool for f in findings)
    causal = [f for f in findings if f.causal_paths]
    pri = Counter(p.priority for p in paths)
    cls = res.pytm.get("classification")
    L: list[str] = []
    w = L.append

    w(f"# Security architecture review: {res.cfg.name}")
    w("")
    w("> Deterministic analysis of the Terraform plan. Paths, edges and priorities come from code, not a model.")
    w("> AI annotations, if enabled, appear in their own section and only after passing evidence validation.")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| Resources in plan | {n_res} ({n_mod} modeled) |")
    tools = " · ".join(f"{t.capitalize() if t != 'tfsec' else 'tfsec'} {by_tool[t]}" for t in ("checkov", "tfsec", "trivy") if t in by_tool)
    w(f"| Scanner findings | {len(findings)}" + (f" ({tools})" if tools else "") + " |")
    w(f"| Findings on attack-path hops | {len(causal)} |")
    w(f"| Attack paths | {len(paths)}" + (f" ({', '.join(f'{pri[k]} {k}' for k in ('high', 'medium', 'low') if pri[k])})" if paths else "") + " |")
    if cls:
        cs = cls["summary"]
        pack = f" ({cs['pack']} from the cloud pack)" if cs.get("pack") else ""
        w(f"| PyTM threats, fed with plan evidence | {cs['published']}: **{cs['confirmed'] + cs['mitigated']} decided by the plan**{pack} · "
          f"{cs['needs_app_team']} questions for the app team. Of the architecture-only model's {cs['generic']}, {cs['ruled_out']} are ruled out |")
    elif res.pytm.get("threat_count") is not None:
        w(f"| PyTM generic threats (for reference) | {res.pytm['threat_count']} |")
    suspicious = [c for c in res.comments if c["suspicious"]]
    if suspicious:
        w(f"| Untrusted comments flagged as instructions | {len(suspicious)} |")
    w("")

    if not paths:
        w("**No attack path** from an internet-reachable entry to a classified asset was found in this plan.")
        w("")
    else:
        _plain_section(w, res)
    for p in paths:
        w(f"## {p.id} · {p.priority.upper()} · {p.status}")
        w("")
        w("**" + " → ".join(_short(n) for n in p.nodes) + f"** ({p.target_sensitivity} asset)")
        w("")
        w("| # | Hop | Status | Evidence |")
        w("|---|---|---|---|")
        for i, h in enumerate(p.hops, start=1):
            ev = []
            for e in h.evidence:
                r = recs.get(e)
                if r and r.kind in ("NET", "IAM") or (r and r.kind == "TF" and "http_tokens" in (r.data or {})):
                    ev.append(f"{e} `{_loc(r.source)}`")
            status = h.status + (f" ({h.precondition})" if h.precondition else "")
            label = f"({h.label})" if h.label else ""
            w(f"| {i} | {_short(h.src)} —{h.type}{label}→ {_short(h.dst)} | {status} | {h.edge}" + (f"; {', '.join(ev)}" if ev else "") + " |")
        w("")
        for pre in p.preconditions:
            w(f"**Precondition `{pre}`:** {PRECONDITION_TEXT.get(pre, pre)}")
            w("")
        w("This is a *plausible* path assembled from configuration evidence. It does not prove that an exploit exists.")
        w("")
        confirmed = _pytm_on_path(cls, p.id)
        if confirmed:
            w("**PyTM threats the plan confirms on this path's hops:**")
            w("")
            w("| Hop | Threat | Element | Decided by |")
            w("|---|---|---|---|")
            for hop, r in confirmed:
                why = "; ".join(f"`{a.split('.')[-1]} = {v['value']}` ({', '.join(v['evidence']) or 'model'})" for a, v in r["decided"].items())
                tag = " (mitigated)" if r["class"] == "mitigated" else ""
                w(f"| {hop} | {r['threat_id']}: {r['description']}{tag} | `{r['element']}` | {why} |")
            w("")
        on = [f for f in findings if p.id in f.causal_paths]
        if on:
            w(f"**Scanner findings on this path's hops** ({len(on)} of {len(findings)}):")
            w("")
            w("| Evidence | Tool | Rule | Severity | Resource | Location |")
            w("|---|---|---|---|---|---|")
            for f in sorted(on, key=lambda f: (f.node or "", f.tool, f.rule_id)):
                w(f"| {f.id} | {f.tool} | `{f.rule_id}` | {f.severity} | `{f.resource}` | `{f.file}:{f.start_line}` |")
            w("")
        rem = [r for r in res.remedies if r.path == p.id]
        if rem:
            w("**Remediation options (effect computed by re-running the path engine):**")
            w("")
            for r in rem:
                eff = {"breaks_path": "breaks this path",
                       "downgrades_path": f"downgrades priority {r.before} → {r.after}",
                       "no_effect": "no change in priority",
                       "breaks_path_but_alternative_exists": f"breaks this route; {r.remaining_paths_to_target} alternative path(s) remain"}[r.effect]
                w(f"- Hop {r.hop}: {r.change}. *Effect:* {eff}.")
            w("")
        # the same numbering as the hop table and pytm's own --seq diagram (seq.puml): dashed arrows are assumptions
        w("```mermaid")
        w("sequenceDiagram")
        w("  autonumber")
        for i, n in enumerate(p.nodes):
            w(f"  participant n{i} as {_short(n)}")
        for i, h in enumerate(p.hops):
            arrow = "-->>" if h.status == "ASSUMPTION" else "->>"
            label = f"{h.type}{' ' + h.label if h.label else ''} [{h.edge}]"
            w(f"  n{i}{arrow}n{i + 1}: {label}")
            if h.precondition:
                w(f"  Note over n{i},n{i + 1}: ASSUMPTION: {h.precondition}")
        w("```")
        w("")

    if cls:
        _pytm_section(w, cls)
    if res.pytm.get("questions"):
        _questions_section(w, res.pytm["questions"], cls)
    if getattr(res, "remediation", None):
        _remediation_section(w, res.remediation)

    # AI section
    if res.ai:
        s = res.ai["summary"]
        w("## AI annotations (bounded, evidence-validated)")
        w("")
        w(f"{s['generated']} generated · {s['accepted']} evidence-backed and accepted · {s['rejected']} rejected · "
          f"{s['human_review']} routed to human review · backend `{res.ai['manifest']['llm_backend']}`, "
          f"decision layer `{res.ai['manifest']['jev_backend']}`")
        w("")
        for a in res.ai["annotations"]:
            if a["status"] != "accepted":
                continue
            w(f"- **{a['annotation_id']}** ({a['type']}, {a.get('path_ref') or a.get('target_ref') or ''}): {escape_statement(a['statement'])}  ")
            w(f"  Evidence: {', '.join(a['evidence_refs'])}")
        rej = [a for a in res.ai["annotations"] if a["status"] != "accepted"]
        if rej:
            w("")
            w("<details><summary>Rejected or held annotations</summary>")
            w("")
            for a in rej:
                w(f"- {a['annotation_id']} ({a['type']}): **{a['status']}** — {escape_statement('; '.join(a.get('rejections', [])) or a.get('reason', ''))}")
            w("")
            w("</details>")
        w("")

    if suspicious:
        w("## Untrusted source comments")
        w("")
        w("Comments are recorded as untrusted metadata. They cannot change the graph, the paths or any priority, and they are "
          "not sent to the AI agents as instructions. These read like instructions to an AI reviewer:")
        w("")
        for c in suspicious:
            text = c["text"].replace("\n", " ")
            w(f"- {c['id']} `{c['file']}:{c['line']}` ({c['anchor'] or 'file'}): “{text[:140]}” — patterns: {', '.join(c['patterns'])}")
        w("")

    other = [f for f in findings if not f.causal_paths]
    if other:
        w("<details><summary>Scanner findings not on any attack-path hop (" + str(len(other)) + ")</summary>")
        w("")
        w("| Evidence | Tool | Rule | Severity | Resource |")
        w("|---|---|---|---|---|")
        for f in sorted(other, key=lambda f: (f.tool, f.rule_id, f.resource)):
            w(f"| {f.id} | {f.tool} | `{f.rule_id}` | {f.severity} | `{f.resource}` |")
        w("")
        w("</details>")
        w("")

    if b.notes or b.unresolved_policies:
        w("<details><summary>Analysis notes and unresolved inputs</summary>")
        w("")
        for n in sorted(b.notes, key=lambda n: (n["resource"], n["note"])):
            w(f"- `{n['resource']}`: {n['note']}")
        for u in b.unresolved_policies:
            w(f"- unresolved policy: {u}")
        w("")
        w("</details>")
        w("")

    w("---")
    w(f"**Scope:** {SCOPE_STATEMENT}")
    w("")
    w(f"Deterministic artifact hashes: graph `{res.hashes.get('resource-graph.json', '')[:12]}` · "
      f"paths `{res.hashes.get('attack-paths.json', '')[:12]}` · evidence `{res.hashes.get('evidence.json', '')[:12]}` · "
      f"PyTM `{res.hashes.get('threat-model.py', '')[:12]}`")
    return "\n".join(L) + "\n"
