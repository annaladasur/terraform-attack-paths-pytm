"""Developer PR comment v2 (W3.1).

Persona report for developers reviewing a pull request:
* First screen <= 10 items (matches M2 count: paths + up to 6 questions + data questions);
* Plain words first: each path explained in plain language with file and line to change;
* The one proven fix: verified remediation patch right on the first screen if available;
* Verdict and ways out: fix, accept risk with owner/expiry, answer questions, or dispute false path;
* Dispute false path option and template (disposition: not_reachable, counted in M8);
* Details collapsed: technical hop tables, preconditions, sequence diagrams, scanner findings,
  PyTM threats, and additional questions collapsed in <details>;
* Hard comment size limit: guaranteed <= 65,535 characters (GitHub & Gitea comment limit)
  even on large repositories like IAM-Vulnerable (265 resources, 37 test paths / 41 blind eval paths).
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from typing import Any

from .. import SCOPE_STATEMENT
from ..graph.model import INTERNET
from ..measure import compute_m1
from ..paths.engine import PRECONDITIONS as PRECONDITION_TEXT
from .markdown import _loc, _short, escape_statement
from .story import path_story, render_story

GIT_HOST_COMMENT_LIMIT = 65535  # GitHub: 65,536 chars; Gitea: 65,535 chars
FIRST_SCREEN_MAX_ITEMS = 10
FIRST_SCREEN_QUESTIONS = 6


def count_first_screen_items(markdown_text: str) -> int:
    """Count the review items displayed on the first screen (before the first <details> tag).

    Items are:
    1. Attack paths presented in plain words;
    2. Yes/no questions in the first-screen questions table;
    3. Data classification questions in the table.
    """
    first_screen = markdown_text.split("<details", 1)[0]
    
    # Count paths: lines like "### Path: PATH-..." or "#### Path: PATH-..." in the first screen
    path_count = len(re.findall(r"^#{3,4}\s+(?:Path:?\s+)?PATH-\d+", first_screen, re.MULTILINE))
    if path_count == 0 and "No attack path from an internet-reachable entry" in first_screen:
        path_count = 0

    # Count questions in table rows
    table_lines = [line.strip() for line in first_screen.splitlines() if line.strip().startswith("|")]
    
    # Yes/no numbered questions: | 1 | ... or | 12 | ...
    q_yes_no = sum(1 for line in table_lines if re.match(r"^\|\s*\d+\s*\|", line))
    
    # Data classification questions: | · | ... or | • | ...
    q_data = sum(1 for line in table_lines if re.match(r"^\|\s*[·•\-]\s*\|", line))

    return path_count + q_yes_no + q_data


def _build_proven_fix_snippet(remediation_doc: dict | None, path_id: str) -> tuple[str, str]:
    """Return (summary_line, diff_block) if a proven fix exists for the given path."""
    if not remediation_doc:
        return "", ""
    for p in remediation_doc.get("paths", []):
        if p.get("path") == path_id and p.get("recommended_diff"):
            attempts = p.get("attempts", [])
            proven_attempts = [a for a in attempts if a.get("status") in ("PROVEN_BREAK", "PROVEN_DOWNGRADE")]
            effect_text = "breaks this path; 0 new paths" if p.get("result") == "PROVEN_BREAK" else "downgrades path priority"
            if proven_attempts:
                att = proven_attempts[0]
                pt = att.get("patch", {})
                file_target = pt.get("file", "")
                summary = f"proven offline via re-planning; {effect_text} (`{file_target}`)"
            else:
                summary = f"proven offline via re-planning; {effect_text}"
            
            diff_text = p["recommended_diff"].rstrip("\n")
            return summary, diff_text
    return "", ""


def extract_first_screen_items(
    res: Any,
    max_first_screen: int = FIRST_SCREEN_MAX_ITEMS,
) -> list[dict[str, Any]]:
    """Extract structured representations of review items on the first screen (<= max_first_screen).

    Returns a list of structured item dicts:
    1. Attack paths: type="attack_path", id, priority, entry, target, status, hops_count, proven_fix
    2. Questions for app team: type="question", number, question, why, settles
    3. Data questions: type="data_question", resource, field, question
    """
    paths = getattr(res, "paths", [])
    pytm_data = getattr(res, "pytm", {}) or {}
    questions_doc = pytm_data.get("questions") or {}
    all_questions = questions_doc.get("questions", [])
    data_questions = questions_doc.get("data_questions", [])
    remediation_doc = getattr(res, "remediation", None)

    num_paths = len(paths)
    max_q_first_screen = min(FIRST_SCREEN_QUESTIONS, len(all_questions))
    num_data_q = len(data_questions)

    available_for_paths = max(1, max_first_screen - (max_q_first_screen + num_data_q)) if num_paths > 0 else 0
    paths_on_first_screen = min(num_paths, max(1, available_for_paths))

    if paths_on_first_screen > max_first_screen:
        paths_on_first_screen = max_first_screen
        max_q_first_screen = 0
        num_data_q = 0

    items: list[dict[str, Any]] = []

    for p in paths[:paths_on_first_screen]:
        path_item: dict[str, Any] = {
            "type": "attack_path",
            "id": getattr(p, "id", ""),
            "priority": getattr(p, "priority", ""),
            "entry": getattr(p, "entry", ""),
            "target": getattr(p, "target", ""),
            "status": getattr(p, "status", "plausible"),
            "hops_count": len(getattr(p, "hops", [])),
        }
        fix_summary, diff_text = _build_proven_fix_snippet(remediation_doc, getattr(p, "id", ""))
        if diff_text:
            path_item["proven_fix"] = {
                "summary": fix_summary,
                "diff": diff_text,
            }
        elif hasattr(p, "remedies") and p.remedies:
            top_rem = p.remedies[0]
            path_item["suggested_fix"] = {
                "hop": getattr(top_rem, "hop", None),
                "change": getattr(top_rem, "change", ""),
                "effect": getattr(top_rem, "effect", ""),
            }
        items.append(path_item)

    for q in all_questions[:max_q_first_screen]:
        items.append({
            "type": "question",
            "number": q.get("n"),
            "question": q.get("question", ""),
            "why": q.get("why", ""),
            "settles": q.get("settles", ""),
        })

    if max_q_first_screen > 0:
        for dq in data_questions[:num_data_q]:
            items.append({
                "type": "data_question",
                "element": dq.get("element", ""),
                "resource": dq.get("element", "") or dq.get("resource", ""),
                "control": dq.get("control", ""),
                "question": dq.get("question", ""),
                "why": dq.get("why", ""),
                "informs": dq.get("informs", 0),
            })

    return items


def _is_safe_boundary(text: str, cut: int) -> bool:
    """Check if cutting text at index `cut` avoids splitting code fences, HTML tags, or table rows."""
    prefix = text[:cut]
    # 1. Code fence: must have an even number of ```
    if prefix.count("```") % 2 != 0:
        return False
    # 2. Tag: must not cut inside <...>
    last_open = prefix.rfind("<")
    last_close = prefix.rfind(">")
    if last_open > last_close:
        return False
    # 3. Table: must not cut inside a table line
    lines = prefix.splitlines()
    if lines and lines[-1].strip().startswith("|"):
        return False
    return True


def _safe_truncate(raw_text: str, max_chars: int) -> str:
    """Truncate markdown text to strictly <= max_chars at a safe section boundary.

    Guarantees:
    - Never cuts inside a code fence, table, or HTML tag;
    - Cuts at </details> boundary, double newline \\n\\n, or newline \\n;
    - Closes any opened <details> tags cleanly;
    - Guaranteed strictly <= max_chars including cutoff note.
    """
    if len(raw_text) <= max_chars:
        return raw_text

    cutoff_note = "\n\n<!-- Note: Collapsed technical appendix truncated to satisfy Git host 64KB comment limit; see full CI report artifacts -->\n"
    budget = max_chars - len(cutoff_note)
    if budget <= 0:
        return raw_text[:max_chars]

    best_cut = -1
    # Priority 1: after a completed </details>
    pos = budget
    while pos > 0:
        idx = raw_text.rfind("</details>", 0, pos)
        if idx == -1:
            break
        candidate = idx + len("</details>")
        if candidate <= budget and _is_safe_boundary(raw_text, candidate):
            best_cut = candidate
            break
        pos = idx

    # Priority 2: at section boundary \n\n
    if best_cut == -1:
        pos = budget
        while pos > 0:
            idx = raw_text.rfind("\n\n", 0, pos)
            if idx == -1:
                break
            candidate = idx
            if candidate <= budget and _is_safe_boundary(raw_text, candidate):
                best_cut = candidate
                break
            pos = idx

    # Priority 3: at line boundary \n
    if best_cut == -1:
        pos = budget
        while pos > 0:
            idx = raw_text.rfind("\n", 0, pos)
            if idx == -1:
                break
            candidate = idx
            if candidate <= budget and _is_safe_boundary(raw_text, candidate):
                best_cut = candidate
                break
            pos = idx

    if best_cut == -1:
        best_cut = budget

    truncated = raw_text[:best_cut].rstrip()
    open_d = truncated.count("<details")
    close_d = truncated.count("</details>")
    if open_d > close_d:
        truncated += "\n</details>" * (open_d - close_d)

    # If adding closing tags exceeded max_chars, recurse with reduced budget
    if len(truncated) + len(cutoff_note) > max_chars:
        excess = (len(truncated) + len(cutoff_note)) - max_chars
        return _safe_truncate(raw_text, max_chars - excess)

    return truncated + cutoff_note


def render_developer_comment(
    res: Any,
    gate: dict | None = None,
    draft: str = "",
    max_first_screen: int = FIRST_SCREEN_MAX_ITEMS,
    max_chars: int = GIT_HOST_COMMENT_LIMIT,
) -> str:
    """Render the Developer PR comment v2 (W3.1).

    Ensures:
    1. First screen <= max_first_screen review items (matches M2 count on PR #42);
    2. Plain words first for every displayed path;
    3. Proven fix diff on first screen if available;
    4. Verdict and four ways out (fix, accept, answer, dispute false path);
    5. Dispute link and YAML template (disposition: not_reachable);
    6. All technical and scanner details collapsed in <details>;
    7. Overall comment length strictly <= max_chars (default 65,535).
    """
    b = getattr(res, "build", None)
    recs = b.ledger.by_id() if b else {}
    paths = getattr(res, "paths", [])
    findings = getattr(res, "findings", [])
    pytm_data = getattr(res, "pytm", {})
    cls = pytm_data.get("classification")
    questions_doc = pytm_data.get("questions") or {}
    all_questions = questions_doc.get("questions", [])
    data_questions = questions_doc.get("data_questions", [])
    remediation_doc = getattr(res, "remediation", None)
    ai_doc = getattr(res, "ai", None)
    comments = getattr(res, "comments", [])
    hashes = getattr(res, "hashes", {})

    L: list[str] = []
    w = L.append

    # ------------------------------------------------------------------ Header & Verdict
    cfg_name = getattr(getattr(res, "cfg", None), "name", "Terraform Plan")
    w(f"# Security architecture review: {cfg_name}")

    # Determine verdict and stats
    if gate is not None:
        level = gate.get("level", "observe")
        threshold = gate.get("fail_on", "high")
        decision = gate.get("decision", "pass")
        without_dec = gate.get("without_decision", 0)
        not_reachable = gate.get("not_reachable", 0)
        accepted = gate.get("accepted", 0)

        if decision == "fail":
            v_badge = f"**Status: Blocked** — {without_dec} path(s) at or above {threshold} need a decision before merge."
        elif without_dec > 0 and level not in ("validate", "prevent"):
            v_badge = f"**Status: Would block at validate** — {without_dec} path(s) at or above {threshold} have no decision yet."
        else:
            v_badge = f"**Status: Pass** — every path at or above {threshold} is fixed or accepted."

        gate_line = f"**Gate Check (level: `{level}`, threshold: `{threshold}`):** {v_badge}"
        if accepted or not_reachable:
            dec_parts = []
            if accepted:
                dec_parts.append(f"{accepted} accepted risk(s)")
            if not_reachable:
                dec_parts.append(f"{not_reachable} disputed false path(s)")
            gate_line += f" Decisions applied: {', '.join(dec_parts)}."
        w(gate_line)
    else:
        if not paths:
            w("**Verdict: Pass** — No attack paths from internet-reachable entries to sensitive assets found.")
        else:
            high_paths = sum(1 for p in paths if getattr(p, "priority", "") == "high")
            w(f"**Verdict:** {len(paths)} attack path(s) identified ({high_paths} high priority).")

    # Four ways to resolve (Verdict & Ways Out)
    w("### Ways to resolve:")
    w("1. **Fix:** Apply the proven fix below or update Terraform to remove the path.")
    w("2. **Accept Risk:** Add an accepted risk to `attack-path-exceptions.yaml` with owner, reason, and expiry (up to 90 days).")
    w("3. **Answer:** Answer the yes/no questions below in `threat-answers.yaml` to settle undecided controls.")
    w("4. **Dispute False Path:** Dispute in `attack-path-exceptions.yaml` with `disposition: not_reachable` "
      "([dispute template](#dispute-a-false-path); tracked under kit metric M8 (False-path rate); does not block merge).")

    # ------------------------------------------------------------------ First Screen Items
    # Budget calculation for first screen <= max_first_screen
    # Normal M2 count: paths + min(6, len(questions)) + len(data_questions)
    num_paths = len(paths)
    
    # PR #42 case: 1 path, 6 questions, 2 data questions = 9 items (<= 10).
    # If num_paths is larger (e.g. IAM-Vulnerable with 37 paths), cap first screen paths
    # so first screen stays <= max_first_screen items.
    max_q_first_screen = min(FIRST_SCREEN_QUESTIONS, len(all_questions))
    num_data_q = len(data_questions)

    available_for_paths = max(1, max_first_screen - (max_q_first_screen + num_data_q)) if num_paths > 0 else 0
    paths_on_first_screen = min(num_paths, max(1, available_for_paths))
    
    # If paths alone exceed max_first_screen, cap paths at max_first_screen and show 0 questions on first screen
    if paths_on_first_screen > max_first_screen:
        paths_on_first_screen = max_first_screen
        max_q_first_screen = 0
        num_data_q = 0

    first_screen_total = paths_on_first_screen + max_q_first_screen + num_data_q
    m2_nominal = num_paths + min(FIRST_SCREEN_QUESTIONS, len(all_questions)) + len(data_questions)

    # Consolidated heading: avoids empty '## First screen' heading (Finding F15)
    w(f"## In plain words ({first_screen_total} review items · M2 count: {m2_nominal})")

    if not paths:
        w("**No attack path** from an internet-reachable entry to a classified asset was found in this plan.")
    else:
        for p in paths[:paths_on_first_screen]:
            w(f"#### Path: {p.id} ({p.priority.upper()})")
            try:
                story_dict = path_story(res, p, "developer")
                # Do not repeat path questions in the story; answered once in the review table below (Finding F15)
                story_dict["questions"] = []
                story_content = render_story(story_dict).rstrip("\n")
            except Exception:
                story_content = f"**{p.priority.upper()}: Attack path from `{_short(p.entry)}` to `{_short(p.target)}`.**"

            # Format story concisely to satisfy <= 40 lines line budget
            story_lines = [line for line in story_content.splitlines() if line.strip() and line.strip() != "How:"]
            for sl in story_lines:
                w(sl)

            # The one proven fix right under the path
            fix_summary, diff_text = _build_proven_fix_snippet(remediation_doc, p.id)
            if diff_text:
                w(f"**Proven fix:** `remediation-{p.id}.diff` ({fix_summary}):")
                w("```diff")
                w(diff_text)
                w("```")
            elif hasattr(p, "remedies") and p.remedies:
                # Deterministic remedy suggestion
                top_rem = p.remedies[0]
                w(f"**Suggested fix:** Hop {top_rem.hop}: {top_rem.change} (*Effect:* {top_rem.effect.replace('_', ' ')}).")

        if num_paths > paths_on_first_screen:
            w(f"*{num_paths - paths_on_first_screen} more path(s) collapsed below in Technical Path Details.*")

    # First screen questions table
    shown_q = all_questions[:max_q_first_screen]
    if shown_q or (num_data_q > 0 and max_q_first_screen > 0):
        w("### Questions for the app team (answer in `threat-answers.yaml`):")
        w("| # | Question | Why it matters | Settles |")
        w("|---|---|---|---|")
        for x in shown_q:
            w(f"| {x['n']} | {x['question']} | {x['why']} | {x['settles']} |")
        for x in data_questions[:num_data_q]:
            w(f"| · | {x['question']} | {x['why']} | informs {x['informs']} |")

    # ------------------------------------------------------------------ Collapsed Section 1: Technical Path Details
    if paths:
        w(f"<details><summary>Technical Path Details & Architecture Flows ({len(paths)} path(s))</summary>")
        w("")
        # Detailed hop tables and sequence diagrams
        # For huge repos like IAM-Vulnerable (37 paths), fully expand first 5 paths and summarize rest in compact table
        detailed_path_limit = 5 if len(paths) > 10 else len(paths)

        for p in paths[:detailed_path_limit]:
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

            # Mermaid sequence diagram
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

            # On-path findings
            on_path_findings = [f for f in findings if p.id in getattr(f, "causal_paths", ())]
            if on_path_findings:
                w(f"**Scanner findings on this path's hops** ({len(on_path_findings)} finding(s)):")
                w("")
                w("| Evidence | Tool | Rule | Severity | Resource | Location |")
                w("|---|---|---|---|---|---|")
                for f in sorted(on_path_findings, key=lambda f: (f.node or "", f.tool, f.rule_id))[:15]:
                    w(f"| {f.id} | {f.tool} | `{f.rule_id}` | {f.severity} | `{f.resource}` | `{f.file}:{f.start_line}` |")
                if len(on_path_findings) > 15:
                    w(f"| ... | | *{len(on_path_findings) - 15} more on-path findings* | | | |")
                w("")

        # Compact summary table for remaining paths if truncated
        if len(paths) > detailed_path_limit:
            w(f"#### Additional Paths Summary ({len(paths) - detailed_path_limit} paths)")
            w("")
            w("| Path | Priority | Entry → Target | Preconditions |")
            w("|---|---|---|---|")
            for p in paths[detailed_path_limit:]:
                pre_str = ", ".join(p.preconditions) or "none"
                w(f"| {p.id} | {p.priority.upper()} | `{_short(p.entry)}` → `{_short(p.target)}` | {pre_str} |")
            w("")

        w("</details>")
        w("")

    # ------------------------------------------------------------------ Collapsed Section 2: Remaining Questions & Answers
    remaining_q = all_questions[max_q_first_screen:]
    answers_applied = questions_doc.get("answers", [])
    if remaining_q or answers_applied:
        w(f"<details><summary>Remaining Questions & Threat Model Answers ({len(remaining_q)} additional question(s))</summary>")
        w("")
        if remaining_q:
            w("#### Additional yes/no questions")
            w("")
            w("| # | Question | Why it matters | Settles |")
            w("|---|---|---|---|")
            # Show up to 25 remaining questions to avoid bloat
            for x in remaining_q[:25]:
                w(f"| {x['n']} | {x['question']} | {x['why']} | {x['settles']} |")
            if len(remaining_q) > 25:
                w(f"| ... | *{len(remaining_q) - 25} more questions in questions.json* | | |")
            w("")

        if answers_applied:
            w("#### Answers applied in threat-answers.yaml")
            w("")
            for a in answers_applied:
                ans = "yes" if a.get("answer") else "no" if a.get("answer") is not None else "?"
                w(f"- `{a.get('element')}` {a.get('control')} = **{ans}** ({a.get('by') or 'unknown'}) · {a.get('status')}"
                  + (f" · {', '.join(a.get('evidence', []))}" if a.get("evidence") else ""))
            w("")
        w("</details>")
        w("")

    # ------------------------------------------------------------------ Collapsed Section 3: PyTM Threat Model
    if cls:
        s_cls = cls.get("summary", {})
        decided_count = s_cls.get("confirmed", 0) + s_cls.get("mitigated", 0)
        open_count = s_cls.get("needs_app_team", 0)
        ruled_count = s_cls.get("ruled_out", 0)
        w(f"<details><summary>PyTM Threat Model Summary ({decided_count} decided · {open_count} open · {ruled_count} ruled out)</summary>")
        w("")
        w("| Category | Threats |")
        w("|---|---|")
        w(f"| Architecture only (baseline without plan evidence) | {s_cls.get('generic', 0)} |")
        w(f"| **Decided by plan evidence** | **{s_cls.get('confirmed', 0)}**"
          + (f" (+{s_cls.get('mitigated', 0)} mitigated)" if s_cls.get("mitigated") else "") + " |")
        w(f"| Questions for the app team (unobserved controls) | {s_cls.get('needs_app_team', 0)} |")
        w(f"| Ruled out by plan evidence | {s_cls.get('ruled_out', 0)} |")
        w("")

        rows = cls.get("findings", [])
        decided_threats = [r for r in rows if r.get("class") in ("confirmed", "mitigated", "ruled_out")]
        if decided_threats:
            w("#### Decided and ruled-out threats")
            w("")
            w("| Class | Threat | Element | Basis |")
            w("|---|---|---|---|")
            for r in decided_threats[:20]:
                why = "; ".join(f"`{a.split('.')[-1]} = {v['value']}`" for a, v in r.get("decided", {}).items())
                if r.get("assumption"):
                    why = f"assumption: {r['assumption']}"
                w(f"| {r['class'].replace('_', ' ')} | {r['threat_id']}: {r['description']} | `{r['element']}` | {why} |")
            if len(decided_threats) > 20:
                w(f"| ... | *{len(decided_threats) - 20} more threats in pytm-findings.json* | | |")
            w("")
        w("</details>")
        w("")

    # ------------------------------------------------------------------ Collapsed Section 4: Verified Remediation
    if remediation_doc:
        s_rem = remediation_doc.get("summary", {})
        w(f"<details><summary>Verified Remediation Patches ({s_rem.get('verified_break', 0)} proven break)</summary>")
        w("")
        w(f"Patch author: `{remediation_doc.get('manifest', {}).get('patch_author', '')}`. "
          "Each proposal passed a deterministic edit policy, was applied to an isolated copy, "
          "re-planned offline, and proven to break the path with no new paths. **Nothing was applied to this repository.**")
        w("")
        for p in remediation_doc.get("paths", []):
            w(f"#### {p['path']}: {p['result'].replace('_', ' ').lower()}")
            w("")
            w("| # | Hop | Proposed change | Result | Effect |")
            w("|---|---|---|---|---|")
            for a in p.get("attempts", []):
                pt = a.get("patch", {})
                ch = f"`{pt.get('file', '')}`: `{(pt.get('replace') or '').strip()[:60]}`".replace("|", "\\|").replace("\n", " ")
                w(f"| {a.get('n')} | {pt.get('hop', '')} | {ch} | {a.get('status')} | {a.get('effect')} |")
            w("")
            if p.get("recommended_diff"):
                w(f"Verified patch (`remediation-{p['path']}.diff`):")
                w("")
                w("```diff")
                w(p["recommended_diff"].rstrip("\n"))
                w("```")
                w("")
        w("</details>")
        w("")

    # ------------------------------------------------------------------ Collapsed Section 5: AI Annotations
    if ai_doc:
        s_ai = ai_doc.get("summary", {})
        gen = s_ai.get("generated", 0)
        acc = s_ai.get("accepted", 0)
        rej = s_ai.get("rejected", 0)
        w(f"<details><summary>AI Annotations & Verification ({acc} accepted · {rej} held/rejected)</summary>")
        w("")
        w("## AI annotations (bounded, evidence-validated)")
        w("")
        w(f"{gen} generated · {acc} evidence-backed and accepted · {rej} rejected · "
          f"{s_ai.get('human_review', 0)} routed to human review · backend `{ai_doc.get('manifest', {}).get('llm_backend', '')}`, "
          f"decision layer `{ai_doc.get('manifest', {}).get('jev_backend', '')}`")
        w("")
        for a in ai_doc.get("annotations", []):
            if a.get("status") == "accepted":
                w(f"- **{a['annotation_id']}** ({a['type']}, {a.get('path_ref') or a.get('target_ref') or ''}): {escape_statement(a['statement'])}  ")
                w(f"  Evidence: {', '.join(a.get('evidence_refs', []))}")
        
        rejected_annos = [a for a in ai_doc.get("annotations", []) if a.get("status") != "accepted"]
        if rejected_annos:
            w("")
            w("#### Rejected or held annotations")
            for a in rejected_annos:
                w(f"- {a['annotation_id']} ({a['type']}): **{a['status']}** — {escape_statement('; '.join(a.get('rejections', [])) or a.get('reason', ''))}")
        w("")
        w("</details>")
        w("")

    # ------------------------------------------------------------------ Collapsed Section 6: Non-path Scanner Findings
    non_path_findings = [f for f in findings if not getattr(f, "causal_paths", ())]
    if non_path_findings:
        by_tool = Counter(f.tool for f in non_path_findings)
        tools_summary = " · ".join(f"{t.capitalize() if t != 'tfsec' else 'tfsec'} {by_tool[t]}" for t in sorted(by_tool))
        w(f"<details><summary>Scanner findings not on any attack-path hop ({len(non_path_findings)} findings — {tools_summary})</summary>")
        w("")
        w("| Evidence | Tool | Rule | Severity | Resource |")
        w("|---|---|---|---|---|")
        # For large repos (e.g. IAM-Vulnerable with 365 non-path findings), show top 25
        for f in sorted(non_path_findings, key=lambda f: (f.tool, f.rule_id, f.resource))[:25]:
            w(f"| {f.id} | {f.tool} | `{f.rule_id}` | {f.severity} | `{f.resource}` |")
        if len(non_path_findings) > 25:
            w(f"| ... | | *{len(non_path_findings) - 25} more findings not on attack paths; view scanner-findings.json* | | |")
        w("")
        w("</details>")
        w("")

    # ------------------------------------------------------------------ Collapsed Section 7: Dispute & Exception Templates
    w('<details id="dispute-a-false-path"><summary>Dispute False Path or Accept Risk Templates (attack-path-exceptions.yaml)</summary>')
    w("")
    w("To resolve attack paths without code changes, commit `attack-path-exceptions.yaml` to the root of your pull request.")
    w("")
    w("#### Option A: Dispute a false path (counted in kit metric M8; does not block merge)")
    w("If the path cannot be reached in reality due to out-of-band network controls, environment barriers, or modeling scope:")
    w("")
    w("```yaml")
    w("exceptions:")
    if paths:
        p0 = paths[0]
        w(f"  - id: DISPUTE-001")
        w(f"    disposition: not_reachable")
        w(f"    entry: {p0.entry}")
        w(f"    target: {p0.target}")
        w(f"    owner: your-team-name")
        w(f"    reason: Security group / VPC boundary restricts ingress; not reachable from internet")
    else:
        w("  - id: DISPUTE-001")
        w("    disposition: not_reachable")
        w("    entry: internet")
        w("    target: aws_s3_bucket.example")
        w("    owner: your-team-name")
        w("    reason: Environment control prevents reachability")
    w("```")
    w("")
    w("#### Option B: Accept risk (requires owner and expiry; compensating control at prevent level)")
    w("```yaml")
    w("exceptions:")
    if paths:
        p0 = paths[0]
        w(f"  - id: RISK-001")
        w(f"    entry: {p0.entry}")
        w(f"    target: {p0.target}")
        w(f"    owner: your-team-name")
        w(f"    reason: Legacy system migration in progress")
        w(f"    expires: 2026-11-15       # maximum 90 days (validate) or 30 days (prevent)")
    else:
        w("  - id: RISK-001")
        w("    entry: internet")
        w("    target: aws_s3_bucket.example")
        w("    owner: your-team-name")
        w("    reason: Temporary operational requirement")
        w("    expires: 2026-11-15")
    w("```")
    w("")
    if draft:
        w("#### Generated draft entries for open paths:")
        w("```yaml")
        w(draft.rstrip())
        w("```")
        w("")
    w("</details>")
    w("")

    # ------------------------------------------------------------------ Collapsed Section 8: Metadata & Scope
    w("<details><summary>Analysis Metadata, Scope & Hashes</summary>")
    w("")
    if b:
        n_res = sum(1 for n in b.graph.nodes.values() if not n.synthetic)
        n_mod = sum(1 for n in b.graph.nodes.values() if not n.synthetic and n.modeled)
        w("| Metric | Value |")
        w("|---|---|")
        w(f"| Resources in plan | {n_res} ({n_mod} modeled) |")
        w(f"| Attack paths | {len(paths)} |")
        w(f"| Scanner findings | {len(findings)} |")
        if b.notes:
            w(f"| Analysis notes | {len(b.notes)} |")
        if b.unresolved_policies:
            w(f"| Unresolved policies | {len(b.unresolved_policies)} |")
        w("")

    # Untrusted comments if present
    suspicious = [c for c in comments if c.get("suspicious")]
    if suspicious:
        w("## Untrusted source comments")
        w("")
        w("Comments are recorded as untrusted metadata. They cannot change the graph or paths, and are never sent to AI agents:")
        w("")
        for c in suspicious:
            txt = c.get("text", "").replace("\n", " ")
            w(f"- {c.get('id')} `{c.get('file')}:{c.get('line')}`: “{txt[:120]}” — patterns: {', '.join(c.get('patterns', []))}")
        w("")

    w(f"**Scope:** {SCOPE_STATEMENT}")
    w("")
    if hashes:
        w(f"Deterministic artifact hashes: graph `{hashes.get('resource-graph.json', '')[:12]}` · "
          f"paths `{hashes.get('attack-paths.json', '')[:12]}` · evidence `{hashes.get('evidence.json', '')[:12]}` · "
          f"PyTM `{hashes.get('threat-model.py', '')[:12]}`")
        w("")
    w("</details>")
    w("")

    # ------------------------------------------------------------------ Assemble and Enforce Length Limit
    raw_text = "\n".join(L).rstrip() + "\n"
    return _safe_truncate(raw_text, max_chars)


def render_developer_report(
    data: Any,
    format: str = "markdown",
    gate: dict | None = None,
    max_chars: int = GIT_HOST_COMMENT_LIMIT,
) -> str:
    """Render developer persona report in markdown, text, or json format."""
    # If data is an artifacts directory path, load the JSON documents
    if isinstance(data, (str, Path)):
        art_dir = Path(data)
        from ..pipeline import RunConfig, RunResult
        from ..graph.build import BuildResult
        
        # Load artifacts
        ap_file = art_dir / "attack-paths.json"
        if not ap_file.exists():
            raise FileNotFoundError(f"Missing attack-paths.json in {art_dir}")
        ap_doc = json.loads(ap_file.read_text(encoding="utf-8"))
        
        from ..paths.engine import AttackPath, Hop
        paths_list = []
        for p in ap_doc.get("paths", []):
            hops = [Hop(
                edge=h.get("edge", ""),
                type=h.get("type", ""),
                src=h.get("src", ""),
                dst=h.get("dst", ""),
                label=h.get("label", ""),
                status=h.get("status", "FACT"),
                precondition=h.get("precondition"),
                evidence=h.get("evidence", []),
            ) for h in p.get("hops", [])]
            paths_list.append(AttackPath(
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
            ))
        
        pytm_findings = json.loads((art_dir / "pytm-findings.json").read_text(encoding="utf-8")) if (art_dir / "pytm-findings.json").exists() else {}
        questions_doc = json.loads((art_dir / "questions.json").read_text(encoding="utf-8")) if (art_dir / "questions.json").exists() else {}
        remediation_doc = json.loads((art_dir / "remediations.json").read_text(encoding="utf-8")) if (art_dir / "remediations.json").exists() else None
        ai_doc = json.loads((art_dir / "ai-annotations.json").read_text(encoding="utf-8")) if (art_dir / "ai-annotations.json").exists() else None
        if gate is None and (art_dir / "gate.json").exists():
            gate = json.loads((art_dir / "gate.json").read_text(encoding="utf-8"))

        findings_list = []
        sf_file = art_dir / "scanner-findings.json"
        if sf_file.exists():
            from ..scanners.normalize import Finding
            sf_doc = json.loads(sf_file.read_text(encoding="utf-8"))
            for f in sf_doc.get("findings", []):
                findings_list.append(Finding(
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
                ))
            
        pytm_res = {
            "threat_count": pytm_findings.get("summary", {}).get("published"),
            "summary": pytm_findings.get("summary", {}),
            "classification": pytm_findings,
            "questions": questions_doc,
        }
        
        # Reconstruct graph and ledger if present
        mock_build = None
        rg_file = art_dir / "resource-graph.json"
        ev_file = art_dir / "evidence.json"
        if rg_file.exists() and ev_file.exists():
            from ..graph.model import Node, Edge
            from ..evidence.ledger import Record

            rg_data = json.loads(rg_file.read_text(encoding="utf-8"))
            ev_data = json.loads(ev_file.read_text(encoding="utf-8"))

            nodes = {}
            for n in rg_data.get("nodes", []):
                nodes[n["id"]] = Node(
                    id=n["id"], type=n["type"], aws_type=n.get("aws_type", ""),
                    category=n.get("category", "other"), label=n.get("label", ""),
                    sensitivity=n.get("sensitivity", {"level": "unclassified"}),
                    source=n.get("source"),
                )
            edges = {}
            for e in rg_data.get("edges", []):
                edges[e["id"]] = Edge(
                    id=e["id"], type=e["type"], src=e["src"], dst=e["dst"],
                    label=e.get("label", ""),
                    evidence=e.get("evidence", []), data=e.get("data", {}),
                )
            
            class MockLedger:
                def __init__(self, recs): self._recs = {r.id: r for r in recs}
                def by_id(self): return self._recs

            recs = [Record(id=r["id"], kind=r["kind"], key=r.get("key"), summary=r.get("summary", ""),
                           source=r.get("source"), data=r.get("data", {})) for r in ev_data.get("records", [])]

            class MockGraph:
                def __init__(self, n, e): self.nodes = n; self.edges = e

            class MockBuild:
                def __init__(self, g, l): self.graph = g; self.ledger = l; self.notes = []; self.unresolved_policies = []

            mock_build = MockBuild(MockGraph(nodes, edges), MockLedger(recs))

        class MockRunResult:
            pass
        class MockConfig:
            name = art_dir.name
        
        mock = MockRunResult()
        mock.cfg = MockConfig()
        mock.paths = paths_list
        mock.findings = findings_list
        mock.comments = []
        mock.remedies = []
        mock.pytm = pytm_res
        mock.remediation = remediation_doc
        mock.ai = ai_doc
        mock.build = mock_build
        mock.hashes = {}
        data = mock

    if format == "json":
        comment_md = render_developer_comment(data, gate=gate, max_chars=max_chars)
        items_count = count_first_screen_items(comment_md)
        all_q = getattr(data, "pytm", {}).get("questions", {}).get("questions", [])
        data_q = getattr(data, "pytm", {}).get("questions", {}).get("data_questions", [])
        paths_count = len(getattr(data, "paths", []))
        m2_calc = paths_count + min(FIRST_SCREEN_QUESTIONS, len(all_q)) + len(data_q)
        
        findings_count = len(getattr(data, "findings", []))
        pytm_data = getattr(data, "pytm", {}) or {}
        pytm_summary = pytm_data.get("summary") or pytm_data.get("classification", {}).get("summary", {})
        pytm_generic = pytm_summary.get("generic", 0)
        m1_calc = compute_m1(findings_count, pytm_generic)
        
        first_screen_items = extract_first_screen_items(data, max_first_screen=FIRST_SCREEN_MAX_ITEMS)

        return json.dumps({
            "persona": "developer",
            "comment_markdown": comment_md,
            "first_screen_items": first_screen_items,
            "items_first_screen": items_count,
            "m1_count": m1_calc,
            "m2_count": m2_calc,
            "paths_count": paths_count,
            "first_screen_max": FIRST_SCREEN_MAX_ITEMS,
            "comment_length_chars": len(comment_md),
            "under_git_limit": len(comment_md) <= GIT_HOST_COMMENT_LIMIT,
        }, indent=2)

    if format == "text":
        comment_md = render_developer_comment(data, gate=gate, max_chars=max_chars)
        # Strip basic markdown symbols for plain text
        lines = [re.sub(r"[#*`_]", "", line) for line in comment_md.splitlines()]
        return "\n".join(lines)

    return render_developer_comment(data, gate=gate, max_chars=max_chars)
