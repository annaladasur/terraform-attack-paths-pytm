"""Source comments are untrusted metadata.

They are recorded as CMT-### evidence with ``trust: untrusted`` so reviewers can
see them, but:

* they never influence the graph, paths or priorities (the plan has no comments);
* they are excluded from AI evidence bundles by default;
* when included (``--include-comments``), they are wrapped as quoted, untrusted
  data and the validator still decides what is accepted.

A deterministic detector flags comments that read like instructions to an AI
reviewer. Flagging is informational; it does not change any security decision.
"""

from __future__ import annotations

import re

from ..graph.build import BuildResult

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("override-instructions", re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all|earlier|other)\b.{0,40}\b(instructions?|findings?|rules?|analysis|guidance|context)\b", re.I | re.S)),
    ("role-play", re.compile(r"\b(you are (now )?(an?|the) |act as |system prompt|as an ai\b|assistant:)", re.I)),
    ("assert-safe", re.compile(r"\b(describe|mark|report|treat|classify|label|consider)\b.{0,50}\b(as )?(secure|safe|compliant|low[- ]risk|benign|approved|not vulnerable)\b", re.I | re.S)),
    ("suppress", re.compile(r"\b(do not|don't|never)\b.{0,20}\b(mention|report|flag|include|discuss|reveal|list)\b", re.I | re.S)),
    ("suppress", re.compile(r"\bsuppress\b.{0,30}\b(findings?|alerts?|warnings?|issues?)\b", re.I | re.S)),
    ("override-policy", re.compile(r"\b(override|bypass|disable)\b.{0,30}\b(security|policy|guardrails?|validator|checks?)\b", re.I | re.S)),
]


def detect(text: str) -> list[str]:
    return sorted({name for name, rx in INJECTION_PATTERNS if rx.search(text)})


def register_comments(result: BuildResult) -> list[dict]:
    out = []
    comments = sorted(result.source.comments, key=lambda c: (c.file, c.line))
    for c in comments:
        hits = detect(c.text)
        anchor = c.block or c.precedes
        cid = result.ledger.append(
            "CMT", (c.file, c.line), f"comment at {c.file}:{c.line}" + (f" ({anchor})" if anchor else ""),
            source={"file": c.file, "start_line": c.line, "end_line": c.end_line},
            data={"text": c.text, "anchor": anchor, "suspicious": bool(hits), "patterns": hits},
            trust="untrusted",
        )
        out.append({"id": cid, "file": c.file, "line": c.line, "anchor": anchor, "text": c.text,
                    "suspicious": bool(hits), "patterns": hits})
    return out
