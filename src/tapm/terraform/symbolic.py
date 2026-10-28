"""Symbolic recovery of IAM policy documents that are unknown at plan time.

``policy = jsonencode({... Resource = "${aws_s3_bucket.x.arn}/*" })`` is unknown in
the plan because the bucket ARN does not exist yet. The *structure* of the policy
is still fully determined by the source. We recover it by re-parsing the source
expression and replacing each interpolation with a symbolic token::

    "${aws_s3_bucket.x.arn}/*"   ->   "tf:aws_s3_bucket.x.arn/*"

The IAM evaluator treats ``tf:<address>.arn`` as the ARN of that graph node. Every
policy recovered this way is marked ``symbolic`` so the evidence says how it was
obtained.
"""

from __future__ import annotations

import re
from typing import Any

import hcl2

from .plan import PlanResource
from .source import SourceIndex

_INTERP = re.compile(r"\$\{([^{}]+)\}")
_REF = re.compile(r"^((?:module\.[A-Za-z0-9_-]+\.)*(?:data\.)?[a-z0-9_]+\.[A-Za-z0-9_-]+(?:\[[^\]]*\])?)\.(arn|id|name|bucket)$")


def symbolic_policy_from_source(res: PlanResource, attr: str, src: SourceIndex, ctx=None) -> dict | None:
    loc = src.locate_member(res.base, attr)
    if not loc:
        return None
    sf = src.files[loc["file"]]
    text = "\n".join(sf.lines[loc["start_line"] - 1 : loc["end_line"]])
    try:
        parsed = hcl2.loads(text + "\n")
    except Exception:
        return None
    value = parsed.get(attr)
    if not isinstance(value, str):
        return None
    inner = _unwrap_jsonencode(value)
    if inner is None:
        return None
    try:
        doc = hcl2.loads("x = " + inner + "\n").get("x")
    except Exception:
        return None
    prefix = res.module + "." if res.module else ""
    return _symbolise(doc, prefix, ctx)


def symbolic_policy_from_document_config(res: PlanResource, ctx=None) -> dict | None:
    """Rebuild an ``aws_iam_policy_document`` from its configuration expressions."""
    statements = res.expressions.get("statement")
    if not isinstance(statements, list):
        return None
    prefix = res.module + "." if res.module else ""
    out = []
    for st in statements:
        s: dict[str, Any] = {"Effect": _const(st.get("effect")) or "Allow"}
        for key, field in (("actions", "Action"), ("not_actions", "NotAction"),
                           ("resources", "Resource"), ("not_resources", "NotResource")):
            val = _values_or_refs(st.get(key), prefix, ctx)
            if val:
                s[field] = val
        principals = st.get("principals") or []
        if principals:
            p: dict[str, list[str]] = {}
            for pr in principals:
                ptype = _const(pr.get("type")) or "AWS"
                p.setdefault(ptype, []).extend(_values_or_refs(pr.get("identifiers"), prefix, ctx))
            s["Principal"] = p
        conds = st.get("condition") or []
        if conds:
            s["Condition"] = {"_symbolic": [
                {"test": _const(c.get("test")), "variable": _const(c.get("variable"))} for c in conds]}
        out.append(s)
    return {"Version": "2012-10-17", "Statement": out, "_symbolic": True, "_approximate": True}


def _const(expr: Any) -> Any:
    if isinstance(expr, dict) and "constant_value" in expr:
        return expr["constant_value"]
    return None


def _values_or_refs(expr: Any, prefix: str, ctx=None) -> list[str]:
    if expr is None:
        return []
    c = _const(expr)
    if c is not None:
        return [str(v) for v in (c if isinstance(c, list) else [c])]
    refs = (expr or {}).get("references", []) if isinstance(expr, dict) else []
    out = []
    for r in refs:
        out.extend(_token_for(r, prefix, ctx))
    # Terraform lists both "aws_x.y.arn" and "aws_x.y"; keep attribute refs only.
    return sorted(set(out)) or (["tf:unresolved"] if refs else [])


def _token_for(ref: str, prefix: str, ctx) -> list[str]:
    m = _REF.match(ref)
    if m:
        return [f"tf:{prefix}{m.group(1)}.{m.group(2)}"]
    if ctx is not None and ref.startswith(("var.", "local.", "module.")):
        return [f"tf:{base}.{attr}" for base, attr in ctx.resolve_attr(ref, prefix) if attr in ("arn", "id", "name", "bucket")]
    return []


def _unwrap_jsonencode(value: str) -> str | None:
    v = value.strip()
    if v.startswith("${jsonencode(") and v.endswith(")}"):
        return v[len("${jsonencode(") : -2]
    return None


def _symbolise(node: Any, prefix: str, ctx=None) -> Any:
    if isinstance(node, dict):  # quoted keys ("Statement" : [...]) come back from hcl2 with their quotes
        return {(k[1:-1] if len(k) >= 2 and k[0] == k[-1] == '"' else k): _symbolise(v, prefix, ctx) for k, v in node.items()}
    if isinstance(node, list):
        return [_symbolise(v, prefix, ctx) for v in node]
    if isinstance(node, str):
        s = node
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]
        if ctx is not None:
            # inline string-template locals so suffixes like "/*" survive
            for _ in range(5):
                new = re.sub(r"\$\{local\.([A-Za-z0-9_-]+)\}",
                             lambda m: ctx.locals_raw.get((prefix, m.group(1))) or m.group(0), s)
                if new == s:
                    break
                s = new

        def repl(m: re.Match[str]) -> str:
            toks = _token_for(m.group(1).strip(), prefix, ctx)
            return toks[0] if len(toks) == 1 else "tf:unresolved"

        return _INTERP.sub(repl, s)
    return node


def mark_symbolic(doc: dict | None) -> dict | None:
    if doc is not None:
        doc = dict(doc)
        doc["_symbolic"] = True
    return doc
