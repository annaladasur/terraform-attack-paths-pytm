"""An attack path in plain words: one screen for someone who has never done threat modeling.

Built deterministically from the same evidence as the report, so it can't say anything the pipeline didn't
establish. Two audiences:

* ``developer``: plain sentences plus the file and line to change;
* ``everyone``: no file names, evidence IDs or jargon; a short glossary instead.

The AI can re-tell it for a particular reader (the ``plain_explainer`` agent); that version goes through the same
validator as every other annotation. This one needs no model.
"""

from __future__ import annotations

import re

from .. import SCOPE_STATEMENT
from ..graph.model import ACCOUNT_ADMIN, ANY_PRINCIPAL, INTERNET
from ..pytm_gen.questions import plain_name

GLOSSARY = {
    "attack path": "a chain of steps someone could take, where the configuration allows every step",
    "IMDS": "a local address every cloud server can call to get its own cloud keys",
    "IMDSv2": "the newer IMDS setting that asks for a token first, so a tricked request can't get the keys",
    "SSRF": "a bug that lets an outsider make your server fetch a web address of their choosing",
    "role": "the cloud identity a server or function runs as; its permissions decide what its keys can do",
    "wildcard": "a permission written with *, covering everything of a kind instead of only what is needed",
    "load balancer": "the front door that passes internet traffic on to your servers",
    "bucket": "a cloud storage folder (Amazon S3)",
    "condition": "something else that must also be true for the path to work, and that Terraform can't show",
}
_ACCESS = {"read": "read", "list": "list", "write": "change", "delete": "delete", "admin": "do anything with",
           "permissions": "change the permissions of", "tagging": "re-tag"}
_PRE = {
    "workload_ssrf": "if they find a way to make {src} fetch a web address for them (an SSRF bug) or run code on it",
    "workload_rce": "if they can run code on {src}",
    "container_escape": "if they can run code in {src} and break out of its container",
    "credential_compromise": "if they get hold of {src}'s access keys",
    "condition_satisfied": "if the condition attached to the permission is met",
}


def _name(addr: str, audience: str) -> str:
    if addr == INTERNET:
        return "anyone on the internet"
    if addr == ANY_PRINCIPAL:
        return "anyone at all"
    if addr == ACCOUNT_ADMIN:
        return "administrator of the whole AWS account"
    n = plain_name(addr)
    return re.sub(r" \([^)]*\)$", "", n) if audience == "everyone" else n


def _access(acc: list[str]) -> str:
    words = [_ACCESS.get(a, a) for a in acc] or ["use"]
    return " and ".join(dict.fromkeys(words))


def _loc(recs: dict, ids: list[str], kinds=("NET", "IAM", "TF")) -> str:
    for i in ids:
        r = recs.get(i)
        if r is not None and r.kind in kinds and r.source and r.source.get("file"):
            a, b = r.source.get("start_line"), r.source.get("end_line")
            return f"{r.source['file']}:{a}" + (f"-{b}" if b and b != a else "")
    return ""


def _wildcard(recs: dict, ids: list[str]) -> bool:
    from ..pytm_gen.facts import wildcard_resource

    for i in ids:
        r = recs.get(i)
        st = (r.data or {}).get("statement", {}) if r is not None and r.kind == "IAM" else {}
        if any(wildcard_resource(x) for x in st.get("resources", [])) or st.get("not_resources"):
            return True
    return False


def _resource_policy(recs: dict, ids: list[str]) -> str | None:
    """The resource policy (e.g. a bucket policy) that makes the grant, if the grant comes from one."""
    for i in ids:
        r = recs.get(i)
        if r is not None and r.kind == "IAM" and (r.data or {}).get("policy_kind") == "resource":
            return (r.data or {}).get("policy")
    return None


def _cap(t: str) -> str:
    return t[:1].upper() + t[1:]


def path_story(res, path, audience: str = "developer") -> dict:
    g = res.build.graph
    recs = res.build.ledger.by_id()
    by_id = {e.id: e for e in g.edges.values() if e.id}
    n = lambda a: _name(a, audience)  # noqa: E731
    target = g.nodes[path.target]
    level = target.sensitivity.get("level", "classified")
    first = path.hops[0]
    who = "Someone on the internet" if path.entry == INTERNET else f"Someone holding the keys of {n(path.entry)}"
    grants = [h for h in path.hops if h.type == "ALLOWS" and h.dst == path.target]
    edge = by_id.get(grants[-1].edge) if grants else None
    acc = _access((edge.data.get("access") if edge is not None else None) or ["read"])
    pres = [_PRE[h.precondition].format(src=n(h.src)) for h in path.hops if h.precondition in _PRE]
    if path.target == ACCOUNT_ADMIN:
        what = f"{who} could become {n(path.target)}"
    else:
        what = f"{who} could {acc} {n(path.target)}, which holds {level} data"
    what += (f", {pres[0]}" if pres else "") + "."

    steps = []
    for i, h in enumerate(path.hops, start=1):
        ev = [h.edge] + list(h.evidence)
        imds = [i for i in ev if recs.get(i) is not None and "http_tokens" in (recs[i].data or {})]
        where = _loc(recs, imds or ev)  # the IMDS hop is fixed where metadata_options is, not in the role
        if h.dst == ANY_PRINCIPAL:
            continue  # "the internet counts as anyone": says nothing a reader needs
        if h.type == "EXPOSES" and h.src == INTERNET:
            label = h.label or ""
            txt = f"Anyone on the internet can reach {n(h.dst)}" + (f" ({label})" if label and audience == "developer" else "") + "."
            if "function_url" in label:
                txt = f"Anyone on the internet can call {n(h.dst)} without logging in."
        elif h.type == "ROUTES_TO":
            txt = f"{_cap(n(h.src))} passes those requests on to {n(h.dst)}."
        elif h.type == "ASSUMES" and h.label == "instance_profile":
            txt = f"{_cap(n(h.src))} can fetch the cloud keys of {n(h.dst)} from a local address (IMDS)."
            if h.precondition == "workload_ssrf":
                txt += " Because the older IMDS setting is allowed, a request someone tricks the server into making can fetch them too."
        elif h.type == "ASSUMES":
            txt = f"{_cap(n(h.src))} can take on {n(h.dst)}."
        elif h.type == "ALLOWS" and h.src == ANY_PRINCIPAL:
            txt = f"The access policy of {n(h.dst)} lets anyone {_access((by_id[h.edge].data.get('access') if h.edge in by_id else None) or [])} it."
        elif h.type == "ALLOWS":
            e = by_id.get(h.edge)
            a = _access((e.data.get("access") if e is not None else None) or [])
            txt = f"Those keys are allowed to {a} {n(h.dst)}"
            if _resource_policy(recs, ev):
                kind = re.sub(r" \([^)]*\)$", "", plain_name(h.dst)).split()[-1]
                txt += f", because the {kind}'s own access policy names {n(h.src)}."
            elif _wildcard(recs, ev):
                txt += " because the permission covers everything of that kind (a wildcard), not only what is needed."
            else:
                txt += "."
        elif h.type == "ESCALATES":
            txt = f"{_cap(n(h.src))} can give itself more permissions" + (f" ({h.label})." if audience == "developer" else ".")
        elif h.type == "TRUSTS":
            txt = f"{_cap(n(h.src))} trusts {n(h.dst)}."
        else:
            txt = f"{n(h.src)} {h.type.lower().replace('_', ' ')} {n(h.dst)}."
        steps.append({"n": len(steps) + 1, "text": txt, "where": where if audience == "developer" else "",
                      "evidence": ev if audience == "developer" else [], "assumption": h.status == "ASSUMPTION"})

    fix = _fix(res, path, audience)
    q = (res.pytm or {}).get("questions") or {}
    on_path = set(path.nodes)
    asks = [x for x in q.get("data_questions", []) if x["element"] == path.target][:1]
    asks += [x for x in q.get("questions", []) if x["element"] in on_path][:2]
    terms = [t for t in GLOSSARY if any(t.lower() in s["text"].lower() for s in steps) or t.lower() in what.lower()]
    if pres:
        terms.append("condition")
    return {"path": path.id, "priority": path.priority, "status": path.status, "audience": audience,
            "headline": f"{path.priority.upper()}: {what}", "what_could_happen": what, "steps": steps, "fix": fix,
            "questions": [{"question": re.sub(r" \([^)]*\)", "", x["question"]) if audience == "everyone" else x["question"],
                           "why": x["why"]} for x in asks],
            "glossary": {t: GLOSSARY[t] for t in dict.fromkeys(terms)} if audience == "everyone" else {}}


def _hop_fix(res, h, audience: str, fallback: str = "") -> str:
    """The change that removes one hop, in words for the audience."""
    n = lambda a: _name(a, audience)  # noqa: E731
    if h is None:
        return fallback
    if h.type == "ALLOWS" and h.src == ANY_PRINCIPAL:
        return f"Remove public access from the policy of {n(h.dst)}, or turn on S3 Block Public Access for it"
    if h.type == "ALLOWS" and _resource_policy(res.build.ledger.by_id(), [h.edge] + list(h.evidence)):
        return f"Remove {n(h.src)} from the access policy of {n(h.dst)}, or limit what that policy lets it do"
    if h.type == "ALLOWS":
        return f"Narrow the permission of {n(h.src)} to the resources it actually needs, so it no longer covers {n(h.dst)}"
    if h.type == "ASSUMES" and h.label == "instance_profile":
        return f"Require IMDSv2 on {n(h.src)}"
    if h.type == "EXPOSES":
        return f"Stop exposing {n(h.dst)} to the whole internet: limit who can reach it"
    if h.type == "ASSUMES":
        return f"Stop {n(h.src)} from taking on {n(h.dst)}"
    return f"Remove the ability of {n(h.src)} to reach {n(h.dst)}"


def _fix(res, path, audience: str) -> dict | None:
    """The proven fix if the remediation loop ran, else the change the path engine computed breaks the path."""
    hops = {i + 1: h for i, h in enumerate(path.hops)}
    rem = next((p for p in ((res.remediation or {}).get("paths") or []) if p["path"] == path.id), None) \
        if getattr(res, "remediation", None) else None
    if rem and rem.get("recommended_attempt"):
        a = next(x for x in rem["attempts"] if x["n"] == rem["recommended_attempt"])
        effect = "the path disappears" if a["status"] == "PROVEN_BREAK" else f"the risk drops from {a['priority_before']} to {a['priority_after']}"
        what = _hop_fix(res, hops.get(a["patch"].get("hop")), audience, "Apply the verified patch")
        dev = audience == "developer"
        return {"text": f"{what}. A patch for this was re-planned and re-checked: {effect}"
                        + (f" (`remediation-{path.id}.diff`)." if dev else "."),
                "where": a["patch"]["file"] if dev else "", "proven": True, "diff": rem.get("recommended_diff") if dev else None}
    breaks = [r for r in res.remedies if r.path == path.id and r.effect == "breaks_path"]
    order = {"ALLOWS": 0, "ASSUMES": 1, "ESCALATES": 1, "ROUTES_TO": 2, "EXPOSES": 3}
    breaks.sort(key=lambda r: order.get(hops[r.hop].type if r.hop in hops else "", 9))
    if not breaks:
        return None
    r = breaks[0]
    text = _hop_fix(res, hops.get(r.hop), audience, r.change)
    recs = res.build.ledger.by_id()
    where = _loc(recs, list(r.evidence)) if audience == "developer" else ""
    return {"text": f"{text}. The path engine re-ran itself with this change: the path disappears.", "where": where,
            "proven": False, "diff": None}


def render_story(story: dict) -> str:
    L = [f"**{story['headline']}**", ""]
    L.append("How:")
    L.append("")
    for s in story["steps"]:
        tail = f" `{s['where']}`" if s["where"] else ""
        mark = " *(needs the condition above)*" if s["assumption"] else ""
        L.append(f"{s['n']}. {s['text']}{mark}{tail}")
    L.append("")
    if story["fix"]:
        L.append(f"**What to change:** {story['fix']['text']}" + (f" `{story['fix']['where']}`" if story["fix"]["where"] else ""))
        L.append("")
    if story["questions"]:
        L.append("**What we need to know from you** (answer in `threat-answers.yaml`):")
        L.append("")
        for q in story["questions"]:
            L.append(f"- {q['question']}")
        L.append("")
    if story["glossary"]:
        L.append("<details><summary>Words used here</summary>")
        L.append("")
        for t, d in story["glossary"].items():
            L.append(f"- **{t}**: {d}")
        L.append("")
        L.append("</details>")
        L.append("")
    return "\n".join(L)


def render_stories(res, audience: str = "everyone") -> str:
    """Every path as a card: the ``story.md`` artifact, meant to be forwarded to anyone."""
    L = [f"# What could go wrong in {res.cfg.name}, in plain words", ""]
    if audience == "everyone":
        L += ["> Written for anyone on the team, whether or not they write Terraform. Each card is generated from "
              "the checked evidence in `report.md`; the developer version there has file and line numbers.", ""]
    if not res.paths:
        L += ["No way in: nothing in this configuration lets someone on the internet reach the sensitive data.", ""]
    for i, p in enumerate(res.paths, start=1):
        head = f"Path {i}" if audience == "everyone" else p.id  # the report calls it PATH-00{i}
        L += [f"## {head}", "", render_story(path_story(res, p, audience)).rstrip("\n"), ""]
    L += ["---", f"**Scope:** {SCOPE_STATEMENT}", ""]
    return "\n".join(L)
