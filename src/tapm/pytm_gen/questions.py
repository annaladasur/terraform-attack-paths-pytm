"""A few plain yes/no questions instead of a hundred threats.

Most of pytm's threats on an infrastructure model depend on controls Terraform
cannot see (does the app validate input? encode output?). The classifier marks
them "questions for the app team", but a developer who doesn't do threat modeling
will not read 107 threats. This module turns them into questions:

* one question per (element, undecided control), in plain language;
* chosen greedily: the question that settles the most open threats first, with
  threats on an attack-path hop counting double (the path is what matters);
* a threat is *settled* once every control it depends on has an answer, whatever
  the answers are, so the count never depends on guessing the answer.

Answers live next to the Terraform, in ``threat-answers.yaml``, reviewed like any
other change:

    answers:
      - element: aws_instance.app
        control: validatesInput
        answer: yes            # yes | no
        by: orders-team
        note: request models validate every endpoint

Each answer becomes an ``APP-###`` evidence record (trust: ``attested``: a person
declared it; the plan cannot prove it) and a fact in the pytm model, and the
classification runs again. Answers can settle pytm threats; they never create,
remove or re-prioritise an attack path.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ANSWERS_FILE = "threat-answers.yaml"
ON_PATH_WEIGHT = 2

# control -> (question, why it matters). {name} is the element, in plain words.
QUESTION_TEXT: dict[str, tuple[str, str]] = {
    "validatesInput": ("Does {name} check every request's input (type, length, format) before using it?",
                       "Unchecked input is how injection attacks start."),
    "sanitizesInput": ("Does {name} clean or escape input before it reaches a database, a shell or a template?",
                       "Input that reaches a query or a command unescaped can run as code."),
    "encodesOutput": ("Does {name} encode what it sends back (HTML/JSON escaping), so user data can't become code in a browser?",
                      "Unencoded output is how cross-site scripting happens."),
    "hasAccessControl": ("Does {name} check what the caller is allowed to do before every action?",
                         "Missing checks let one user read or change another user's data."),
    "authenticatesSource": ("Does {name} require callers to prove who they are (login, token, mTLS)?",
                            "Anonymous callers can use anything that doesn't ask."),
    "authorizesSource": ("After authentication, does {name} check that this caller may do this specific thing?",
                         "Authenticated is not the same as allowed."),
    "implementsAuthenticationScheme": ("Does {name} use a standard authentication scheme (OIDC, SAML, signed tokens) rather than a home-made one?",
                                       "Home-made authentication is easy to get subtly wrong."),
    "usesStrongSessionIdentifiers": ("Are the session IDs issued by {name} long, random and replaced at login?",
                                     "Guessable or fixed session IDs let attackers take over sessions."),
    "isHardened": ("Is {name} hardened: unused services off, patched, running as a least-privilege user?",
                   "Every extra service or privilege is extra attack surface."),
    "handlesResourceConsumption": ("Does {name} limit request sizes, rates and time per request?",
                                   "Without limits, one client can exhaust the service."),
    "checksInputBounds": ("Does {name} check sizes and ranges of input (lengths, counts, numbers)?",
                          "Out-of-range input causes crashes and memory bugs."),
    "providesIntegrity": ("Does {name} detect tampering with the data it handles (signatures, checksums)?",
                          "Undetected tampering means you act on forged data."),
    "usesParameterizedInput": ("Does {name} use parameterised queries for every database call?",
                               "String-built queries are the classic SQL injection."),
    "disablesDTD": ("If {name} parses XML, is DTD / external-entity processing turned off?",
                    "XML external entities can read local files or reach internal services."),
    "usesXMLParser": ("Does {name} parse XML at all?", "XML parsers bring their own class of attacks."),
    "definesConnectionTimeout": ("Does {name} set connection and session timeouts?",
                                 "Sessions that never expire stay useful to whoever steals them."),
    "encryptsCookies": ("Are the cookies set by {name} encrypted or signed, and marked Secure and HttpOnly?",
                        "Readable cookies leak session data."),
    "encryptsSessionData": ("Is session data stored by {name} encrypted?", "Session stores are a common leak."),
    "usesMFA": ("Does {name} require multi-factor authentication for its users?", "Passwords alone get phished."),
    "implementsCSRFToken": ("Do the state-changing forms and APIs of {name} require an anti-CSRF token?",
                            "Without one, another site can act as the logged-in user."),
    "verifySessionIdentifiers": ("Does {name} check that a session ID it receives is one it issued and still valid?",
                                 "Accepting any session ID invites fixation attacks."),
    "implementsServerSideValidation": ("Does {name} repeat validation on the server, not only in the browser?",
                                       "Browser checks are easily skipped."),
    "implementsNonce": ("Does {name} use nonces or timestamps so a captured request can't be replayed?",
                        "Replayed requests repeat actions the user did once."),
    "usesCodeSigning": ("Is the code {name} runs signed and checked before it runs?", "Unsigned code can be swapped."),
    "invokesScriptFilters": ("Does {name} filter scripts out of user-supplied content?", "Stored scripts run in other users' browsers."),
    "validatesContentType": ("Does {name} check the Content-Type of what it receives?", "Wrong content types confuse parsers."),
    "disablesiFrames": ("Does {name} forbid being framed by other sites (X-Frame-Options / frame-ancestors)?",
                        "Framing enables clickjacking."),
    "encodesHeaders": ("Does {name} encode values it puts into HTTP headers?", "Header injection splits responses."),
    "validatesHeaders": ("Does {name} reject malformed HTTP headers?", "Malformed headers enable request smuggling."),
    "implementsStrictHTTPValidation": ("Does {name} use strict HTTP parsing (reject ambiguous requests)?",
                                       "Ambiguous requests enable request smuggling."),
    "isResilient": ("Can {name} keep working when a dependency fails (retries, fallbacks)?", "Cascading failures become outages."),
    "usesSecureFunctions": ("Does {name} avoid unsafe functions (eval, unsafe deserialisation, strcpy...)?",
                            "Unsafe functions turn input into code or memory corruption."),
    "authenticatesDestination": ("Do clients of {name} verify its TLS certificate?", "Unverified TLS can be intercepted."),
    "checksDestinationRevocation": ("Do clients of {name} check certificate revocation?", "Revoked certificates keep working otherwise."),
    "isEncrypted": ("Is traffic to {name} encrypted (TLS)?", "Plaintext traffic can be read on the network."),
    "providesConfidentiality": ("Does {name} keep the data it handles confidential (encryption, access limits)?",
                                "Data that isn't protected leaks."),
    "usesSessionTokens": ("Does {name} use session tokens?", "Session tokens need their own protection."),
    "usesVPN": ("Does traffic to {name} run over a VPN or private link?", "Private links reduce who can reach it."),
    "implementsAPI": ("Does {name} expose an API?", "APIs are an entry point of their own."),
    "usesCache": ("Does {name} cache responses?", "Shared caches can serve one user's data to another."),
    "allowsClientSideScripting": ("Does {name} let users supply scripts or rich content?", "User scripts run in other users' browsers."),
    "hasPhysicalAccess": ("Can people get physical access to {name}?", "Physical access bypasses most controls."),
    "isShared": ("Is {name} shared with other applications or tenants?", "Shared components widen the blast radius."),
    "usesEnvironmentVariables": ("Does {name} read secrets or settings from environment variables?",
                                 "Environment variables leak through logs and debug pages."),
    # about data (pytm Data objects on the flows), answered for the store that holds it
    "storesPII": ("Does {name} hold personal data (names, emails, addresses, account or ID numbers)?",
                  "Personal data raises the stakes of every path to it, and brings legal duties."),
    "storesCredentials": ("Does {name} hold passwords, keys or tokens?", "Stored credentials turn one leak into many."),
}
# a question about a Data object is asked of the store that holds it
_DATA_CONTROL = {"isPII": "storesPII", "isCredentials": "storesCredentials"}
_DATA_ATTR = {v: k for k, v in _DATA_CONTROL.items()}
_CONTENTS = " contents"


# a flow control pytm copies from one of the flow's elements is asked of that element
_FLOW_COPIED = {"controls.isEncrypted": "sink", "controls.authenticatesDestination": "source",
                "controls.checksDestinationRevocation": "source"}


def question_key(element: str, attr: str, flow: dict | None = None) -> tuple[str, str] | None:
    """(who the question is asked of, what is asked); None when the attribute is not a yes/no question."""
    if flow and attr in _FLOW_COPIED:
        return flow[_FLOW_COPIED[attr]], attr
    if attr.startswith("data:"):
        name, a = attr[len("data:"):].rsplit(".", 1)
        if a not in _DATA_CONTROL:
            return None
        return (name[: -len(_CONTENTS)] if name.endswith(_CONTENTS) else name), _DATA_CONTROL[a]
    return element, attr


def answer_target(element: str, control: str) -> tuple[str, str]:
    """Where an answer lands in the model facts: (facts key, attribute)."""
    if control in _DATA_ATTR:
        return f"data:{element}{_CONTENTS}", _DATA_ATTR[control]
    return element, (control if control in _NOT_CONTROLS else f"controls.{control}")
_ANSWER = {"yes": True, "no": False, True: True, False: False}


def control_name(attr: str) -> str:
    """'controls.validatesInput' -> 'validatesInput'."""
    return attr.split(".")[-1]


def plain_name(element: str) -> str:
    """'aws_instance.app' -> 'the app (aws_instance.app)'; flows keep their label."""
    m = re.match(r"^((?:module\.[\w-]+(?:\[[^\]]*\])?\.)*)aws_([a-z0-9_]+)\.([\w-]+)(?:\[\"?([^\]\"]*)\"?\])?$", element)
    if not m:
        return element
    mods, typ, name, key = m.groups()
    kind = {"lb": "load balancer", "alb": "load balancer", "instance": "server", "lambda_function": "function",
            "s3_bucket": "bucket", "db_instance": "database", "dynamodb_table": "table", "iam_role": "role",
            "iam_user": "user", "iam_group": "group", "secretsmanager_secret": "secret", "api_gateway_rest_api": "API",
            "apigatewayv2_api": "API", "ecs_service": "container service", "ssm_parameter": "parameter"}.get(typ, typ.replace("_", " "))
    if name in ("this", "main", "default", "self") and mods:  # module-internal names say nothing: use the module's
        name = re.findall(r"module\.([\w-]+)", mods)[-1]
    if key:
        name = f"{name}-{key}"
    return f"the {name.replace('_', '-')} {kind} ({element})"


# app-layer controls that a load balancer only provides through a web application firewall in front of the app
_WAF_CONTROLS = {"validatesInput", "sanitizesInput", "encodesOutput", "checksInputBounds", "invokesScriptFilters",
                 "validatesContentType", "usesParameterizedInput"}


def question_text(element: str, attr: str) -> tuple[str, str]:
    q, why = QUESTION_TEXT.get(control_name(attr), (f"Is `{control_name(attr)}` true for {{name}}?", ""))
    q = q.format(name=plain_name(element))
    if re.match(r"^(?:module\.[\w-]+\.)*aws_(lb|alb)\.", element) and control_name(attr) in _WAF_CONTROLS:
        q += " (For a load balancer: is a WAF rule doing this in front of the app?)"
    return q, why


def select_questions(classification: dict) -> dict:
    """Greedy: at each step the (element, control) question that settles the most open threats (path-hop threats
    count double). Returns the ordered questions and how many threats each settles."""
    open_rows = [r for r in classification["findings"] if r["class"] == "needs_app_team"]
    boolean = lambda a: not a.endswith(("data", "tlsVersion", "checkTLSVersion", "hasDataLeaks", "environment"))  # noqa: E731
    need = []
    for r in open_rows:
        keys = [question_key(r["element"], a, r.get("flow")) for a in r["undecided"]]
        qs = {k for k in keys if k}
        yes_no = all(k is not None for k in keys) and all(boolean(a) for a in r["undecided"])
        need.append((qs, ON_PATH_WEIGHT if r.get("on_paths") else 1, r, yes_no))
    answerable = [n for n in need if n[3]]
    asked: set = set()
    out = []
    while True:
        best, gain, weight = None, 0, 0
        cands = sorted({q for qs, _, _, _ in answerable for q in qs if q not in asked})
        for q in cands:
            now = [(w, r) for qs, w, r, _ in answerable if not qs <= asked and qs <= asked | {q}]
            wsum = sum(w for w, _ in now)
            if wsum > weight:
                best, gain, weight = q, len(now), wsum
        if best is None:
            break
        asked.add(best)
        settled = [r for qs, _, r, _ in answerable if qs <= asked]
        element, attr = best
        text, why = question_text(element, attr)
        out.append({"n": len(out) + 1, "element": element, "control": control_name(attr),
                    "question": text, "why": why, "settles": gain,
                    "settles_on_path": sum(1 for qs, w, r, _ in answerable if w > 1 and qs <= asked and not qs <= asked - {best}),
                    "cumulative": len(settled)})
    # questions about the data itself (does the bucket hold personal data?) inform threats that also depend on things
    # yes/no cannot settle; they are the questions a data owner, technical or not, can answer at once
    asked_keys = {(x["element"], x["control"]) for x in out}
    informs: dict[tuple[str, str], int] = {}
    for qs, _, r, _ in need:
        for k in qs:
            if k[1] in _DATA_ATTR and k not in asked_keys:
                informs[k] = informs.get(k, 0) + 1
    data_questions = []
    for (element, control), n in sorted(informs.items(), key=lambda kv: (-kv[1], kv[0][1] != "storesPII", kv[0])):
        text, why = question_text(element, control)
        data_questions.append({"element": element, "control": control, "question": text, "why": why, "informs": n})
    return {"open": len(open_rows), "answerable": len(answerable), "not_yes_no": len(need) - len(answerable),
            "questions": out, "data_questions": data_questions}


def coverage(selection: dict, k: int) -> int:
    """How many open threats the first k questions settle."""
    qs = selection["questions"][:k]
    return qs[-1]["cumulative"] if qs else 0


# ------------------------------------------------------------------ answers
def load_answers(path: str | Path) -> list[dict]:
    """``threat-answers.yaml`` (normally next to the Terraform); malformed entries are reported, never guessed."""
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()
    doc = yaml.safe_load("\n".join(lines)) or {}
    out = []
    for i, a in enumerate(doc.get("answers") or []):
        a = dict(a or {})
        ans = a.get("answer")
        ans = _ANSWER.get(ans if isinstance(ans, bool) else str(ans).strip().lower())
        line = next((n for n, l in enumerate(lines, start=1) if f"control: {a.get('control')}" in l
                     and any(f"element: {a.get('element')}" in lines[m] for m in range(max(0, n - 4), n))), None)
        out.append({"index": i, "element": str(a.get("element", "")), "control": str(a.get("control", "")),
                    "answer": ans, "by": str(a.get("by", "")), "note": str(a.get("note", ""))[:200],
                    "line": line, "valid": ans is not None and bool(a.get("element")) and bool(a.get("control"))})
    return out


def register_answers(result, answers: list[dict]) -> dict[str, dict]:
    """Record each valid answer as APP-### evidence; return {element: {attribute: fact}} for the model."""
    facts: dict[str, dict] = {}
    for a in answers:
        if not a["valid"]:
            continue
        key, attr = answer_target(a["element"], a["control"])
        src = {"file": ANSWERS_FILE, "start_line": a["line"] or 1, "end_line": a["line"] or 1}
        rid = result.ledger.append("APP", (a["element"], a["control"]),
                                   f"{a['element']}: {a['control']} = {'yes' if a['answer'] else 'no'} (answered by {a['by'] or 'unknown'})",
                                   source=src, data={"element": a["element"], "control": a["control"], "answer": a["answer"],
                                                     "by": a["by"], "note": a["note"]}, trust="attested")
        facts.setdefault(key, {})[attr] = {
            "value": a["answer"], "evidence": [rid],
            "basis": f"answered by {a['by'] or 'unknown'}" + (f": {a['note']}" if a["note"] else "")}
    return facts


# element attributes that are not under .controls in pytm 1.4
_NOT_CONTROLS = {"usesXMLParser", "usesSessionTokens", "usesVPN", "implementsAPI", "usesCache", "allowsClientSideScripting",
                 "hasPhysicalAccess", "isShared", "usesEnvironmentVariables"}


def answer_status(answers: list[dict], facts: dict[str, dict], controls: dict[str, dict]) -> list[dict]:
    """What happened to each answer: applied, ignored because the plan decides it, unknown element, or malformed."""
    out = []
    for a in answers:
        key, attr = answer_target(a["element"], a["control"])
        if not a["valid"]:
            status = "malformed (needs element, control and answer yes/no)"
        elif key not in controls:
            status = "unknown element (not in the model)"
        elif controls[key].get(attr, {}).get("evidence") != facts.get(key, {}).get(attr, {}).get("evidence"):
            status = "ignored: the plan decides this control"
        else:
            status = "applied"
        out.append({**{k: a[k] for k in ("element", "control", "answer", "by", "line")}, "status": status,
                    "evidence": facts.get(key, {}).get(attr, {}).get("evidence", [])})
    return out


def answer_effect(classification: dict) -> dict:
    """How many pytm threats the answers decided, split into confirmed (a 'no' left the threat standing) and ruled
    out (a 'yes' removed it)."""
    out = {"confirmed": 0, "ruled_out": 0}
    for r in classification["findings"]:
        if r["class"] in out and any(x.startswith("APP-") for v in r["decided"].values() for x in v["evidence"]):
            out[r["class"]] += 1
    return out
