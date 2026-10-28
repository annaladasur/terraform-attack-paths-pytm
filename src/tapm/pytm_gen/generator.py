"""Typed security graph -> executable OWASP pytm model (Python source).

The generated file is plain pytm: anyone can run ``python threat-model.py --dfd``
without this project installed. Every element carries its Terraform address,
evidence ID and source location in ``description``/``sourceFiles`` so the model is
traceable back to the plan. Output is deterministic: sorted elements, stable
UUIDs derived from addresses, no timestamps.

Evidence-fed: pytm attributes and controls that the plan can decide are set, each
with the evidence IDs behind it (``facts.py``); everything else is left at pytm's
default and reported as undecided. The model loads ``threat-library.json`` (pytm's
threats plus the cloud threat pack) when it sits next to the file. Attack-path
flows come first, so pytm numbers them in path order (DFD and ``--seq``).
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from ..graph.build import LEVEL_ORDER, BuildResult
from ..graph.kinds import ASSET_TYPES
from ..graph.model import ANY_PRINCIPAL, INTERNET, Graph, Node
from ..util import digest
from .facts import PACK_ATTRS, FactBuilder, render_value

PACK_FILE = Path(__file__).with_name("cloud_threats.json")
SCOPE_ASSUMPTIONS = [
    "Scope: resources, network exposure and IAM relationships visible in the Terraform plan.",
    "Controls not decidable from infrastructure code (input validation, output encoding, sessions...) are left undecided.",
    "IAM Conditions are flagged, not evaluated; SCPs, RCPs and session policies are out of scope.",
]

PYTM_VERSION = "1.4.0"
# the IMDS request never leaves the host, so pytm's network-transit threats do not apply to it (pytm's own mechanism:
# an Assumption that excludes threat IDs; the classifier reports them as ruled out by this assumption)
IMDS_ASSUMPTION = "IMDS is link-local: requests to 169.254.169.254 never leave the host, so network interception does not apply"
IMDS_TRANSIT_THREATS = {"CR01", "CR02", "DE01", "AC05", "DE03", "CR06", "CR08", "DR01"}
_WEAKNESS = ("HTTP", "TCP", "HTTPS")  # most to least exposed


def _ident(node_id: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", node_id)
    return "n_" + re.sub(r"_+", "_", s).strip("_")


def _uuid(key: str) -> str:
    return str(uuid.UUID(hex=digest(["pytm", key], 32)))


def _loc(n: Node) -> str:
    if not n.source:
        return ""
    return f"{n.source['file']}:{n.source['start_line']}-{n.source['end_line']}"


def _q(s: str) -> str:
    return repr(s)


def _display(node_id: str) -> str:
    """pytm writes element names into DOT unescaped; keep them quote-free (the exact address is in description)."""
    return node_id.replace('"', "'")


def threat_library() -> list[dict]:
    """pytm's built-in threats (pinned version) followed by the cloud threat pack."""
    import pytm

    builtin = json.loads((Path(pytm.__file__).parent / "threatlib" / "threats.json").read_text(encoding="utf-8"))
    return builtin + json.loads(PACK_FILE.read_text(encoding="utf-8"))


API_TYPES = ("aws_api_gateway_rest_api", "aws_apigatewayv2_api")


def _pytm_class(n: Node) -> str | None:
    if n.type in ("aws_lb", "aws_alb", "aws_instance", "aws_ecs_service") or n.type in API_TYPES:
        return "Server"
    if n.type == "aws_lambda_function":
        return "Lambda"
    if n.category == "data":
        return "Datastore"
    return None


def _drawn(g: Graph) -> dict[str, Node]:
    return {nid: n for nid, n in sorted(g.nodes.items())
            if n.type in ("aws_lb", "aws_alb") or n.type in API_TYPES or n.category == "compute" or n.type in ASSET_TYPES}


def _flows(g: Graph, drawn: dict[str, Node], paths) -> list:
    flows = []
    for e in g.edges_of("EXPOSES"):
        if e.src == INTERNET and e.dst in drawn:
            flows.append(("internet", _ident(e.dst), f"{e.label} ({e.id})", e, _proto(e.label), _port(e)))
    for e in g.edges_of("ALLOWS"):
        if e.src == ANY_PRINCIPAL and e.dst in drawn:
            flows.append(("any_principal", _ident(e.dst), f"{','.join(e.data.get('actions', []))} ({e.id})", e, "HTTPS", 443))
    for e in g.edges_of("ROUTES_TO"):
        if e.src in drawn and e.dst in drawn:
            flows.append((_ident(e.src), _ident(e.dst), f"{e.label} ({e.id})", e, _proto(e.label), _port(e)))
    for e in g.edges_of("READS", "WRITES"):
        if e.src in drawn and e.dst in drawn:
            acts = ",".join(e.data.get("actions", []))
            flows.append((_ident(e.src), _ident(e.dst), f"{acts} via {e.data.get('role')} ({e.id})", e, "HTTPS", 443))
    # the credential hop: an instance fetches its role's temporary credentials from the metadata service (IMDS)
    for e in _imds_edges(g, drawn):
        flows.append((_ident(e.src), _imds_var(e.src), f"role credentials for {e.dst} ({e.id})", e, "HTTP", 80))
    rank = _rank(flows, drawn, paths)
    order = {id(f): i for i, f in enumerate(flows)}
    return sorted(flows, key=lambda f: (0, rank[f[3].id]) if f[3].id in rank else (1, order[id(f)]))


def _imds_edges(g: Graph, drawn: dict[str, Node]) -> list:
    return [e for e in g.edges_of("ASSUMES")
            if e.label == "instance_profile" and e.src in drawn and g.nodes[e.src].type == "aws_instance"]


def _imds_var(nid: str) -> str:
    return _ident("imds_" + nid)


def _imds_name(nid: str) -> str:
    return f"IMDS of {_display(nid)}"


def _data_name(nid: str) -> str:
    return f"{_display(nid)} contents"


def _creds_name(e) -> str:
    return f"{_display(e.dst)} credentials"


def _data_stores(g: Graph, drawn: dict[str, Node]) -> list[str]:
    """Classified data stores some modelled flow reaches: they get a pytm Data object for what they hold."""
    reached = {e.dst for e in g.edges_of("READS", "WRITES") if e.src in drawn and e.dst in drawn}
    reached |= {e.dst for e in g.edges_of("ALLOWS") if e.src == ANY_PRINCIPAL and e.dst in drawn}
    return sorted(nid for nid in reached if drawn[nid].category == "data"
                  and LEVEL_ORDER.get(drawn[nid].sensitivity.get("level", "unclassified"), 0) >= 2)


def _rank(flows: list, drawn: dict[str, Node], paths) -> dict[str, int]:
    """Attack-path flows first, in hop order, so pytm numbers the path (1), (2), (3)... A hop is drawn as its own
    edge (EXPOSES, ROUTES_TO, public ALLOWS, the IMDS credential flow for ASSUMES) or, for role -> asset, as the
    READS/WRITES flow from the workload that assumed the role."""
    rank: dict[str, int] = {}
    for p in paths or []:
        actor = None
        for h in p.hops:
            if h.src in drawn or h.src in (INTERNET, ANY_PRINCIPAL):
                actor = h.src
            hit = [f for f in flows if f[3].id == h.edge]
            if not hit and actor:
                hit = [f for f in flows if f[3].type in ("READS", "WRITES") and f[3].src == actor and f[3].dst == h.dst]
            for f in hit:
                rank.setdefault(f[3].id, len(rank))
    return rank


def model_facts(result: BuildResult, answers: dict[str, dict] | None = None) -> dict[str, dict]:
    """{pytm element name: {attribute: fact}} for every drawn element and flow (written as pytm-controls.json).
    ``answers`` (from threat-answers.yaml, see questions.py) fill in controls the plan leaves open; the plan wins."""
    g = result.graph
    fb = FactBuilder(result)
    drawn = _drawn(g)
    out: dict[str, dict] = {}
    for nid, n in drawn.items():
        cls = _pytm_class(n)
        if cls is None:
            continue
        facts = {f.attr: f.to_json() for f in fb.element(nid)}
        for a in PACK_ATTRS.get(cls, ()):
            facts.setdefault(a, {"value": False, "evidence": [], "basis": "not applicable to this element"})
        out[_display(nid)] = facts
    for e in _imds_edges(g, drawn):
        out[_imds_name(e.src)] = {f.attr: f.to_json() for f in fb.imds(e.src)}
        out[f"data:{_creds_name(e)}"] = {f.attr: f.to_json() for f in fb.role_credentials(e)}
    for nid in _data_stores(g, drawn):
        out[f"data:{_data_name(nid)}"] = {f.attr: f.to_json() for f in fb.data_contents(nid)}
    for _, _, label, e, _, _ in _flows(g, drawn, None):
        facts = {f.attr: f.to_json() for f in (fb.imds_flow(e.src) if e.type == "ASSUMES" else fb.flow(e))}
        floor = out.get(_display(e.dst), {}).get("minTLSVersion")
        if floor and floor["value"] != "TLSVersion.NONE":
            facts["tlsVersion"] = {**floor, "basis": f"the listener refuses anything below its policy minimum ({floor['basis']})"}
        if facts:
            out[label] = facts
    for element, attrs in sorted((answers or {}).items()):
        if element in out:
            for attr, fact in sorted(attrs.items()):
                out[element].setdefault(attr, fact)
    return out


def _pack_threat(sid: str) -> dict:
    return next(t for t in json.loads(PACK_FILE.read_text(encoding="utf-8")) if t["SID"] == sid)


def generate(result: BuildResult, name: str, plan_sha: str, paths=None, answers: dict[str, dict] | None = None,
             source_prefix: str = "") -> str:
    """``source_prefix`` locates the Terraform files from the model's directory for pytm's ``sourceFiles`` (and
    ``--stale_days``): "" when the model sits in the Terraform root, "../" in a ``tm/`` folder (tm_skills layout)."""
    g: Graph = result.graph
    drawn = _drawn(g)
    exposed = {e.dst for e in g.edges_of("EXPOSES") if e.src == INTERNET}
    facts = model_facts(result, answers)
    recs = result.ledger.by_id()
    lines: list[str] = []
    w = lines.append

    w("#!/usr/bin/env python3")
    w(f"# GENERATED by terraform-attack-paths-pytm from plan sha256:{plan_sha[:16]}. Do not edit by hand;")
    w("# regenerate with `tapm model`. Every element cites TF-/GRAPH- evidence IDs from evidence.json, and every")
    w("# control set below cites the evidence that decides it. Controls not set here are undecided from Terraform.")
    w(f"# Requires OWASP pytm=={PYTM_VERSION}.")
    w("from pathlib import Path")
    w("from uuid import UUID")
    w("")
    w("from pytm import (TM, Actor, Assumption, Boundary, Classification, Data, Datastore, DatastoreType, Dataflow, Finding,")
    w("                  Lambda, Lifetime, Process, Server, TLSVersion)")
    w("")
    w("_library = Path(__file__).with_name('threat-library.json')  # pytm's threats + the cloud threat pack")
    w(f"tm = TM({_q(name)}, description={_q('Generated from a Terraform plan. Scope: resources, network exposure and IAM relationships visible in the plan.')},")
    w("        **({'threatsFile': str(_library)} if _library.exists() else {}))")
    w("tm.isOrdered = True")
    w("tm.mergeResponses = True")
    w(f"tm.assumptions = {SCOPE_ASSUMPTIONS!r}")
    w("")

    # boundaries
    w("# --- trust boundaries ----------------------------------------------------")
    w(f"b_internet = Boundary('Internet', uuid=UUID({_q(_uuid('b:internet'))}))")
    w(f"b_aws = Boundary('AWS APIs', uuid=UUID({_q(_uuid('b:aws'))}))")
    vpcs = sorted((n for n in g.nodes.values() if n.type == "aws_vpc"), key=lambda x: x.id)
    for v in vpcs:
        cidr = v.attributes.get("cidr_block", "")
        w(f"{_ident('b_' + v.id)} = Boundary({_q(f'VPC {cidr}'.strip() if cidr else v.id)}, uuid=UUID({_q(_uuid('b:' + v.id))}))")
    subnet_vpc = {e.dst: e.src for e in g.edges_of("CONTAINS") if g.nodes[e.src].type == "aws_vpc"}
    node_subnet = {}
    for e in g.edges_of("CONTAINS"):
        if g.nodes[e.src].type == "aws_subnet":
            node_subnet.setdefault(e.dst, e.src)
    w("")

    def boundary_for(n: Node) -> str:
        if n.id == INTERNET or n.category == "external":
            return "b_internet"
        sub = node_subnet.get(n.id)
        if sub and sub in subnet_vpc:
            return _ident("b_" + subnet_vpc[sub])
        return "b_aws"

    def emit_facts(var: str, key: str) -> None:
        for attr, f in sorted(facts.get(key, {}).items()):
            ev = ", ".join(f["evidence"])
            comment = f"  # {ev + ': ' if ev else ''}{f['basis']}"
            w(f"{var}.{attr} = {render_value(f['value'])}{comment}")

    # pytm copies protocol, port and isEncrypted from a flow's sink element onto the flow, so they are set on the
    # element: the weakest protocol any modelled flow uses to reach it.
    listen: dict[str, tuple[str, int | None]] = {}
    for _, _, _, e, proto, port in _flows(g, drawn, None):
        cur = listen.get(e.dst)
        if cur is None or _WEAKNESS.index(proto) < _WEAKNESS.index(cur[0]) or (proto == cur[0] and (port or 0) < (cur[1] or 0)):
            listen[e.dst] = (proto, port)

    w("# --- elements --------------------------------------------------------------")
    # Out-of-scope elements come first: pytm 1.4.0's resolve() hands an out-of-scope element a copy of every finding
    # produced for the elements before it (fixed on pytm main, #338). Defined first, it inherits none.
    imds_edges = _imds_edges(g, drawn)
    for e in imds_edges:
        var = _imds_var(e.src)
        w(f"{var} = Process({_q(_imds_name(e.src))}, uuid=UUID({_q(_uuid('imds:' + e.src))}))")
        w(f"{var}.inBoundary = {boundary_for(g.nodes[e.src])}")
        w(f"{var}.inScope = False  # AWS's metadata service itself; the flow to it is in scope")
        w(f"{var}.protocol = 'HTTP'")
        w(f"{var}.port = 80")
        w(f"{var}.description = {_q(f'instance metadata service of {e.src}: serves {e.dst} credentials ({e.id})')}")
        emit_facts(var, _imds_name(e.src))
    w(f"internet = Actor('Internet client', uuid=UUID({_q(_uuid('internet'))}))")
    w("internet.inBoundary = b_internet")
    w("internet.description = 'Untrusted clients on the public internet (entry condition for attack paths).'")
    if ANY_PRINCIPAL in g.nodes and g.out_edges(ANY_PRINCIPAL):
        w(f"any_principal = Actor('Any AWS principal / anonymous', uuid=UUID({_q(_uuid(ANY_PRINCIPAL))}))")
        w("any_principal.inBoundary = b_internet")
    for nid, n in drawn.items():
        var = _ident(nid)
        desc = f"{nid} | {n.aws_type} | {n.evidence or ''} | {_loc(n)}"
        cls = _pytm_class(n)
        if cls == "Server":
            w(f"{var} = Server({_q(_display(nid))}, uuid=UUID({_q(_uuid(nid))}))")
            w(f"{var}.onAWS = True")
            if n.type == "aws_instance":
                pre = [e.precondition for e in g.out_edges(nid, ("ASSUMES",)) if e.precondition]
                if pre:
                    desc += f" | credential exposure precondition: {pre[0]}"
            if nid in exposed:
                desc += " | internet-exposed"
        elif cls == "Lambda":
            w(f"{var} = Lambda({_q(_display(nid))}, uuid=UUID({_q(_uuid(nid))}))")
            w(f"{var}.onAWS = True")
        elif cls == "Datastore":
            level = n.sensitivity.get("level", "unclassified")
            w(f"{var} = Datastore({_q(_display(nid))}, uuid=UUID({_q(_uuid(nid))}))")
            w(f"{var}.onAWS = True")
            if n.type == "aws_s3_bucket":
                w(f"{var}.type = DatastoreType.AWS_S3")
            if n.type == "aws_db_instance":
                w(f"{var}.type = DatastoreType.SQL")
                w(f"{var}.isSQL = True")
            if LEVEL_ORDER.get(level, 0) >= 2:
                w(f"{var}.storesSensitiveData = True")
                w(f"{var}.maxClassification = Classification.{'SECRET' if level == 'restricted' else 'SENSITIVE'}")
            has_write = any("write" in e.data.get("access", []) for e in g.in_edges(nid, ("ALLOWS",)))
            w(f"{var}.hasWriteAccess = {has_write}")
            desc += f" | classification: {level} ({n.sensitivity.get('basis')})"
        else:
            continue
        if nid in listen:
            w(f"{var}.protocol = {_q(listen[nid][0])}")
            if listen[nid][1]:
                w(f"{var}.port = {int(listen[nid][1])}")
        w(f"{var}.inBoundary = {boundary_for(n)}")
        w(f"{var}.description = {_q(desc)}")
        if n.source:
            w(f"{var}.sourceFiles = [{_q(source_prefix + n.source['file'])}]")
        emit_facts(var, _display(nid))
        blocked = n.flags.get("public_access_blocked")
        if blocked and facts.get(_display(nid), {}).get("publicAccessBlocked", {}).get("value"):
            ev = facts[_display(nid)]["publicAccessBlocked"]["evidence"]
            ref = "; ".join(f"{x}: {recs[x].summary}" for x in ev if x in recs) or f"neutralised by {blocked.get('by')}"
            # pytm 1.4.0 blanks every threat field an override leaves unset (fixed on pytm main, #339): carry them over
            t = _pack_threat("TAPM-S3-01")
            w(f"{var}.overrides = [Finding(threat_id='TAPM-S3-01', response='mitigated', references={_q(ref)},")
            w(f"                          description={_q(t['description'])}, severity={_q(t['severity'])},")
            w(f"                          details={_q(t['details'])},")
            w(f"                          mitigations={_q(t['mitigations'])},")
            w(f"                          example={_q(t['example'])}, condition={_q(t['condition'])},")
            w(f"                          likelihood={_q(t['Likelihood Of Attack'])})]")
    w("")

    # what the flows carry: pytm Data objects, with the evidence behind each attribute; attributes the plan cannot
    # decide (does the bucket hold personal data?) are left for the owner to answer (tapm ask)
    data_var: dict = {}
    stores = _data_stores(g, drawn)
    if stores or imds_edges:
        w("# --- data carried by the flows ---------------------------------------------")
    for nid in stores:
        var = _ident("d_" + nid)
        w(f"{var} = Data({_q(_data_name(nid))})")
        emit_facts(var, f"data:{_data_name(nid)}")
        if "isPII" not in facts.get(f"data:{_data_name(nid)}", {}):
            w(f"# {var}.isPII: undecided from Terraform (ask the owner; see questions.json)")
        data_var[nid] = var
    for e in imds_edges:
        var = _ident("d_creds_" + e.src)
        w(f"{var} = Data({_q(_creds_name(e))})")
        emit_facts(var, f"data:{_creds_name(e)}")
        data_var[("creds", e.src)] = var
    if stores or imds_edges:
        w("")

    w("# --- data flows (each cites the GRAPH evidence that justifies it; attack-path flows first) --------")
    w("# pytm copies protocol, port and isEncrypted from each flow's sink element (set above); the label keeps the")
    w("# protocol this particular flow uses.")
    flow_vars: dict[str, str] = {}
    for i, (s_, d, label, e, proto, port) in enumerate(_flows(g, drawn, paths), start=1):
        var = f"df_{i:03d}"
        flow_vars[e.id] = var
        w(f"{var} = Dataflow({s_}, {d}, {_q(label)}, uuid=UUID({_q(_uuid('df:' + (e.id or str(i))))}))")
        emit_facts(var, label)
        carried = data_var.get(("creds", e.src)) if e.type == "ASSUMES" else data_var.get(e.dst)
        if carried:
            w(f"{var}.data = [{carried}]")
        if e.type == "ASSUMES":
            w(f"{var}.assumptions = [Assumption({_q(IMDS_ASSUMPTION)}, exclude={sorted(IMDS_TRANSIT_THREATS)!r})]")
        files = sorted({recs[x].source["file"] for x in e.evidence
                        if x in recs and recs[x].kind in ("NET", "IAM", "TF") and recs[x].source and recs[x].source.get("file")})
        if files:
            w(f"{var}.sourceFiles = {[source_prefix + f for f in files]!r}")
        note = f"{e.type} {e.src} -> {e.dst}; evidence: {', '.join(e.evidence)}"
        if e.precondition:
            note += f"; precondition: {e.precondition}"
        w(f"{var}.note = {_q(note)}")
    w("")

    # levels: 0 = the attack path only (the overview a non-specialist reads), 1 = the whole model
    if paths:
        rank = _rank(_flows(g, drawn, None), drawn, paths)
        on_path = {n for p in paths for n in p.nodes}
        hops = {h.edge for p in paths for h in p.hops}
        w("# --- diagram levels: 0 = the attack path only (overview), 1 = the whole model ----------")
        names = [("internet", INTERNET), ("any_principal", ANY_PRINCIPAL)] if ANY_PRINCIPAL in g.nodes and g.out_edges(ANY_PRINCIPAL) \
            else [("internet", INTERNET)]
        levels: dict[str, bool] = {var: nid in on_path for var, nid in names}
        levels.update({_ident(nid): nid in on_path for nid, n in drawn.items() if _pytm_class(n)})
        levels.update({_imds_var(e.src): e.id in hops for e in imds_edges})
        path_bounds = {boundary_for(g.nodes[nid]) for nid in on_path if nid in g.nodes and nid != ANY_PRINCIPAL}
        levels.update({b: b in path_bounds for b in ["b_internet", "b_aws"] + [_ident("b_" + v.id) for v in vpcs]})
        levels.update({var: eid in rank for eid, var in flow_vars.items()})
        for var, lv in levels.items():
            w(f"{var}.levels = {{0, 1}}" if lv else f"{var}.levels = {{1}}")
        w("")
    w(MAIN_GUARD)
    w("    tm.process()")
    return "\n".join(lines) + "\n"


MAIN_GUARD = 'if __name__ == "__main__":'
TODO = "# TODO - find the real value for this attribute"  # the tm_skills pytm skill's marker for unknown attributes


def with_open_questions(model_src: str, questions: dict | None, k: int = 12) -> str:
    """Mark the attributes the app team still has to answer, in the tm_skills convention, above the main guard.

    Comments only: the model's behaviour is unchanged. Answers go in threat-answers.yaml (they become evidence and
    the line becomes a set attribute with its APP- evidence ID) or straight into the model.
    """
    from .questions import answer_target

    if not questions or not (questions.get("questions") or questions.get("data_questions")):
        return model_src
    L = ["# --- open questions: undecided from Terraform, answerable by the app team (tapm ask) -----------------",
         "# Ordered by how many open threats each answer settles, attack-path elements first. Answer in",
         "# threat-answers.yaml next to the Terraform (reviewed like code, becomes APP- evidence) or set them here."]
    rows = [(f"Q{x['n']}", x) for x in (questions.get("questions") or [])[:k]]
    rows += [("data", x) for x in questions.get("data_questions") or []]
    for tag, x in rows:
        key, attr = answer_target(x["element"], x["control"])
        var = _ident("d_" + x["element"]) if key.startswith("data:") else _ident(x["element"])
        L.append(f"# {var}.{attr} = ?  {TODO} ({tag}: {x['question']})")
    more = len(questions.get("questions") or []) - k
    if more > 0:
        L.append(f"# … {more} more in questions.json")
    L.append("")
    head, sep, tail = model_src.rpartition(MAIN_GUARD)
    return head + "\n".join(L) + "\n" + sep + tail if sep else model_src + "\n".join(L) + "\n"


def _proto(label: str) -> str:
    l = (label or "").upper()
    if l.startswith("HTTPS"):
        return "HTTPS"
    if l.startswith("HTTP"):
        return "HTTP"
    return "TCP"


def _port(e) -> int | None:
    for p in e.data.get("ports", []) or []:
        try:
            return int(p)
        except (TypeError, ValueError):
            m = re.search(r"(\d+)", str(p))
            if m:
                return int(m.group(1))
    if e.data.get("port"):
        return int(e.data["port"])
    m = re.search(r"/(\d+)", e.label or "")
    return int(m.group(1)) if m else None
