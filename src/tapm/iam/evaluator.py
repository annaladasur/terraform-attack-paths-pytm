"""Deterministic IAM evaluation over the Terraform-visible policy set.

Produces graph edges that Terraform never states explicitly:

* ``ATTACHES``  instance -> instance profile -> role, principal -> policy
* ``TRUSTS``    role -> principal named in its trust policy
* ``ASSUMES``   workload -> role (instance profile / execution role),
                principal -> role (sts:AssumeRole, iam:PassRole combos, takeovers)
* ``ALLOWS``    principal -> asset, with the evaluated actions and access classes
* ``ESCALATES`` principal -> ``aws:account-admin`` (admin-equivalent or self-grant)

Every edge cites IAM-### statement records and TF-### resource records.
See ``tapm.iam.policy`` for what is and is not evaluated.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..evidence.ledger import Ledger, handle
from ..graph.kinds import ASSET_TYPES
from ..graph.model import ACCOUNT_ADMIN, ANY_PRINCIPAL, INTERNET, Edge, Graph, Node
from ..terraform.plan import Plan, PlanResource
from ..terraform.source import SourceIndex
from ..terraform.symbolic import symbolic_policy_from_document_config, symbolic_policy_from_source
from ..util import as_list
from .policy import UNKNOWN, PolicyDoc, Statement, arn_matches, concretize, parse_document

DATA = Path(__file__).parent / "data"


@lru_cache(maxsize=None)
def _data(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def action_catalog() -> dict[str, dict[str, dict]]:
    return {k: v for k, v in _data("actions.json").items() if not k.startswith("_")}


def escalation_rules() -> list[dict]:
    return _data("escalation.json")["rules"]


def managed_policies() -> dict[str, dict]:
    return {k: v for k, v in _data("managed_policies.json").items() if not k.startswith("_")}


@dataclass
class PolicySource:
    address: str  # policy resource address, or a managed policy ARN
    kind: str  # inline | managed | aws_managed | boundary | resource | trust
    doc: PolicyDoc | None
    provenance: str  # plan | policy_document | symbolic_source | symbolic_config | aws_managed_summary | unresolved
    via: list[str] = field(default_factory=list)  # attachment resource addresses
    tf_address: str | None = None  # resource that holds the document (for source location)
    attr: str = "policy"


@dataclass
class Principal:
    node: Node
    res: PlanResource
    name_token: str
    arn: str
    identity: list[PolicySource] = field(default_factory=list)
    boundary: PolicySource | None = None
    groups: list[str] = field(default_factory=list)  # group base addresses


def marker(base: str) -> str:
    """Stand-in for a value the plan does not know yet, unique per resource."""
    return f"\x02{base}\x02"


class IamEvaluator:
    def __init__(self, plan: Plan, src: SourceIndex, graph: Graph, ledger: Ledger, tf: dict[str, str]):
        self.plan = plan
        self.src = src
        self.g = graph
        self.ledger = ledger
        self.tf = tf  # resource address -> TF ledger handle
        self.region = _provider_region(plan.raw)
        self.principals: dict[str, Principal] = {}
        self.unresolved: list[dict] = []

    # ------------------------------------------------------------------ helpers
    def _known(self, r: PlanResource, attr: str) -> Any:
        if r.is_unknown(attr):
            return None
        return r.values.get(attr)

    def _name(self, r: PlanResource, attr: str) -> str:
        v = self._known(r, attr)
        return str(v) if v not in (None, "") else marker(r.address)

    def arn_of(self, r: PlanResource, form: str | None = None) -> str:
        t = r.type
        acct = UNKNOWN
        region = self.region
        if t == "aws_s3_bucket":
            base = f"arn:aws:s3:::{self._name(r, 'bucket')}"
            return base + "/\x03object" if form == "object" else base
        if t in ("aws_iam_role", "aws_iam_user", "aws_iam_group", "aws_iam_policy"):
            kind = {"aws_iam_role": "role", "aws_iam_user": "user", "aws_iam_group": "group", "aws_iam_policy": "policy"}[t]
            path = self._known(r, "path") or "/"
            return f"arn:aws:iam::{acct}:{kind}{path}{self._name(r, 'name')}"
        if t == "aws_secretsmanager_secret":
            return f"arn:aws:secretsmanager:{region}:{acct}:secret:{self._name(r, 'name')}-{UNKNOWN}"
        if t == "aws_ssm_parameter":
            return f"arn:aws:ssm:{region}:{acct}:parameter/{self._name(r, 'name').lstrip('/')}"
        if t == "aws_kms_key":
            return f"arn:aws:kms:{region}:{acct}:key/{marker(r.address)}"
        if t == "aws_dynamodb_table":
            return f"arn:aws:dynamodb:{region}:{acct}:table/{self._name(r, 'name')}"
        if t == "aws_db_instance":
            return f"arn:aws:rds:{region}:{acct}:db:{self._name(r, 'identifier')}"
        if t == "aws_lambda_function":
            return f"arn:aws:lambda:{region}:{acct}:function:{self._name(r, 'function_name')}"
        if t == "aws_instance":
            return f"arn:aws:ec2:{region}:{acct}:instance/{marker(r.address)}"
        return f"arn:aws:unknown:{region}:{acct}:{marker(r.address)}"

    def _name_token(self, r: PlanResource) -> str:
        attr = {"aws_s3_bucket": "bucket", "aws_db_instance": "identifier", "aws_lambda_function": "function_name"}.get(r.type, "name")
        return self._name(r, attr)

    def matches_resource(self, st: Statement, r: PlanResource, form: str | None, own_policy: bool = False) -> bool:
        arn = self.arn_of(r, form)
        name = self._name_token(r)
        bucket_arn = self.arn_of(r) if r.type == "aws_s3_bucket" else arn

        def one(p: str) -> bool:
            c = concretize(p, r.base, name, bucket_arn, r.address)
            return arn_matches(c, arn)

        if st.resources:
            return any(one(p) for p in st.resources)
        if st.not_resources:
            return not any(one(p) for p in st.not_resources)
        return own_policy

    def matches_principal(self, st: Statement, p: Principal) -> tuple[bool, str]:
        """Does a resource/trust policy statement name this principal? -> (match, how)"""
        for ident in st.principals.get("AWS", []):
            if ident == "*":
                return True, "any"
            if re.fullmatch(r"\d{12}", ident) or ident.endswith(":root"):
                return True, "account"
            c = concretize(ident, p.res.base, p.name_token, p.arn, p.res.address)
            if arn_matches(c, p.arn):
                return True, "direct"
        return False, ""

    def _stmt_record(self, src: PolicySource, st: Statement) -> str:
        loc = None
        if src.tf_address:
            base = self.plan.resources[src.tf_address].base if src.tf_address in self.plan.resources else src.tf_address
            needle = st.sid or (st.actions[0] if st.actions else None)
            focus = self.src.locate_text(base, f'"{needle}"') if needle else None
            loc = self.src.locate_member(base, src.attr) or self.src.locate(base)
            if loc and focus and loc["start_line"] <= focus["start_line"] <= loc["end_line"]:
                loc = dict(loc, focus_line=focus["start_line"])
            elif focus and not loc:
                loc = focus
        acts = st.actions or [f"NOT {a}" for a in st.not_actions]
        ress = st.resources or [f"NOT {r}" for r in st.not_resources] or \
            (["this role (trust policy)"] if src.kind == "trust" else ["this resource (resource policy)"])
        princ = ""
        if st.principals:
            princ = " for " + "; ".join(f"{k}:{','.join(v)}" for k, v in sorted(st.principals.items()))
        summary = (f"{src.address} statement {st.index}{' (' + st.sid + ')' if st.sid else ''}: "
                   f"{st.effect} {', '.join(acts)} on {', '.join(ress)}{princ}"
                   f"{' [conditional]' if st.conditional else ''}")
        refs = [self.tf[a] for a in [src.tf_address, *src.via] if a and a in self.tf]
        return self.ledger.add(
            "IAM", ("stmt", src.kind, src.address, st.index), summary, source=loc,
            data={"policy": src.address, "policy_kind": src.kind, "provenance": src.provenance,
                  "approximate": bool(src.doc and src.doc.approximate) or src.provenance.startswith("symbolic"),
                  "statement": st.to_json()},
            refs=refs,
        )

    # ------------------------------------------------------------ documents
    def doc_for(self, r: PlanResource, attr: str = "policy") -> tuple[PolicyDoc | None, str, str | None]:
        """Resolve a policy document attribute -> (doc, provenance, holder address)."""
        val = self._known(r, attr)
        if isinstance(val, str) and val.strip():
            return parse_document(val), "plan", r.address
        for ref in r.references.get(attr, []):
            if ref.startswith(("data.aws_iam_policy_document.", "module.")) and ".data.aws_iam_policy_document." in f".{ref}":
                pass
            if "data.aws_iam_policy_document." in ref:
                for d in self.plan.instances_of(ref):
                    j = self._known(d, "json")
                    if isinstance(j, str) and j:
                        return parse_document(j), "policy_document", d.address
                    sym = symbolic_policy_from_document_config(d, self._resolver())
                    if sym:
                        return parse_document(sym), "symbolic_config", d.address
        sym = symbolic_policy_from_source(r, attr, self.src, self._resolver())
        if sym:
            return parse_document(sym), "symbolic_source", r.address
        return None, "unresolved", r.address

    def _resolver(self):
        return self.plan.ctx

    def managed_doc(self, arn: str) -> PolicyDoc | None:
        m = managed_policies().get(arn)
        if not m:
            return None
        doc = parse_document({"Statement": m["Statement"]})
        if doc:
            doc.approximate = bool(m.get("approximate"))
        return doc

    def policy_from_arn_attr(self, att: PlanResource, attr: str = "policy_arn") -> PolicySource:
        for ref in att.references.get(attr, []):
            for pol in self.plan.instances_of(ref):
                if pol.type == "aws_iam_policy":
                    doc, prov, holder = self.doc_for(pol)
                    return PolicySource(pol.address, "managed", doc, prov, via=[att.address], tf_address=holder)
        arn = self._known(att, attr)
        if isinstance(arn, str):
            doc = self.managed_doc(arn)
            if doc:
                return PolicySource(arn, "aws_managed", doc, "aws_managed_summary", via=[att.address])
            for pol in self.plan.by_type("aws_iam_policy"):
                if arn.endswith(f":policy/{self._known(pol, 'name')}"):
                    d, prov, holder = self.doc_for(pol)
                    return PolicySource(pol.address, "managed", d, prov, via=[att.address], tf_address=holder)
        src = PolicySource(str(arn or att.address), "managed", None, "unresolved", via=[att.address])
        self.unresolved.append({"attachment": att.address, "policy_arn": arn})
        return src

    # ----------------------------------------------------------- principals
    def _refers(self, r: PlanResource, attr: str, target: PlanResource) -> bool:
        if target.base in r.references.get(attr, []):
            return True
        vals = as_list(self._known(r, attr))
        name = self._known(target, "name")
        return bool(name) and any(str(v) == str(name) or str(v).endswith(f"/{name}") for v in vals)

    def collect_principals(self) -> None:
        roles = self.plan.by_type("aws_iam_role")
        users = self.plan.by_type("aws_iam_user")
        groups = self.plan.by_type("aws_iam_group")
        for r in roles + users:
            if r.address not in self.g.nodes:
                continue
            p = Principal(self.g.nodes[r.address], r, self._name(r, "name"), self.arn_of(r))
            self.principals[r.address] = p

        inline_types = {"aws_iam_role": ("aws_iam_role_policy", "role"), "aws_iam_user": ("aws_iam_user_policy", "user")}
        attach_types = {"aws_iam_role": ("aws_iam_role_policy_attachment", "role"),
                        "aws_iam_user": ("aws_iam_user_policy_attachment", "user")}
        for p in self.principals.values():
            r = p.res
            itype, iattr = inline_types[r.type]
            for pol in self.plan.by_type(itype):
                if self._refers(pol, iattr, r):
                    doc, prov, holder = self.doc_for(pol)
                    p.identity.append(PolicySource(pol.address, "inline", doc, prov, tf_address=holder))
                    self._attach_edge(p, pol.address, pol.address)
            atype, aattr = attach_types[r.type]
            for att in self.plan.by_type(atype):
                if self._refers(att, aattr, r):
                    ps = self.policy_from_arn_attr(att)
                    p.identity.append(ps)
                    self._attach_edge(p, ps.address, att.address)
            plural = "roles" if r.type == "aws_iam_role" else "users"
            for att in self.plan.by_type("aws_iam_policy_attachment"):
                if self._refers(att, plural, r):
                    ps = self.policy_from_arn_attr(att)
                    p.identity.append(ps)
                    self._attach_edge(p, ps.address, att.address)
            for i, ip in enumerate(as_list(self._known(r, "inline_policy"))):
                if isinstance(ip, dict) and ip.get("policy"):
                    doc = parse_document(ip["policy"])
                    p.identity.append(PolicySource(f"{r.address}.inline_policy[{i}]", "inline", doc, "plan", tf_address=r.address, attr="inline_policy"))
            for ref in r.references.get("managed_policy_arns", []):
                for pol in self.plan.instances_of(ref):
                    if pol.type == "aws_iam_policy":
                        doc, prov, holder = self.doc_for(pol)
                        p.identity.append(PolicySource(pol.address, "managed", doc, prov, via=[r.address], tf_address=holder))
                        self._attach_edge(p, pol.address, r.address)
            for arn in as_list(self._known(r, "managed_policy_arns")):
                doc = self.managed_doc(str(arn))
                p.identity.append(PolicySource(str(arn), "aws_managed", doc, "aws_managed_summary" if doc else "unresolved"))
            # permissions boundary
            if r.references.get("permissions_boundary") or self._known(r, "permissions_boundary"):
                p.boundary = self.policy_from_arn_attr(r, "permissions_boundary")
                p.boundary.kind = "boundary"

        # groups (users only)
        for gr in groups:
            members: list[PlanResource] = []
            for m in self.plan.by_type("aws_iam_group_membership"):
                if self._refers(m, "group", gr):
                    members += [u for u in users if self._refers(m, "users", u)]
            for m in self.plan.by_type("aws_iam_user_group_membership"):
                if self._refers(m, "groups", gr):
                    members += [u for u in users if self._refers(m, "user", u)]
            gpols: list[PolicySource] = []
            for pol in self.plan.by_type("aws_iam_group_policy"):
                if self._refers(pol, "group", gr):
                    doc, prov, holder = self.doc_for(pol)
                    gpols.append(PolicySource(pol.address, "inline", doc, prov, via=[gr.address], tf_address=holder))
            for att in self.plan.by_type("aws_iam_group_policy_attachment"):
                if self._refers(att, "group", gr):
                    gpols.append(self.policy_from_arn_attr(att))
            for att in self.plan.by_type("aws_iam_policy_attachment"):
                if self._refers(att, "groups", gr):
                    gpols.append(self.policy_from_arn_attr(att))
            for u in members:
                p = self.principals.get(u.address)
                if p:
                    p.groups.append(gr.base)
                    for ps in gpols:
                        p.identity.append(PolicySource(ps.address, ps.kind, ps.doc, ps.provenance,
                                                       via=sorted(set(ps.via + [gr.address])), tf_address=ps.tf_address))
                    if gr.address in self.g.nodes:
                        self.g.add_edge(Edge("ATTACHES", gr.address, u.address, label="group_membership",
                                             evidence=[self.tf[gr.address], self.tf[u.address]]))

        for p in self.principals.values():
            for ps in p.identity:
                if ps.doc is None:
                    self.unresolved.append({"principal": p.res.address, "policy": ps.address, "provenance": ps.provenance})

    def _attach_edge(self, p: Principal, policy_addr: str, via: str) -> None:
        if policy_addr in self.g.nodes:
            self.g.add_edge(Edge("ATTACHES", p.res.address, policy_addr, label="policy",
                                 evidence=[self.tf[x] for x in (p.res.address, policy_addr, via) if x in self.tf]))

    # ---------------------------------------------------------- evaluation
    def _decide(self, p: Principal, action: str, target: PlanResource, form: str | None,
                resource_policy: list[PolicySource]):
        """Return (allowed, conditional, allow_handles, deny_handles)."""
        allow_h, deny_h = [], []
        cond_only = True
        id_allow = False
        for ps in p.identity:
            if not ps.doc:
                continue
            for st in ps.doc.statements:
                if not st.matches_action(action) or not self.matches_resource(st, target, form):
                    continue
                if st.effect == "Deny":
                    if not st.conditional:
                        deny_h.append(self._stmt_record(ps, st))
                    continue
                id_allow = True
                cond_only = cond_only and st.conditional
                allow_h.append(self._stmt_record(ps, st))
        if id_allow and p.boundary is not None:
            b_ok = False
            if p.boundary.doc:
                for st in p.boundary.doc.statements:
                    if st.effect == "Allow" and st.matches_action(action) and self.matches_resource(st, target, form):
                        b_ok = True
                        allow_h.append(self._stmt_record(p.boundary, st))
            else:
                b_ok = True  # unresolved boundary: do not claim it restricts
            if not b_ok:
                id_allow = False
                allow_h = []
        res_allow = False
        for ps in resource_policy:
            if not ps.doc:
                continue
            for st in ps.doc.statements:
                if not st.matches_action(action) or not self.matches_resource(st, target, form, own_policy=True):
                    continue
                ok, how = self.matches_principal(st, p)
                if not ok:
                    continue
                if st.effect == "Deny":
                    if not st.conditional:
                        deny_h.append(self._stmt_record(ps, st))
                    continue
                if how in ("direct", "any"):
                    res_allow = True
                    cond_only = cond_only and st.conditional
                    allow_h.append(self._stmt_record(ps, st))
        allowed = (id_allow or res_allow) and not deny_h
        return allowed, (allowed and cond_only), allow_h, deny_h

    def resource_policies(self, target: PlanResource) -> list[PolicySource]:
        out = []
        if target.type == "aws_s3_bucket":
            for bp in self.plan.by_type("aws_s3_bucket_policy"):
                if target.base in bp.references.get("bucket", []) or self._known(bp, "bucket") == self._known(target, "bucket"):
                    doc, prov, holder = self.doc_for(bp)
                    out.append(PolicySource(bp.address, "resource", doc, prov, tf_address=holder))
            if self._known(target, "policy"):
                doc, prov, holder = self.doc_for(target)
                out.append(PolicySource(target.address, "resource", doc, prov, tf_address=holder))
        elif target.type == "aws_kms_key" and (self._known(target, "policy") or target.references.get("policy")):
            doc, prov, holder = self.doc_for(target)
            out.append(PolicySource(target.address, "resource", doc, prov, tf_address=holder))
        elif target.type == "aws_secretsmanager_secret":
            for sp in self.plan.by_type("aws_secretsmanager_secret_policy"):
                if target.base in sp.references.get("secret_arn", []):
                    doc, prov, holder = self.doc_for(sp)
                    out.append(PolicySource(sp.address, "resource", doc, prov, tf_address=holder))
        return out

    def evaluate_assets(self) -> None:
        catalog = action_catalog()
        assets = [r for r in self.plan.resources.values() if r.type in ASSET_TYPES and r.address in self.g.nodes]
        for target in assets:
            rpols = self.resource_policies(target)
            for p in sorted(self.principals.values(), key=lambda x: x.res.address):
                allowed_actions, classes, handles, denied = [], set(), set(), []
                conditional_all = True
                for action, meta in sorted(catalog.get(target.type, {}).items()):
                    ok, cond, ah, dh = self._decide(p, action, target, meta["form"], rpols)
                    if ok:
                        allowed_actions.append(action)
                        classes.add(meta["class"])
                        handles.update(ah)
                        conditional_all = conditional_all and cond
                    elif dh:
                        denied.append(action)
                        handles.update(dh)
                if not allowed_actions:
                    if denied:
                        self.g.nodes[target.address].flags.setdefault("explicit_denies", []).append(
                            {"principal": p.res.address, "actions": denied})
                    continue
                symbolic = any(self.ledger.get(h).data.get("provenance", "").startswith("symbolic") for h in handles)
                self.g.add_edge(Edge(
                    "ALLOWS", p.res.address, target.address, label=",".join(sorted(classes)),
                    data={"actions": allowed_actions, "access": sorted(classes), "denied": denied, "symbolic": symbolic},
                    evidence=sorted(handles | {self.tf[p.res.address], self.tf[target.address]}),
                    conditional=conditional_all,
                ))

        # Public resource policies: Principal "*" on an asset, unconditional.
        for target in assets:
            for ps in self.resource_policies(target):
                if not ps.doc:
                    continue
                for st in ps.doc.statements:
                    if st.effect != "Allow" or "*" not in st.principals.get("AWS", []):
                        continue
                    acts = [a for a, m in sorted(catalog.get(target.type, {}).items())
                            if st.matches_action(a) and self.matches_resource(st, target, m["form"], own_policy=True)]
                    if not acts:
                        continue
                    h = self._stmt_record(ps, st)
                    classes = sorted({catalog[target.type][a]["class"] for a in acts})
                    self._external(ANY_PRINCIPAL, "Any AWS principal / anonymous", "AWS::IAM::AnyPrincipal")
                    self.g.nodes[target.address].flags["public_policy"] = {"actions": acts, "conditional": st.conditional}
                    self.g.add_edge(Edge("ALLOWS", ANY_PRINCIPAL, target.address, label=",".join(classes),
                                         data={"actions": acts, "access": classes, "denied": [], "symbolic": False,
                                               "via": "resource_policy"},
                                         evidence=[h, self.tf[target.address]], conditional=st.conditional))

    def allows_action_anywhere(self, p: Principal, action: str) -> list[str]:
        hs = []
        for ps in p.identity:
            if not ps.doc:
                continue
            for st in ps.doc.statements:
                if st.effect == "Deny" and st.matches_action(action) and not st.conditional and "*" in st.resources:
                    return []
            for st in ps.doc.statements:
                if st.effect == "Allow" and st.matches_action(action) and (st.resources or st.not_resources):
                    hs.append(self._stmt_record(ps, st))
        return hs

    def allows_on(self, p: Principal, action: str, target: PlanResource) -> list[str]:
        ok, _, ah, _ = self._decide(p, action, target, None, [])
        return ah if ok else []

    def _conditional(self, handles: list[str]) -> bool:
        """True if every IAM statement among the handles carries a Condition."""
        stmts = [self.ledger.get(h) for h in handles if h.startswith("IAM|")]
        return bool(stmts) and all(r.data.get("statement", {}).get("condition") for r in stmts)

    # --------------------------------------------------------------- trust
    def evaluate_trust(self) -> None:
        for p in sorted(self.principals.values(), key=lambda x: x.res.address):
            if p.res.type != "aws_iam_role":
                continue
            doc, prov, holder = self.doc_for(p.res, "assume_role_policy")
            if not doc:
                continue
            ps = PolicySource(p.res.address, "trust", doc, prov, tf_address=holder, attr="assume_role_policy")
            p.node.flags["trust_provenance"] = prov
            for st in doc.statements:
                if st.effect != "Allow" or not any(st.matches_action(a) for a in
                                                   ("sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML")):
                    continue
                h = self._stmt_record(ps, st)
                base_ev = [h, self.tf[p.res.address]]
                for svc in st.principals.get("Service", []):
                    nid = f"principal:service:{svc}"
                    self._external(nid, f"AWS service {svc}", "AWS::IAM::ServicePrincipal")
                    self.g.add_edge(Edge("TRUSTS", p.res.address, nid, evidence=base_ev, conditional=st.conditional))
                for fed in st.principals.get("Federated", []):
                    nid = f"principal:federated:{fed}"
                    self._external(nid, f"Federated {fed}", "AWS::IAM::OIDCProvider")
                    self.g.add_edge(Edge("TRUSTS", p.res.address, nid, evidence=base_ev, conditional=st.conditional))
                    if "token.actions.githubusercontent.com" in fed and not _has_sub_condition(st.condition):
                        self.g.nodes[nid].flags["entry"] = "federated_identity"
                        self.g.add_edge(Edge("ASSUMES", nid, p.res.address, label="oidc_without_sub_condition",
                                             evidence=base_ev, conditional=False))
                for ident in st.principals.get("AWS", []):
                    if ident == "*":
                        self._external(ANY_PRINCIPAL, "Any AWS principal", "AWS::IAM::AnyPrincipal")
                        self.g.add_edge(Edge("TRUSTS", p.res.address, ANY_PRINCIPAL, evidence=base_ev, conditional=st.conditional))
                        self.g.add_edge(Edge("ASSUMES", ANY_PRINCIPAL, p.res.address, label="trust_any_principal",
                                             evidence=base_ev, conditional=st.conditional))
                        continue
                    if re.fullmatch(r"\d{12}", ident) or ident.endswith(":root"):
                        acct = re.sub(r"^arn:aws:iam::(\d{12}):root$", r"\1", ident)
                        nid = f"principal:account:{acct}"
                        self._external(nid, f"AWS account {acct} (any principal it authorises)", "AWS::IAM::AccountPrincipal")
                        self.g.add_edge(Edge("TRUSTS", p.res.address, nid, evidence=base_ev, conditional=st.conditional))
                        # delegated to identity policies of principals in that account
                        for q in sorted(self.principals.values(), key=lambda x: x.res.address):
                            if q is p:
                                continue
                            ah = self.allows_on(q, "sts:AssumeRole", p.res)
                            if ah:
                                self.g.add_edge(Edge("ASSUMES", q.res.address, p.res.address, label="sts:AssumeRole",
                                                     evidence=base_ev + ah, conditional=st.conditional,
                                                     data={"assumption": "trusted account is this account"}))
                        continue
                    matched = False
                    for q in sorted(self.principals.values(), key=lambda x: x.res.address):
                        c = concretize(ident, q.res.base, q.name_token, q.arn, q.res.address)
                        if q is not p and arn_matches(c, q.arn):
                            matched = True
                            self.g.add_edge(Edge("TRUSTS", p.res.address, q.res.address, evidence=base_ev, conditional=st.conditional))
                            ah = self.allows_on(q, "sts:AssumeRole", p.res)
                            self.g.add_edge(Edge("ASSUMES", q.res.address, p.res.address, label="sts:AssumeRole",
                                                 evidence=base_ev + ah, conditional=st.conditional))
                    if not matched:
                        nid = f"principal:arn:{ident}"
                        self._external(nid, ident, "AWS::IAM::ExternalPrincipal")
                        self.g.add_edge(Edge("TRUSTS", p.res.address, nid, evidence=base_ev, conditional=st.conditional))

    def _external(self, nid: str, label: str, aws_type: str) -> Node:
        return self.g.add_node(Node(nid, "external", aws_type, "external", label, synthetic=True))

    # ------------------------------------------------------------ workloads
    def evaluate_workloads(self) -> None:
        for inst in self.plan.by_type("aws_instance"):
            if inst.address not in self.g.nodes:
                continue
            for pref in inst.references.get("iam_instance_profile", []) or []:
                for prof in self.plan.instances_of(pref):
                    self._workload_role(inst, prof)
            prof_name = self._known(inst, "iam_instance_profile")
            if prof_name and not inst.references.get("iam_instance_profile"):
                for prof in self.plan.by_type("aws_iam_instance_profile"):
                    if self._known(prof, "name") == prof_name:
                        self._workload_role(inst, prof)
        for fn in self.plan.by_type("aws_lambda_function"):
            if fn.address not in self.g.nodes:
                continue
            for rref in fn.references.get("role", []) or []:
                for role in self.plan.instances_of(rref):
                    self._assume_if_trusted(fn, role, "lambda.amazonaws.com", "workload_rce",
                                            [self.tf[fn.address]], "execution_role")
        for svc in self.plan.by_type("aws_ecs_service"):
            if svc.address in self.g.nodes:
                self._ecs_roles(svc)

    def _ecs_roles(self, svc: PlanResource) -> None:
        """A task's own role (task_role_arn), and on EC2 capacity the container instance's role via IMDS.

        The execution role (execution_role_arn) is used by the ECS agent, not handed to the container.
        """
        from ..graph import ecs

        td = ecs.task_definition_of(self.plan, svc)
        if td is None:
            return
        base_ev = [self.tf[svc.address], self.tf[td.address]]
        for rref in td.references.get("task_role_arn", []) or []:
            for role in self.plan.instances_of(rref):
                if role.type == "aws_iam_role":
                    self._assume_if_trusted(svc, role, "ecs-tasks.amazonaws.com", "workload_rce", base_ev, "task_role")
        if ecs.is_fargate(svc, td):
            return
        aids = ecs.escape_aids(td)
        for host in ecs.hosts(self.plan, ecs.cluster_of(self.plan, svc)):
            pre, why = ecs.container_imds(host)
            if pre is None:
                continue
            h = self.ledger.add("TF", (host.address, "ecs_container_imds", svc.address),
                                f"{host.address} runs {svc.address}'s tasks (ECS_CLUSTER in user data); {why}"
                                + (f"; the task eases escape: {', '.join(aids)}" if aids else ""),
                                source=self.src.locate_member(host.base, "user_data") or self.src.locate(host.base),
                                data={"host": host.address, "precondition": pre, "escape_aids": aids}, refs=[self.tf[host.address]])
            for pref in host.references.get("iam_instance_profile", []) or []:
                for prof in self.plan.instances_of(pref):
                    if prof.type != "aws_iam_instance_profile":
                        continue
                    for role in (r for ref in prof.references.get("role", []) for r in self.plan.instances_of(ref)):
                        self._assume_if_trusted(svc, role, "ec2.amazonaws.com", pre,
                                                base_ev + [self.tf[host.address], self.tf[prof.address], h], "ecs_host_role")

    def _workload_role(self, inst: PlanResource, prof: PlanResource) -> None:
        self.g.add_edge(Edge("ATTACHES", inst.address, prof.address, label="iam_instance_profile",
                             evidence=[self.tf[inst.address], self.tf[prof.address]]))
        roles = [r for ref in prof.references.get("role", []) for r in self.plan.instances_of(ref)]
        if not roles and self._known(prof, "role"):
            roles = [r for r in self.plan.by_type("aws_iam_role") if self._known(r, "name") == self._known(prof, "role")]
        for role in roles:
            self.g.add_edge(Edge("ATTACHES", prof.address, role.address, label="role",
                                 evidence=[self.tf[prof.address], self.tf[role.address]]))
            precondition, imds_h = self._imds(inst)
            if precondition is None:
                continue
            self._assume_if_trusted(inst, role, "ec2.amazonaws.com", precondition,
                                    [self.tf[inst.address], self.tf[prof.address], imds_h], "instance_profile")

    def _imds(self, inst: PlanResource) -> tuple[str | None, str]:
        mo = (as_list(inst.values.get("metadata_options")) or [{}])[0] or {}
        endpoint = mo.get("http_endpoint")
        tokens = mo.get("http_tokens")
        loc = self.src.locate_member(inst.base, "metadata_options") or self.src.locate(inst.base)
        if endpoint == "disabled":
            summary, pre = f"{inst.address}: instance metadata endpoint disabled (role credentials not reachable via IMDS)", None
        elif tokens == "required":
            summary, pre = f"{inst.address}: IMDSv2 required (http_tokens = required)", "workload_rce"
        else:
            shown = tokens if tokens else "not set"
            summary, pre = f"{inst.address}: IMDSv1 allowed (http_tokens = {shown})", "workload_ssrf"
        h = self.ledger.add("TF", (inst.address, "metadata_options"), summary, source=loc,
                            data={"http_endpoint": endpoint, "http_tokens": tokens}, refs=[self.tf[inst.address]])
        return pre, h

    def _assume_if_trusted(self, workload: PlanResource, role: PlanResource, service: str,
                           precondition: str, ev: list[str], label: str) -> None:
        trust = [e for e in self.g.out_edges(role.address, ("TRUSTS",)) if e.dst == f"principal:service:{service}"]
        if not trust:
            self.g.nodes[workload.address].flags.setdefault("untrusted_role", []).append(role.address)
            return
        self.g.add_edge(Edge("ASSUMES", workload.address, role.address, label=label,
                             evidence=sorted(set(ev + trust[0].evidence)), precondition=precondition,
                             conditional=trust[0].conditional))

    # ----------------------------------------------------------- escalation
    def evaluate_escalation(self) -> None:
        rules = escalation_rules()
        roles = self.plan.by_type("aws_iam_role")
        users = self.plan.by_type("aws_iam_user")
        for p in sorted(self.principals.values(), key=lambda x: x.res.address):
            admin = self._admin_equivalent(p)
            if admin:
                p.node.flags["admin_equivalent"] = True
                self._admin_node()
                self.g.add_edge(Edge("ESCALATES", p.res.address, ACCOUNT_ADMIN, label="admin_equivalent_policy",
                                     evidence=admin + [self.tf[p.res.address]]))
                continue
            for rule in rules:
                if rule.get("principal_types") and p.res.type not in rule["principal_types"]:
                    continue
                eff = rule["effect"]
                if eff == "self_admin":
                    hs = self._self_admin(p, rule)
                    if hs:
                        self._admin_node()
                        self.g.add_edge(Edge("ESCALATES", p.res.address, ACCOUNT_ADMIN, label=rule["id"],
                                             evidence=hs + [self.tf[p.res.address]], conditional=self._conditional(hs)))
                elif eff == "passrole":
                    combo = [self.allows_action_anywhere(p, a) for a in rule["all"]]
                    if not all(combo):
                        continue
                    for role in roles:
                        pr = self.allows_on(self.principals.get(p.res.address), "iam:PassRole", role)
                        trusts = [e for e in self.g.out_edges(role.address, ("TRUSTS",))
                                  if e.dst == f"principal:service:{rule['service']}"]
                        if pr and trusts and role.address != p.res.address:
                            ev = sorted({h for c in combo for h in c} | set(pr) | set(trusts[0].evidence))
                            self.g.add_edge(Edge("ASSUMES", p.res.address, role.address, label=rule["id"], evidence=ev))
                elif eff == "takeover_user":
                    for u in users:
                        if u.address == p.res.address:
                            continue
                        hs = self.allows_on(p, rule["all"][0], u)
                        if hs:
                            self.g.add_edge(Edge("ASSUMES", p.res.address, u.address, label=rule["id"],
                                                 evidence=hs + [self.tf[u.address]], conditional=self._conditional(hs)))
                elif eff == "takeover_role_trust":
                    for role in roles:
                        if role.address == p.res.address:
                            continue
                        hs = self.allows_on(p, rule["all"][0], role)
                        if hs:
                            self.g.add_edge(Edge("ASSUMES", p.res.address, role.address, label=rule["id"],
                                                 evidence=hs + [self.tf[role.address]], conditional=self._conditional(hs)))
                elif eff == "takeover_workload":
                    wtype = {"function": "aws_lambda_function", "instance": "aws_instance"}[rule["on"]]
                    for w in self.plan.by_type(wtype):
                        per = [self.allows_on(p, a, w) for a in rule["all"]]
                        if not all(per):
                            continue
                        hs = sorted({h for x in per for h in x})
                        for e in self.g.out_edges(w.address, ("ASSUMES",)):
                            if e.src != w.address:
                                continue
                            self.g.add_edge(Edge("ASSUMES", p.res.address, e.dst, label=rule["id"],
                                                 evidence=hs + [x for x in e.evidence], conditional=self._conditional(hs)))

        # a principal that can attach or write policies on a role it can also act as is, in effect, admin
        for p in sorted(self.principals.values(), key=lambda x: x.res.address):
            if p.node.flags.get("admin_equivalent"):
                continue
            for e in list(self.g.out_edges(p.res.address, ("ASSUMES",))):
                role = self.plan.resources.get(e.dst)
                if role is None or role.type != "aws_iam_role":
                    continue
                hs = [h for a in ("iam:AttachRolePolicy", "iam:PutRolePolicy") for h in self.allows_on(p, a, role)]
                if hs:
                    self._admin_node()
                    self.g.add_edge(Edge("ESCALATES", p.res.address, ACCOUNT_ADMIN, label=f"PE-POLICY-ON-ASSUMABLE-ROLE({role.address})",
                                         evidence=sorted(set(hs + list(e.evidence) + [self.tf[p.res.address]])),
                                         conditional=self._conditional(hs) or e.conditional))
                    break

    def _admin_node(self) -> None:
        self.g.add_node(Node(ACCOUNT_ADMIN, "external", "AWS::IAM::AccountAdministrator", "identity",
                             "Account administrator (full IAM control)", synthetic=True,
                             sensitivity={"level": "restricted", "basis": "definition"}))

    def _admin_equivalent(self, p: Principal) -> list[str]:
        if p.boundary is not None:
            return []
        for ps in p.identity:  # an unconditional Deny on IAM administration voids admin-equivalence
            for st in (ps.doc.statements if ps.doc else []):
                if (st.effect == "Deny" and not st.conditional and "*" in st.resources
                        and any(st.matches_action(a) for a in ("iam:PutUserPolicy", "iam:AttachRolePolicy", "iam:CreatePolicyVersion"))):
                    return []
        hs = []
        for ps in p.identity:
            if not ps.doc:
                continue
            for st in ps.doc.statements:
                if (st.effect == "Allow" and not st.conditional and "*" in st.resources
                        and any(a in ("*", "iam:*") for a in st.actions)):
                    hs.append(self._stmt_record(ps, st))
        return hs

    def _self_admin(self, p: Principal, rule: dict) -> list[str]:
        action = rule["all"][0]
        on = rule.get("on")
        if on == "self":
            return self.allows_on(p, action, p.res)
        if on == "policy":
            hs = []
            for ps in p.identity:
                if ps.kind == "managed" and ps.address in self.plan.resources:
                    hs += self.allows_on(p, action, self.plan.resources[ps.address])
            return hs or [h for h in self.allows_action_anywhere(p, action)
                          if "*" in (self.ledger.get(h).data["statement"].get("resources") or [])]
        # "any": group or account-wide scope
        hs = []
        for gb in p.groups:
            for gr in self.plan.instances_of(gb):
                hs += self.allows_on(p, action, gr)
        return hs or [h for h in self.allows_action_anywhere(p, action)
                      if "*" in (self.ledger.get(h).data["statement"].get("resources") or [])]

    # ----------------------------------------------------------------- run
    def run(self) -> None:
        self.collect_principals()
        self.evaluate_trust()
        self.evaluate_workloads()
        self.evaluate_assets()
        self.evaluate_escalation()


def _has_sub_condition(cond: Any) -> bool:
    if not isinstance(cond, dict):
        return False
    for _op, kv in cond.items():
        if isinstance(kv, dict) and any(k.endswith(":sub") for k in kv):
            return True
    return False


def _provider_region(raw: dict) -> str:
    cfg = ((raw.get("configuration") or {}).get("provider_config") or {}).get("aws") or {}
    region = ((cfg.get("expressions") or {}).get("region") or {}).get("constant_value")
    return region or UNKNOWN
