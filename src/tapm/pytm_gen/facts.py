"""Terraform evidence -> pytm attributes and controls.

pytm's 114 built-in threats are conditions over element attributes, and every
attribute defaults to False. A model that sets nothing therefore reports threats
that reflect *unknowns*, not weaknesses. This module sets only the attributes a
Terraform plan can actually decide, each with the evidence IDs behind it, and
leaves the rest explicitly unknown (application-layer controls such as input
validation are invisible to infrastructure code).

It also computes the attributes used by the cloud threat pack
(``cloud_threats.json``): IMDSv1, instance roles, sensitive-data reach,
internet reachability, wildcard grants, public bucket policies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..evidence.ledger import handle
from ..graph.build import LEVEL_ORDER, BuildResult
from ..graph.model import ANY_PRINCIPAL, INTERNET
from ..util import as_list

# attributes set by the model structure itself (not facts about controls)
STRUCTURAL = {"protocol", "dstPort", "isResponse", "inScope", "source.inScope", "sink.inScope", "onAWS", "type", "isSQL",
              "storesSensitiveData", "maxClassification", "hasWriteAccess", "name", "port"}

# custom attributes used by the cloud threat pack, per pytm element class; always set, so always decided
PACK_ATTRS = {
    "Server": ("imdsV1Allowed", "hasInstanceRole", "readsSensitiveData", "internetReachable", "internetWideIngress"),
    "Lambda": ("readsSensitiveData", "internetReachable", "unauthenticatedUrl"),
    "Datastore": ("readableViaWildcardGrant", "publicPolicyGrant", "publicAccessBlocked"),
}


@dataclass
class Fact:
    attr: str                      # "controls.isEncryptedAtRest", "minTLSVersion", "imdsV1Allowed"
    value: Any                     # bool, str, or "TLSVersion.X"
    evidence: list[str] = field(default_factory=list)
    basis: str = ""

    def to_json(self) -> dict:
        return {"value": self.value, "evidence": sorted(set(self.evidence)), "basis": self.basis}


_TLS = [("TLS13-1-3", "TLSv13"), ("TLS13-1-2", "TLSv12"), ("TLS-1-2", "TLSv12"), ("FS-1-2", "TLSv12"),
        ("TLS13-1-1", "TLSv11"), ("TLS-1-1", "TLSv11"), ("FS-1-1", "TLSv11"), ("TLS13-1-0", "TLSv10"),
        ("TLS-1-0", "TLSv10"), ("2016-08", "TLSv10"), ("FS-2018-06", "TLSv10")]


def tls_min(ssl_policy: str | None) -> str | None:
    """Minimum TLS version of an ELB security policy name, or None if the name is not recognised."""
    if not ssl_policy:
        return None
    for marker, v in _TLS:
        if marker in ssl_policy:
            return v
    return None


def wildcard_resource(resource) -> bool:
    """True when a policy resource covers resources it does not name: ``*``, ``arn:aws:s3:::*``,
    ``...:table/*``. Object paths under one named bucket (``arn:aws:s3:::name/*``) are not wildcards."""
    r = str(resource)
    if "*" not in r:
        return False
    if r.startswith(("tf:", "${")):  # a reference to one named resource, possibly with an object path
        return "*" in r.split("/", 1)[0]
    parts = r.split(":", 5)
    if not r.startswith("arn:") or len(parts) < 6:
        return True
    service, res = parts[2], parts[5]
    if service == "s3":
        return "*" in res.split("/", 1)[0]
    return "*" in res


class FactBuilder:
    def __init__(self, result: BuildResult):
        self.r = result
        self.g = result.graph
        self.plan = result.plan
        self.tf_id = {a: result.ledger.id_of(h) for a, h in result.tf.items()}
        self.recs = result.ledger.by_id()

    def key_id(self, kind: str, key) -> str | None:
        return self.r.ledger.ids.get(handle(kind, key))

    def _tf(self, addr: str) -> list[str]:
        return [self.tf_id[addr]] if addr in self.tf_id else []

    def _refs(self, res, attr: str) -> list[str]:
        return res.references.get(attr, [])

    # ------------------------------------------------------------ elements
    def element(self, nid: str) -> list[Fact]:
        n = self.g.nodes[nid]
        res = self.plan.resources.get(nid)
        if n.type in ("aws_lb", "aws_alb"):
            return self._lb(nid, res)
        if n.type == "aws_instance":
            return self._instance(nid, res)
        if n.type == "aws_lambda_function":
            return self._lambda(nid, res)
        if n.category == "data":
            return self._datastore(nid, res)
        return []

    def _listeners(self, lb):
        return [ls for ls in self.plan.by_type("aws_lb_listener", "aws_alb_listener")
                if lb.base in " ".join(self._refs(ls, "load_balancer_arn"))]

    def _lb(self, nid, lb) -> list[Fact]:
        facts: list[Fact] = []
        if lb is None:
            return facts
        ev = self._tf(nid)
        listeners = self._listeners(lb)
        https = [ls for ls in listeners if (ls.values.get("protocol") or "").upper() in ("HTTPS", "TLS")]
        plain = [ls for ls in listeners if (ls.values.get("protocol") or "").upper() in ("HTTP", "TCP", "UDP")]
        if listeners:
            lev = ev + [self.tf_id[ls.address] for ls in listeners if ls.address in self.tf_id]
            if https and not plain:
                versions = [tls_min(ls.values.get("ssl_policy")) for ls in https]
                facts.append(Fact("controls.isEncrypted", True, lev, "every listener terminates TLS"))
                facts.append(Fact("controls.authenticatesDestination", True, lev, "TLS listener presents an ACM certificate"))
                if all(versions):
                    worst = min(versions, key=lambda v: ["TLSv10", "TLSv11", "TLSv12", "TLSv13"].index(v))
                    facts.append(Fact("minTLSVersion", f"TLSVersion.{worst}", lev,
                                      f"ssl_policy {', '.join(sorted({ls.values.get('ssl_policy') for ls in https}))}"))
            elif plain:
                facts.append(Fact("controls.isEncrypted", False, lev, "a listener accepts plaintext HTTP/TCP"))
                facts.append(Fact("minTLSVersion", "TLSVersion.NONE", lev, "plaintext listener"))
            auth = [ls for ls in listeners for a in as_list(ls.values.get("default_action"))
                    if isinstance(a, dict) and a.get("type") in ("authenticate-oidc", "authenticate-cognito")]
            if auth:
                facts.append(Fact("controls.authenticatesSource", True, lev, "listener authenticates users (OIDC/Cognito)"))
                facts.append(Fact("controls.implementsAuthenticationScheme", True, lev, "listener authenticates users"))
        dihf = lb.values.get("drop_invalid_header_fields")
        if isinstance(dihf, bool):
            facts.append(Fact("controls.validatesHeaders", dihf, ev, f"drop_invalid_header_fields = {str(dihf).lower()}"))
        mode = lb.values.get("desync_mitigation_mode")
        if isinstance(mode, str):
            facts.append(Fact("controls.implementsStrictHTTPValidation", mode == "strictest", ev,
                              f"desync_mitigation_mode = {mode}"))
        facts += self._pack_reach(nid)
        return facts

    def _role_of(self, nid) -> list[str]:
        return [e.dst for e in self.g.out_edges(nid, ("ASSUMES",))]

    def _sensitive_reads(self, nid) -> list:
        out = []
        for e in self.g.out_edges(nid, ("READS", "WRITES")):
            if LEVEL_ORDER.get(self.g.nodes[e.dst].sensitivity.get("level", "unclassified"), 0) >= 2:
                out.append(e)
        return out

    def _wildcard_statements(self, edges) -> list[str]:
        ids = []
        for e in edges:
            for x in e.evidence:
                rec = self.recs.get(x)
                if rec is None or rec.kind != "IAM":
                    continue
                st = (rec.data or {}).get("statement", {})
                if any(wildcard_resource(res) for res in st.get("resources", [])) or st.get("not_resources"):
                    ids.append(x)
        return sorted(set(ids))

    def _pack_reach(self, nid) -> list[Fact]:
        exp = [e for e in self.g.in_edges(nid, ("EXPOSES",)) if e.src == INTERNET]
        routed = [e for e in self.g.in_edges(nid, ("ROUTES_TO",))
                  if any(x.src == INTERNET for x in self.g.in_edges(e.src, ("EXPOSES",)))]
        edges = exp + routed
        facts = [Fact("internetReachable", bool(edges), [e.id for e in edges if e.id],
                      "reachable from the internet" if edges else "no EXPOSES/ROUTES_TO chain from the internet")]
        wide_ev = []
        for e in exp:
            for x in e.evidence:
                rec = self.recs.get(x)
                if rec is not None and rec.kind == "NET" and (rec.data or {}).get("internet"):
                    wide_ev.append(x)
        if self.g.nodes[nid].type in ("aws_lb", "aws_alb", "aws_instance"):
            facts.append(Fact("internetWideIngress", bool(wide_ev), sorted(set(wide_ev)),
                              "security group admits 0.0.0.0/0 or ::/0" if wide_ev else "no internet-wide ingress rule"))
        return facts

    def _instance(self, nid, inst) -> list[Fact]:
        facts: list[Fact] = []
        ev = self._tf(nid)
        mo = ((as_list(inst.values.get("metadata_options")) or [{}])[0] or {}) if inst is not None else {}
        rec_id = self.key_id("TF", (nid, "metadata_options"))
        mev = [rec_id] if rec_id else ev
        v1 = mo.get("http_endpoint") != "disabled" and mo.get("http_tokens") != "required"
        facts.append(Fact("imdsV1Allowed", v1, mev, f"http_tokens = {mo.get('http_tokens') or 'not set'}, "
                                                    f"http_endpoint = {mo.get('http_endpoint') or 'default'}"))
        roles = self._role_of(nid)
        prof = [e for e in self.g.out_edges(nid, ("ATTACHES",)) if self.g.nodes[e.dst].type == "aws_iam_instance_profile"]
        facts.append(Fact("hasInstanceRole", bool(prof), [e.id for e in prof if e.id] + ev,
                          "instance profile attached" if prof else "no instance profile"))
        reads = self._sensitive_reads(nid)
        facts.append(Fact("readsSensitiveData", bool(reads), [e.id for e in reads if e.id],
                          "role can read or write a confidential/restricted asset" if reads else "no sensitive data access"))
        grants = [e for r in roles for e in self.g.out_edges(r, ("ALLOWS",))]
        if grants:
            wild = self._wildcard_statements(grants)
            facts.append(Fact("controls.implementsPOLP", not wild, wild or sorted({x for e in grants for x in e.evidence}),
                              "role has wildcard-resource grants" if wild else "every grant names specific resources"))
        # disks: EBS encryption at rest, as the plan states it for the root and extra volumes
        vols = [v for key in ("root_block_device", "ebs_block_device") for v in as_list(inst.values.get(key) if inst is not None else None)
                if isinstance(v, dict)]
        enc = [v.get("encrypted") for v in vols]
        if vols and all(x is True for x in enc):
            facts.append(Fact("controls.isEncryptedAtRest", True, ev, "every EBS volume has encrypted = true"))
        elif any(x is False for x in enc):
            facts.append(Fact("controls.isEncryptedAtRest", False, ev, "an EBS volume has encrypted = false"))
        # target group protocol decides whether traffic into the instance is encrypted
        routes = self.g.in_edges(nid, ("ROUTES_TO",))
        if routes:
            protos = {(e.label or "").split("/")[0].upper() for e in routes}
            rev = sorted({x for e in routes for x in e.evidence})
            if protos <= {"HTTPS", "TLS"}:
                facts.append(Fact("controls.isEncrypted", True, rev, "target group protocol HTTPS/TLS"))
            elif protos & {"HTTP", "TCP"}:
                facts.append(Fact("controls.isEncrypted", False, rev, f"target group protocol {'/'.join(sorted(protos))}"))
        facts += self._pack_reach(nid)
        return facts

    def _lambda(self, nid, fn) -> list[Fact]:
        facts: list[Fact] = []
        ev = self._tf(nid)
        if fn is not None:
            env = as_list(fn.values.get("environment"))
            facts.append(Fact("usesEnvironmentVariables", bool(env and env[0]), ev,
                              "environment block present" if env and env[0] else "no environment block"))
        reads = self._sensitive_reads(nid)
        facts.append(Fact("readsSensitiveData", bool(reads), [e.id for e in reads if e.id],
                          "role can read or write a confidential/restricted asset" if reads else "no sensitive data access"))
        exp = [e for e in self.g.in_edges(nid, ("EXPOSES",)) if e.src == INTERNET]
        facts.append(Fact("internetReachable", bool(exp), [e.id for e in exp if e.id],
                          "function URL reachable from the internet" if exp else "not internet-reachable"))
        url = [e for e in exp if "function_url" in (e.label or "")]
        facts.append(Fact("unauthenticatedUrl", bool(url), [x for e in url for x in e.evidence],
                          "function URL with authorization_type NONE" if url else "no unauthenticated function URL"))
        if url:
            facts.append(Fact("controls.authenticatesSource", False, [x for e in url for x in e.evidence],
                              "function URL authorization_type NONE"))
        return facts

    def _datastore(self, nid, res) -> list[Fact]:
        n = self.g.nodes[nid]
        facts: list[Fact] = []
        ev = self._tf(nid)
        # encryption at rest
        enc, basis, eev = None, "", ev
        if n.type == "aws_s3_bucket":
            sse = [c for c in self.plan.by_type("aws_s3_bucket_server_side_encryption_configuration")
                   if res is not None and res.base in " ".join(self._refs(c, "bucket"))]
            if sse:
                enc, basis, eev = True, "server-side encryption configured", ev + [self.tf_id[c.address] for c in sse if c.address in self.tf_id]
            else:
                enc, basis = True, "S3 encrypts new objects with SSE-S3 by default (since January 2023)"
        elif n.type == "aws_db_instance" and res is not None and isinstance(res.values.get("storage_encrypted"), bool):
            enc, basis = res.values["storage_encrypted"], f"storage_encrypted = {str(res.values['storage_encrypted']).lower()}"
        elif n.type in ("aws_dynamodb_table", "aws_secretsmanager_secret", "aws_kms_key"):
            enc, basis = True, "encrypted at rest by the service (always on)"
        elif n.type == "aws_ssm_parameter" and res is not None and res.values.get("type"):
            enc = res.values.get("type") == "SecureString"
            basis = f"parameter type {res.values.get('type')}"
        if enc is not None:
            facts.append(Fact("controls.isEncryptedAtRest", enc, eev, basis))
            if enc:
                facts.append(Fact("controls.usesEncryptionAlgorithm", "AES", eev, "AES-256 (" + basis + ")"))
        # access control: IAM authorises every request unless a public grant is effective
        public = [e for e in self.g.in_edges(nid, ("ALLOWS",)) if e.src == ANY_PRINCIPAL]
        pev = sorted({x for e in public for x in e.evidence})
        facts.append(Fact("controls.hasAccessControl", not public, pev or ev,
                          "public grant is effective" if public else "every request needs IAM authorisation"))
        facts.append(Fact("controls.authorizesSource", not public, pev or ev,
                          "anonymous principals are allowed" if public else "IAM authorises the caller"))
        grants = [e for e in self.g.in_edges(nid, ("ALLOWS",)) if e.src != ANY_PRINCIPAL]
        wild = self._wildcard_statements(grants)
        facts.append(Fact("controls.implementsPOLP", not wild and not public, wild or pev or ev,
                          "reachable through wildcard-resource grants" if wild else
                          ("public grant" if public else "every grant names this resource specifically")))
        facts.append(Fact("readableViaWildcardGrant", bool(wild), wild,
                          "a wildcard-resource grant covers this store" if wild else "no wildcard-resource grant"))
        blocked = n.flags.get("public_access_blocked")
        bev = [x for x in (self.key_id("NET", ("public_access_block", (blocked or {}).get("by", ""))),) if x]
        facts.append(Fact("publicPolicyGrant", bool(public or blocked), pev or bev,
                          "a policy or ACL grants anonymous access" if (public or blocked) else "no public grant"))
        facts.append(Fact("publicAccessBlocked", bool(blocked), bev,
                          f"neutralised by {blocked.get('by')}" if blocked else "no block public access neutralising a grant"))
        return facts

    # ------------------------------------------------------------ data (pytm Data objects)
    _PII_KEYS = ("pii", "containspii", "personaldata", "contains_pii", "personal_data")

    def data_contents(self, nid: str) -> list[Fact]:
        """What a classified data store holds: classification from its tag; PII only if a tag says so."""
        n = self.g.nodes[nid]
        res = self.plan.resources.get(nid)
        tf = self._tf(nid)
        level = n.sensitivity.get("level", "unclassified")
        cev = [n.sensitivity["evidence"]] if n.sensitivity.get("evidence") else tf
        facts = [Fact("classification", f"Classification.{'SECRET' if level == 'restricted' else 'SENSITIVE'}", cev,
                      f"{level} ({n.sensitivity.get('basis')})"),
                 Fact("isStored", True, tf, "held in the data store")]
        tags = {}
        for key in ("tags", "tags_all"):
            v = (res.values.get(key) if res is not None else None)
            if isinstance(v, dict):
                tags.update({str(k).lower(): str(val).strip().lower() for k, val in v.items()})
        pii = next(((k, v) for k, v in sorted(tags.items()) if k in self._PII_KEYS), None)
        if pii and pii[1] in ("true", "yes", "false", "no"):
            facts.append(Fact("isPII", pii[1] in ("true", "yes"), tf, f"tag {pii[0]} = {pii[1]}"))
        elif tags.get("dataclassification") in ("pii", "personal"):
            facts.append(Fact("isPII", True, cev, f"tag DataClassification = {tags['dataclassification']}"))
        if n.type == "aws_secretsmanager_secret" or (n.type == "aws_ssm_parameter" and n.sensitivity.get("basis") == "type:securestring"):
            facts.append(Fact("isCredentials", True, tf, "a secret store"))
        return facts

    def _metadata(self, nid: str) -> tuple[bool, list[str], str]:
        inst = self.plan.resources.get(nid)
        mo = ((as_list(inst.values.get("metadata_options")) or [{}])[0] or {}) if inst is not None else {}
        rec_id = self.key_id("TF", (nid, "metadata_options"))
        v1 = mo.get("http_endpoint") != "disabled" and mo.get("http_tokens") != "required"
        return v1, ([rec_id] if rec_id else self._tf(nid)), f"http_tokens = {mo.get('http_tokens') or 'not set'}"

    def role_credentials(self, e) -> list[Fact]:
        """The temporary credentials an instance fetches from IMDS for its role (an ASSUMES instance_profile edge)."""
        ev = sorted(set([e.id] + list(e.evidence)))
        return [Fact("classification", "Classification.SECRET", ev, f"temporary AWS credentials for {e.dst}"),
                Fact("isCredentials", True, ev, "STS credentials issued through the instance profile"),
                Fact("credentialsLife", "Lifetime.SHORT", ev, "instance-profile credentials expire and rotate automatically"),
                Fact("isPII", False, ev, "credentials, not personal data"),
                Fact("isStored", False, ev, "fetched on demand from IMDS")]

    def imds(self, nid: str) -> list[Fact]:
        _, mev, _ = self._metadata(nid)
        return [Fact("controls.isEncrypted", False, mev, "IMDS answers over link-local HTTP (169.254.169.254)")]

    def imds_flow(self, nid: str) -> list[Fact]:
        v1, mev, basis = self._metadata(nid)
        return [Fact("controls.authenticatesSource", not v1, mev,
                     f"{basis}: " + ("IMDSv1 answers any local request, including one an SSRF makes" if v1
                                     else "IMDSv2 requires a session token first"))]

    # ------------------------------------------------------------ flows
    def flow(self, e) -> list[Fact]:
        """Facts owned by the dataflow itself (pytm copies isEncrypted from the sink element)."""
        if e.type in ("READS", "WRITES"):
            ev = sorted(set(e.evidence))
            return [Fact("controls.authenticatesSource", True, ev, "AWS API requests are SigV4-signed"),
                    Fact("controls.authorizesSource", True, ev, "IAM authorises every AWS API request"),
                    Fact("controls.implementsAuthenticationScheme", True, ev, "SigV4")]
        if e.type == "ALLOWS" and e.src == ANY_PRINCIPAL:
            ev = sorted(set(e.evidence))
            return [Fact("controls.authenticatesSource", False, ev, "anonymous access"),
                    Fact("controls.authorizesSource", False, ev, "anonymous access")]
        return []


def pack_defaults(pytm_class: str) -> dict[str, bool]:
    return {a: False for a in PACK_ATTRS.get(pytm_class, ())}


def render_value(v: Any) -> str:
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, str) and v.startswith(("TLSVersion.", "Classification.", "Lifetime.")):
        return v
    return repr(v)


def condition_attrs(condition: str) -> list[str]:
    """Attribute paths a pytm threat condition reads, relative to the target."""
    return sorted(set(re.findall(r"target\.((?:source\.|sink\.)?(?:controls\.)?[A-Za-z_][A-Za-z0-9_]*)", condition)))
