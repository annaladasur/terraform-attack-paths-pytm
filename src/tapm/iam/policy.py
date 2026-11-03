"""IAM policy documents: parsing, normalisation and matching.

Scope (stated on purpose): identity policies, resource policies (S3 bucket
policies), trust policies and permissions boundaries that are *visible in the
Terraform plan*. Action/NotAction, Resource/NotResource, Principal, explicit Deny
and the presence of a Condition are evaluated. Condition *values* are not
evaluated: conditional grants and applicable conditional Deny restrictions
produce conditional edges, labelled as assumptions. Unresolved policy documents
and boundaries remain visible as uncertainty. A boundary intersects identity
grants and direct role-ARN resource grants; direct same-account user-ARN resource
grants bypass its implicit denial, while explicit boundary Deny still wins.
STS session principals, SCPs, RCPs, session policies and runtime context are out of scope.
NotPrincipal is parsed for visibility but not simulated; its presence is reported
as unresolved analysis and taints otherwise applicable grants.
Unknown policy sets, documents and assignments are inventoried even without an
emitted path. Optional/computed role policy sets and S3/KMS policy readback are
classified as omitted Terraform input only for new creates where both parsed
full source and configuration establish omission. Writing a policy onto a
bounded principal does not establish unrestricted account administration;
boundary escape after the grant remains explicit uncertainty.
Parsing alone does not establish recovery completeness: unresolved symbolic
tokens, missing referenced resources and malformed policy structures remain
unresolved. Policy-document configuration is checked before adapter defaults or
dropped fields can erase restrictions.
This is not a complete IAM policy simulator.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..util import as_list, glob_to_regex

UNKNOWN = "\x00?\x00"  # an ARN segment the plan does not know yet (e.g. account id)
NOMATCH = "\x01"


@dataclass
class Statement:
    index: int
    sid: str | None
    effect: str
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    principals: dict[str, list[str]] = field(default_factory=dict)
    not_principals: dict[str, list[str]] = field(default_factory=dict)
    condition: Any = None

    @property
    def conditional(self) -> bool:
        return bool(self.condition)

    def matches_action(self, action: str) -> bool:
        if self.actions:
            return any(_match_action(p, action) for p in self.actions)
        if self.not_actions:
            return not any(_match_action(p, action) for p in self.not_actions)
        return False

    def to_json(self) -> dict:
        out: dict[str, Any] = {"index": self.index, "effect": self.effect}
        for k in ("sid", "actions", "not_actions", "resources", "not_resources", "principals", "not_principals"):
            v = getattr(self, k)
            if v:
                out[k] = v
        if self.condition:
            out["condition"] = self.condition
        return out


@dataclass
class PolicyDoc:
    statements: list[Statement]
    symbolic: bool = False
    approximate: bool = False
    raw: Any = None


def parse_document(doc: Any) -> PolicyDoc | None:
    if doc is None:
        return None
    if isinstance(doc, str):
        doc = doc.strip()
        if not doc:
            return None
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            return None
    if not isinstance(doc, dict):
        return None
    raw_statements = doc.get("Statement")
    if not isinstance(raw_statements, (dict, list)) or not raw_statements:
        return None

    def strings(value):
        return isinstance(value, str) and bool(value) or (
            isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value))

    def principal(value):
        return strings(value) or (isinstance(value, dict) and bool(value)
                                  and all(isinstance(key, str) and strings(item) for key, item in value.items()))

    stmts = []
    for i, st in enumerate(as_list(raw_statements)):
        if not isinstance(st, dict):
            return None
        if st.get("Effect") not in ("Allow", "Deny"):
            return None
        if bool("Action" in st) == bool("NotAction" in st):
            return None
        if not all(strings(st[key]) for key in ("Action", "NotAction", "Resource", "NotResource") if key in st):
            return None
        if "Resource" in st and "NotResource" in st or "Principal" in st and "NotPrincipal" in st:
            return None
        if not all(principal(st[key]) for key in ("Principal", "NotPrincipal") if key in st):
            return None
        if "Condition" in st and not isinstance(st["Condition"], dict):
            return None
        if set(st) - {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal", "Condition"}:
            return None
        stmts.append(
            Statement(
                index=i,
                sid=st.get("Sid"),
                effect=st["Effect"],
                actions=[str(a) for a in as_list(st.get("Action"))],
                not_actions=[str(a) for a in as_list(st.get("NotAction"))],
                resources=[str(r) for r in as_list(st.get("Resource"))],
                not_resources=[str(r) for r in as_list(st.get("NotResource"))],
                principals=_principals(st.get("Principal")),
                not_principals=_principals(st.get("NotPrincipal")),
                condition=st.get("Condition"),
            )
        )
    return PolicyDoc(stmts, symbolic=bool(doc.get("_symbolic")), approximate=bool(doc.get("_approximate")), raw=doc)


def _principals(value: Any) -> dict[str, list[str]]:
    if value is None:
        return {}
    if value == "*":
        return {"AWS": ["*"]}
    if isinstance(value, dict):
        return {str(k): sorted(str(x) for x in as_list(v)) for k, v in value.items()}
    return {"AWS": [str(x) for x in as_list(value)]}


def _match_action(pattern: str, action: str) -> bool:
    # IAM action names are case-insensitive.
    return bool(glob_to_regex(pattern, case_insensitive=True).match(action))


# --------------------------------------------------------------------------- ARNs


def arn_matches(pattern: str, arn: str) -> bool:
    """Glob-match an IAM Resource pattern against a candidate ARN.

    Candidate ARNs may contain ``UNKNOWN`` segments (account id, region, generated
    ids). ``*`` in the pattern matches an unknown segment; a literal account id or
    region in the pattern is assumed to be *this* account/region (recorded by the
    evaluator as an assumption).
    """
    if pattern == "*":
        return True
    if NOMATCH in pattern:
        return False
    # a pattern built from a node's own ARN carries its unknown markers: treat them as wildcards
    pattern = pattern.replace(UNKNOWN, "*")
    p_parts = pattern.split(":", 5)
    a_parts = arn.split(":", 5)
    if len(p_parts) != 6 or len(a_parts) != 6:
        return bool(glob_to_regex(pattern).match(arn))
    for idx, (p, a) in enumerate(zip(p_parts, a_parts)):
        if idx == 4 and p == "aws" and a != "aws":
            return False  # the AWS-managed namespace never contains customer resources
        if idx in (3, 4) and a == UNKNOWN:
            continue  # region / account: assume ours
        if a == UNKNOWN and p != "*":
            return False
        if not glob_to_regex(p).match(a.replace(UNKNOWN, "\x00")):
            return False
    return True


_TOKEN = re.compile(r"tf:((?:module\.[A-Za-z0-9_-]+\.)*(?:data\.)?[a-z0-9_]+\.[A-Za-z0-9_-]+(?:\[[^\]]*\])?)\.(arn|id|name|bucket)")


def document_tokens(doc: PolicyDoc) -> tuple[list[str], bool]:
    """Return symbolic resource references and whether opaque tokens remain."""
    references, unresolved = [], False

    def walk(value):
        nonlocal unresolved
        if isinstance(value, dict):
            for key, item in value.items():
                walk(key)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            references.extend(match.group(1) for match in _TOKEN.finditer(value))
            if "tf:" in _TOKEN.sub("", value) or "${" in value:
                unresolved = True

    walk(doc.raw)
    return references, unresolved


def concretize(pattern: str, node_base: str, node_name: str | None, node_arn: str | None,
               node_address: str | None = None) -> str:
    """Replace symbolic ``tf:<address>.<attr>`` tokens for one candidate node.

    A token that names the candidate node becomes that node's name/ARN; a token
    naming any other resource can never match this node. An indexed token
    (``aws_s3_bucket.data["logs"].arn``) names one instance; an unindexed one names
    every instance of that resource.
    """
    if "tf:" not in pattern:
        return pattern

    def repl(m: re.Match[str]) -> str:
        full = m.group(1)
        addr = re.sub(r"\[[^\]]*\]$", "", full)
        if addr != node_base:
            return NOMATCH
        if full != addr and node_address and node_address != node_base and full != node_address:
            return NOMATCH  # another instance of the same resource
        if m.group(2) == "arn":
            return node_arn if node_arn else NOMATCH
        return node_name if node_name else NOMATCH

    return _TOKEN.sub(repl, pattern)
