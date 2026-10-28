"""Load ``terraform show -json`` output into typed plan resources.

What we read and why:

* ``planned_values``      -> attribute values Terraform knows at plan time.
* ``resource_changes``    -> which of those values are unknown / sensitive.
* ``prior_state``         -> data sources Terraform could read during plan
                             (for example ``aws_iam_policy_document``).
* ``configuration``       -> expression *references*. For new resources most IDs and
                             ARNs are unknown at plan time, so the configuration
                             references are what tell us that ``aws_instance.app``
                             points at ``aws_iam_instance_profile.app``.

Nothing here guesses. If a value is unknown it is recorded as unknown.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..util import base_address

_REF_RESOURCE = re.compile(r"^(data\.)?[a-z0-9_]+\.[A-Za-z0-9_-]+")
_IGNORED_REF_ROOTS = ("count.", "each.", "path.", "terraform.", "self.")


@dataclass
class PlanResource:
    address: str
    mode: str  # managed | data
    type: str
    name: str
    index: Any
    module: str  # "" for root, else "module.a.module.b"
    provider: str
    values: dict[str, Any]
    unknown: dict[str, Any] = field(default_factory=dict)
    sensitive: dict[str, Any] = field(default_factory=dict)
    actions: list[str] = field(default_factory=list)
    # top-level attribute -> resolved referenced resource base addresses
    references: dict[str, list[str]] = field(default_factory=dict)
    # top-level attribute -> raw configuration expression (for symbolic fallbacks)
    expressions: dict[str, Any] = field(default_factory=dict)
    unresolved_refs: list[str] = field(default_factory=list)
    pending_refs: list[tuple[str, str]] = field(default_factory=list)  # (attr, local.* ref) resolved later from source

    @property
    def base(self) -> str:
        return base_address(self.address)

    def is_unknown(self, attr: str) -> bool:
        return self.unknown.get(attr) is True

    def all_references(self) -> list[str]:
        out: set[str] = set()
        for refs in self.references.values():
            out.update(refs)
        return sorted(out)


@dataclass
class Plan:
    path: str | None
    terraform_version: str
    format_version: str
    resources: dict[str, PlanResource]
    variables: dict[str, Any]
    raw: dict[str, Any]
    ctx: Any = None

    def apply_locals(self, locals_map: dict[tuple[str, str], dict]) -> None:
        """Resolve ``local.*`` references using locals recovered from source (the plan omits locals)."""
        if self.ctx is None:
            return
        self.ctx.locals.update({k: v["refs"] for k, v in locals_map.items()})
        self.ctx.locals_raw.update({k: v["raw"] for k, v in locals_map.items() if v.get("raw")})
        for pr in self.resources.values():
            prefix = pr.module + "." if pr.module else ""
            still = []
            for attr, ref in pr.pending_refs:
                got = self.ctx.resolve(ref, prefix)
                if got:
                    pr.references[attr] = sorted(set(pr.references.get(attr, [])) | set(got))
                    pr.unresolved_refs = [u for u in pr.unresolved_refs if u != ref]
                else:
                    still.append((attr, ref))
            pr.pending_refs = still

    def by_type(self, *types: str) -> list[PlanResource]:
        return [r for a, r in sorted(self.resources.items()) if r.type in types]

    def instances_of(self, base: str) -> list[PlanResource]:
        return [r for a, r in sorted(self.resources.items()) if r.base == base]

    def get(self, address: str) -> PlanResource | None:
        return self.resources.get(address)


def load_plan(path: str | Path) -> Plan:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_plan(raw, str(path))


def parse_plan(raw: dict[str, Any], path: str | None = None) -> Plan:
    resources: dict[str, PlanResource] = {}

    def walk_values(module: dict[str, Any], module_addr: str) -> None:
        for r in module.get("resources", []) or []:
            pr = PlanResource(
                address=r["address"],
                mode=r.get("mode", "managed"),
                type=r["type"],
                name=r["name"],
                index=r.get("index"),
                module=module_addr,
                provider=r.get("provider_name", ""),
                values=r.get("values") or {},
                sensitive=r.get("sensitive_values") or {},
            )
            resources[pr.address] = pr
        for child in module.get("child_modules", []) or []:
            walk_values(child, child.get("address", ""))

    walk_values((raw.get("planned_values") or {}).get("root_module") or {}, "")

    # Data sources read during planning live in prior_state.
    prior = ((raw.get("prior_state") or {}).get("values") or {}).get("root_module") or {}

    def walk_prior(module: dict[str, Any], module_addr: str) -> None:
        for r in module.get("resources", []) or []:
            if r.get("mode") != "data" or r["address"] in resources:
                continue
            resources[r["address"]] = PlanResource(
                address=r["address"],
                mode="data",
                type=r["type"],
                name=r["name"],
                index=r.get("index"),
                module=module_addr,
                provider=r.get("provider_name", ""),
                values=r.get("values") or {},
                sensitive=r.get("sensitive_values") or {},
            )
        for child in module.get("child_modules", []) or []:
            walk_prior(child, child.get("address", ""))

    walk_prior(prior, "")

    for rc in raw.get("resource_changes", []) or []:
        addr = rc["address"]
        change = rc.get("change") or {}
        pr = resources.get(addr)
        if pr is None:
            # Deferred data sources and deletions have no planned value.
            pr = PlanResource(
                address=addr,
                mode=rc.get("mode", "managed"),
                type=rc["type"],
                name=rc["name"],
                index=rc.get("index"),
                module=rc.get("module_address", ""),
                provider=rc.get("provider_name", ""),
                values=change.get("after") or {},
            )
            resources[addr] = pr
        pr.actions = list(change.get("actions") or [])
        pr.unknown = change.get("after_unknown") or {}
        if change.get("after_sensitive"):
            pr.sensitive = change.get("after_sensitive") or pr.sensitive

    configs = _index_configuration(raw.get("configuration") or {})
    for pr in resources.values():
        cfg = configs.get(pr.base)
        if not cfg:
            continue
        expressions, module_prefix, ctx = cfg
        pr.expressions = expressions
        for attr, expr in sorted(expressions.items()):
            refs: set[str] = set()
            for ref in _collect_refs(expr):
                resolved = ctx.resolve(ref, module_prefix)
                if resolved:
                    refs.update(resolved)
                elif not ref.startswith(_IGNORED_REF_ROOTS):
                    pr.unresolved_refs.append(ref)
                    if ref.startswith("local."):
                        pr.pending_refs.append((attr, ref))
            if refs:
                pr.references[attr] = sorted(refs)
        pr.unresolved_refs = sorted(set(pr.unresolved_refs))

    variables = {k: v.get("value") for k, v in (raw.get("variables") or {}).items()}
    return Plan(
        path=path,
        terraform_version=raw.get("terraform_version", ""),
        format_version=raw.get("format_version", ""),
        resources=dict(sorted(resources.items())),
        variables=variables,
        raw=raw,
        ctx=next(iter(configs.values()))[2] if configs else None,
    )


def _collect_refs(expr: Any) -> list[str]:
    out: list[str] = []
    if isinstance(expr, dict):
        out.extend(expr.get("references", []) or [])
        for k, v in expr.items():
            if k not in ("references", "constant_value"):
                out.extend(_collect_refs(v))
    elif isinstance(expr, list):
        for item in expr:
            out.extend(_collect_refs(item))
    return out


class _ConfigContext:
    """Resolves references across module boundaries (var.*, module.x.output, local.*)."""

    def __init__(self) -> None:
        # module prefix ("" or "module.a.") -> module config dict
        self.modules: dict[str, dict[str, Any]] = {}
        # (module prefix, local name) -> raw references, recovered from source
        self.locals: dict[tuple[str, str], list[str]] = {}
        self.locals_raw: dict[tuple[str, str], str] = {}

    def resolve(self, ref: str, prefix: str, depth: int = 0) -> list[str]:
        return sorted({base for base, _ in self.resolve_attr(ref, prefix, depth)})

    def resolve_attr(self, ref: str, prefix: str, depth: int = 0) -> list[tuple[str, str | None]]:
        """-> [(resource base address, attribute or None)]"""
        if depth > 16 or ref.startswith(_IGNORED_REF_ROOTS):
            return []
        if ref.startswith("local."):
            out = []
            for r in self.locals.get((prefix, ref.split(".")[1]), []):
                out.extend(self.resolve_attr(r, prefix, depth + 1))
            return sorted(set(out), key=str)
        if ref.startswith("var."):
            var = ref.split(".")[1]
            parent_prefix, call = _split_module_prefix(prefix)
            if call is None:
                return []
            parent = self.modules.get(parent_prefix) or {}
            call_cfg = (parent.get("module_calls") or {}).get(call) or {}
            expr = (call_cfg.get("expressions") or {}).get(var)
            out = []
            for r in _collect_refs(expr):
                out.extend(self.resolve_attr(r, parent_prefix, depth + 1))
            return sorted(set(out), key=str)
        if ref.startswith("module."):
            parts = ref.split(".")
            if len(parts) < 3:
                return []
            child_prefix = f"{prefix}module.{_strip_index(parts[1])}."
            child = self.modules.get(child_prefix) or {}
            output = (child.get("outputs") or {}).get(parts[2]) or {}
            out = []
            for r in _collect_refs(output.get("expression")):
                out.extend(self.resolve_attr(r, child_prefix, depth + 1))
            return sorted(set(out), key=str)
        m = _REF_RESOURCE.match(ref)
        if not m:
            return []
        rest = ref[m.end():]
        rest = re.sub(r"^\[[^\]]*\]", "", rest)
        attr = rest.lstrip(".").split(".")[0] or None
        return [(prefix + m.group(0), attr)]


def _strip_index(name: str) -> str:
    return re.sub(r"\[.*\]$", "", name)


def _split_module_prefix(prefix: str) -> tuple[str, str | None]:
    """``module.a.module.b.`` -> (``module.a.``, ``b``)."""
    if not prefix:
        return "", None
    parts = prefix.rstrip(".").split(".")
    call = parts[-1]
    parent = ".".join(parts[:-2])
    return (parent + "." if parent else ""), call


def _index_configuration(configuration: dict[str, Any]):
    ctx = _ConfigContext()
    index: dict[str, tuple[dict[str, Any], str, _ConfigContext]] = {}

    def walk(module: dict[str, Any], prefix: str) -> None:
        ctx.modules[prefix] = module
        for r in module.get("resources", []) or []:
            addr = prefix + r["address"]
            index[addr] = (r.get("expressions") or {}, prefix, ctx)
        for name, call in sorted((module.get("module_calls") or {}).items()):
            walk(call.get("module") or {}, f"{prefix}module.{name}.")

    walk(configuration.get("root_module") or {}, "")
    return index
