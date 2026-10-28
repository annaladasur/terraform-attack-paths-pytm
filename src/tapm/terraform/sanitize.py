"""Plan sanitiser.

HashiCorp documents that saved plans and ``terraform show -json`` output can hold
sensitive values in cleartext. Nothing downstream of this module (artifacts, AI
evidence bundles) receives the raw plan:

* values Terraform marks sensitive (``sensitive_values`` / ``after_sensitive``)
  are replaced with ``"(sensitive)"``;
* variables declared ``sensitive = true`` are redacted;
* ``prior_state`` values and provider configuration are dropped;
* only the top-level keys the pipeline needs are kept.
"""

from __future__ import annotations

import copy
from typing import Any

REDACTED = "(sensitive)"
KEEP_TOP = ("format_version", "terraform_version", "planned_values", "resource_changes", "configuration",
            "variables", "applyable", "complete", "errored")


def _redact(values: Any, mask: Any) -> Any:
    if mask is True:
        return REDACTED
    if isinstance(values, dict) and isinstance(mask, dict):
        return {k: _redact(v, mask.get(k)) for k, v in values.items()}
    if isinstance(values, list) and isinstance(mask, list):
        return [_redact(v, mask[i] if i < len(mask) else None) for i, v in enumerate(values)]
    return values


def sanitize_plan(raw: dict) -> dict:
    plan = {k: copy.deepcopy(v) for k, v in raw.items() if k in KEEP_TOP}

    def walk(module: dict) -> None:
        for r in module.get("resources", []) or []:
            r["values"] = _redact(r.get("values") or {}, r.get("sensitive_values") or {})
        for c in module.get("child_modules", []) or []:
            walk(c)

    walk((plan.get("planned_values") or {}).get("root_module") or {})
    for rc in plan.get("resource_changes", []) or []:
        ch = rc.get("change") or {}
        ch["after"] = _redact(ch.get("after"), ch.get("after_sensitive"))
        ch["before"] = _redact(ch.get("before"), ch.get("before_sensitive"))

    sens_vars = set()

    def walk_cfg(module: dict) -> None:
        for name, v in (module.get("variables") or {}).items():
            if v.get("sensitive"):
                sens_vars.add(name)
                if "default" in v:
                    v["default"] = REDACTED
        for call in (module.get("module_calls") or {}).values():
            walk_cfg(call.get("module") or {})

    cfg = plan.get("configuration") or {}
    cfg.pop("provider_config", None)
    walk_cfg(cfg.get("root_module") or {})
    for name in list((plan.get("variables") or {}).keys()):
        if name in sens_vars:
            plan["variables"][name] = {"value": REDACTED}
    plan["_sanitized"] = {"by": "tapm", "rules": ["sensitive_values", "after_sensitive", "sensitive variables",
                                                  "prior_state dropped", "provider_config dropped", "timestamp dropped"]}
    return plan
