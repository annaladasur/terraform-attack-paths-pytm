"""SARIF 2.1.0 export so attack paths appear in GitHub code scanning next to scanner alerts.

One result per path, located at the first hop's source-located evidence (usually the
ingress rule or IAM statement that opens the path). Related locations list every
other hop's evidence.
"""

from __future__ import annotations

from .. import SCOPE_STATEMENT, __version__

LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _loc(rec, msg: str | None = None) -> dict | None:
    src = rec.source if rec else None
    if not src or not src.get("file"):
        return None
    loc = {"physicalLocation": {"artifactLocation": {"uri": src["file"]},
                                "region": {"startLine": int(src["start_line"]), "endLine": int(src["end_line"])}}}
    if msg:
        loc["message"] = {"text": msg}
    return loc


def to_sarif(res, uri_prefix: str = "") -> dict:
    recs = res.build.ledger.by_id()
    rules, results = {}, []
    for p in res.paths:
        rule_id = f"TAPM-PATH-{p.priority.upper()}"
        rules[rule_id] = {"id": rule_id, "name": f"AttackPath{p.priority.capitalize()}",
                          "shortDescription": {"text": f"{p.priority} priority attack path to a classified asset"},
                          "fullDescription": {"text": f"Plausible attack path to a classified asset. Scope: {SCOPE_STATEMENT}"},
                          "helpUri": "https://example.invalid/terraform-attack-paths-pytm/docs/methodology.md#attack-path",
                          "properties": {"scope": SCOPE_STATEMENT}}
        fine = [recs[e] for h in p.hops for e in h.evidence if e in recs and recs[e].kind in ("NET", "IAM")]
        related = []
        for i, r in enumerate(fine):
            loc = _loc(r, f"{r.id}: {r.summary[:200]}")
            if loc:
                loc["id"] = i
                related.append(loc)
        primary = related[0] if related else _loc(recs.get(p.hops[0].evidence[0]) if p.hops[0].evidence else None)
        if not primary:
            continue
        primary = {k: v for k, v in primary.items() if k in ("physicalLocation",)}
        results.append({
            "ruleId": rule_id, "level": LEVEL[p.priority],
            "message": {"text": p.summary() + (f". Scanner findings on its hops: {', '.join(p.findings)}" if p.findings else "")},
            "locations": [primary], "relatedLocations": related,
            "partialFingerprints": {"attackPathKey": p.key},
            "properties": {"path_id": p.id, "status": p.status, "preconditions": p.preconditions, "nodes": p.nodes,
                           "scope": SCOPE_STATEMENT},
        })
    if uri_prefix:
        for r in results:
            for loc in [*r["locations"], *r["relatedLocations"]]:
                a = loc["physicalLocation"]["artifactLocation"]
                a["uri"] = f"{uri_prefix.rstrip('/')}/{a['uri']}"
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "terraform-attack-paths-pytm", "version": __version__,
                                          "rules": list(rules.values()),
                                          "properties": {"scope": SCOPE_STATEMENT}}},
                      "properties": {"scope": SCOPE_STATEMENT},
                      "results": results}]}
