"""Classify pytm findings by what the Terraform evidence decides.

pytm evaluates each threat condition against element attributes that default to
False, so an unset control reads as a missing control. For every (threat, element)
pair this module separates what the plan decides from what it cannot see:

* **confirmed**: the threat fires for *every* value of the attributes the plan does
  not decide. The evidence alone establishes it.
* **needs app team**: the threat fires with pytm's defaults, but some value of an
  undecided attribute (input validation, session handling...) would clear it. A
  question for the application owners, not a finding about the infrastructure.
* **mitigated**: an evidence-backed override (``Finding(response='mitigated')``).
* **ruled out**: the *generic* model (the same architecture with no evidence-fed
  controls) reports it, and the evidence rules it out.

It runs the generated model in its own interpreter (pytm keeps model state in
class variables): ``python -m tapm.pytm_gen.classify threat-model.py
pytm-controls.json pytm-findings.json``.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

from .facts import STRUCTURAL, condition_attrs

PACK_PREFIX = "TAPM-"
MAX_UNKNOWN = 12  # 2^12 evaluations per pair at most; above this the pair is "needs app team"
CLASS_ORDER = ("confirmed", "mitigated", "needs_app_team", "ruled_out")

# a flow's control copied from an element by pytm's _apply_defaults: flow attribute -> (end, element attribute)
_COPIED = {"controls.isEncrypted": ("sink", "controls.isEncrypted"),
           "controls.authenticatesDestination": ("source", "controls.authenticatesDestination"),
           "controls.checksDestinationRevocation": ("source", "controls.checksDestinationRevocation")}
_STRUCTURAL = STRUCTURAL | {"inputs", "outputs", "inBoundary", "source", "sink", "source.inBoundary", "sink.inBoundary"}


def _split(path: str) -> tuple[str | None, str]:
    """'sink.controls.x' -> ('sink', 'controls.x'); 'controls.x' -> (None, 'controls.x')."""
    head, _, rest = path.partition(".")
    if head in ("source", "sink") and rest:
        return head, rest
    return None, path


def _data_owner(e, path: str):
    """'data:<Data name>.<attribute>' -> (the Data object on flow e, attribute)."""
    name, attr = path[len("data:"):].rsplit(".", 1)
    return next(d for d in getattr(e, "data", []) or [] if d.name == name), attr


def _owner(e, path: str):
    if path.startswith("data:"):
        return _data_owner(e, path)
    end, rel = _split(path)
    obj = getattr(e, end) if end else e
    if rel.startswith("controls."):
        return obj.controls, rel.split(".", 1)[1]
    return obj, rel


def _get(e, path: str):
    obj, name = _owner(e, path)
    return getattr(obj, name, None)


def _set(e, path: str, value) -> None:
    obj, name = _owner(e, path)
    setattr(obj, name, value)


def _default(e, path: str):
    obj, name = _owner(e, path)
    field = type(obj).model_fields.get(name)
    if field is None:
        return False
    return field.get_default(call_default_factory=True)


class Classifier:
    def __init__(self, ns: dict, facts: dict[str, dict]):
        from pytm import TM, Dataflow

        self.TM, self.Dataflow = TM, Dataflow
        self.tm = ns["tm"]
        self.facts = facts

    # --------------------------------------------------------------- decidability
    def _fact(self, e, path: str) -> tuple[dict | None, str]:
        """(fact, where) if the evidence decides ``path`` on element ``e``."""
        end, rel = _split(path)
        if end:
            node = getattr(e, end, None)
            f = self.facts.get(getattr(node, "name", ""), {}).get(rel)
            return f, f"{end} {getattr(node, 'name', '')}"
        own = self.facts.get(e.name, {}).get(path)
        if own is not None:
            return own, "element"
        if isinstance(e, self.Dataflow) and path in _COPIED:
            which, attr = _COPIED[path]
            node = getattr(e, which)
            f = self.facts.get(node.name, {}).get(attr)
            if f is not None:
                return f, f"{which} {node.name} (pytm copies it to the flow)"
        return None, ""

    def _data_fact(self, e, d, attr: str) -> tuple[dict | None, str]:
        f = self.facts.get(f"data:{d.name}", {}).get(attr)
        if f is not None:
            return f, f"data {d.name}"
        # pytm copies at-rest encryption of stored data from the flow's endpoints; for data that is not stored it
        # does not apply
        end = {"isDestEncryptedAtRest": "sink", "isSourceEncryptedAtRest": "source"}.get(attr)
        stored = self.facts.get(f"data:{d.name}", {}).get("isStored")
        if end and stored is not None and stored["value"] is False:
            return {"value": False, "evidence": stored["evidence"], "basis": "not stored, so at-rest encryption does not apply"}, \
                f"data {d.name}"
        if end and getattr(d, "isStored", False):
            node = getattr(e, end)
            f = self.facts.get(node.name, {}).get("controls.isEncryptedAtRest")
            if f is not None:
                return f, f"{end} {node.name} (pytm copies it to the data)"
        return None, ""

    def _split_attrs(self, e, condition: str):
        decided, unknown_bool, opaque = {}, [], []
        paths = condition_attrs(condition)
        data = list(getattr(e, "data", None) or [])
        if data and "data" in paths:
            # `any(d.isPII for d in target.data)`: expand into the attributes of each Data object the flow carries
            paths = [x for x in paths if x != "data"]
            for d in data:
                for attr in sorted(set(re.findall(r"\bd\.([A-Za-z_]+)", condition))):
                    path = f"data:{d.name}.{attr}"
                    f, where = self._data_fact(e, d, attr)
                    if f is not None:
                        decided[path] = {"value": f["value"], "evidence": f["evidence"], "basis": f["basis"], "on": where}
                    elif isinstance(getattr(d, attr, None), bool):
                        unknown_bool.append(path)
                    else:
                        opaque.append(path)
        for path in paths:
            if path in _STRUCTURAL:
                continue
            f, where = self._fact(e, path)
            if f is not None:
                decided[path] = {"value": f["value"], "evidence": f["evidence"], "basis": f["basis"], "on": where}
                continue
            try:
                v = _get(e, path)
            except AttributeError:
                v = None
            if isinstance(v, bool):
                unknown_bool.append(path)
            else:
                opaque.append(path)
        return decided, unknown_bool, opaque

    def _fires_for_all(self, t, e, unknown: list[str]) -> tuple[bool, bool]:
        """(fires for every assignment, fires for some assignment) of the undecided booleans."""
        saved = {p: _get(e, p) for p in unknown}
        every, some = True, False
        try:
            for values in itertools.product((False, True), repeat=len(unknown)):
                for p, v in zip(unknown, values):
                    _set(e, p, v)
                if t.apply(e):
                    some = True
                else:
                    every = False
                if some and not every:
                    break
        finally:
            for p, v in saved.items():
                _set(e, p, v)
        return every, some

    # --------------------------------------------------------------- generic baseline
    def _reset_to_defaults(self) -> None:
        """Undo every evidence-fed fact: what pytm sees when it is given only the architecture."""
        for d in self.TM._data:
            for attr in self.facts.get(f"data:{d.name}", {}):
                setattr(d, attr, type(d).model_fields[attr].get_default(call_default_factory=True))
            if getattr(d, "isStored", False):
                d.isDestEncryptedAtRest = d.isSourceEncryptedAtRest = False
        for e in self.TM._elements:
            for path in self.facts.get(e.name, {}):
                _set(e, path, _default(e, path))
            if isinstance(e, self.Dataflow):
                for path, (which, attr) in _COPIED.items():
                    if attr in self.facts.get(getattr(e, which).name, {}):
                        _set(e, path, _default(e, path))

    def _elements(self):
        return [e for e in self.TM._elements if getattr(e, "inScope", True)]

    # --------------------------------------------------------------- main
    def run(self, prepared: bool = False) -> dict:
        tm = self.tm
        if not prepared:
            tm.check()
            tm.resolve()
        published = {(f.threat_id, f.element.name): f for f in tm.findings}
        rows: dict[tuple[str, str], dict] = {}
        for (tid, name), f in published.items():
            e, t = f.element, next(x for x in self.TM._threats if x.id == tid)
            decided, unknown, opaque = self._split_attrs(e, t.condition)
            row = self._row(t, e, decided, unknown + opaque)
            if getattr(f, "response", "") == "mitigated" or (not t.apply(e)):
                row["class"] = "mitigated"
                row["override"] = next((o.references for o in getattr(e, "overrides", []) if o.threat_id == tid), "")
            elif opaque or len(unknown) > MAX_UNKNOWN:
                row["class"] = "needs_app_team"
            else:
                every, _ = self._fires_for_all(t, e, unknown)
                row["class"] = "confirmed" if every else "needs_app_team"
            rows[(tid, name)] = row

        # threats an element's assumption excludes (pytm's Assumption(exclude=...)): ruled out, with the assumption named
        excluded = {(f.threat_id, f.element.name): getattr(getattr(f, "assumption", None), "name", "")
                    for f in getattr(tm, "excluded_findings", []) or []}
        # the same architecture without evidence-fed facts, built-in threats only
        pack = [t for t in self.TM._threats if t.id.startswith(PACK_PREFIX)]
        builtin = [t for t in self.TM._threats if not t.id.startswith(PACK_PREFIX)]
        fed = {e.name: {t.id: self._split_attrs(e, t.condition)[0] for t in builtin} for e in self._elements()}
        self._reset_to_defaults()
        generic = set()
        for e in self._elements():
            for t in builtin:
                if t.apply(e):
                    generic.add((t.id, e.name))
                    if (t.id, e.name) not in rows:
                        rows[(t.id, e.name)] = {**self._row(t, e, fed[e.name][t.id], []), "class": "ruled_out"}
                        if (t.id, e.name) in excluded:
                            rows[(t.id, e.name)]["assumption"] = excluded[(t.id, e.name)]
        for key, row in rows.items():
            row["in_generic"] = key in generic

        findings = sorted(rows.values(), key=lambda r: (CLASS_ORDER.index(r["class"]), r["element"], r["threat_id"]))
        count = {c: sum(1 for r in findings if r["class"] == c) for c in CLASS_ORDER}
        summary = {
            "generic": len(generic),
            "published": len(published),
            **count,
            "pack": sum(1 for r in findings if r["source"] == "pack" and r["class"] != "ruled_out"),
            "added_by_evidence": sum(1 for r in findings if r["source"] == "pytm" and not r["in_generic"]),
            "decided_by_answers": sum(1 for r in findings if r["class"] != "needs_app_team"
                                      and any(x.startswith("APP-") for v in r["decided"].values() for x in v["evidence"])),
            "pack_threats": sorted(t.id for t in pack),
        }
        return {"summary": summary, "findings": findings}

    def _row(self, t, e, decided: dict, undecided: list[str]) -> dict:
        row = {
            "threat_id": t.id,
            "source": "pack" if t.id.startswith(PACK_PREFIX) else "pytm",
            "element": e.name,
            "element_type": type(e).__name__,
            "description": t.description,
            "severity": t.severity,
            "condition": t.condition,
            "decided": dict(sorted(decided.items())),
            "undecided": sorted(undecided),
        }
        if isinstance(e, self.Dataflow):
            row["flow"] = {"source": e.source.name, "sink": e.sink.name}
        return row


# which hop a cloud-pack threat speaks about: ("in", types) = the hop into the element, ("out", types) = the first
# hop of that type from the element onwards
PACK_HOPS = {"TAPM-NET-01": ("in", ("EXPOSES",)), "TAPM-LMB-01": ("in", ("EXPOSES",)),
             "TAPM-EC2-01": ("out", ("ASSUMES",)), "TAPM-EC2-02": ("out", ("ASSUMES",)),
             "TAPM-IAM-01": ("out", ("ALLOWS",)), "TAPM-IAM-02": ("in", ("ALLOWS",)), "TAPM-S3-01": ("in", ("ALLOWS",))}
_GRAPH_ID = re.compile(r"\((GRAPH-\d+)\)$")


def _hop_of(row: dict, path) -> int | None:
    """1-based hop of ``path`` that a classified finding speaks about, or None."""
    name = {n.replace('"', "'"): i for i, n in enumerate(path.nodes)}
    hops = path.hops
    if "flow" in row:
        m = _GRAPH_ID.search(row["element"])
        for i, h in enumerate(hops, start=1):
            if m and h.edge == m.group(1):
                return i
        src, dst = name.get(row["flow"]["source"]), name.get(row["flow"]["sink"])
        if src is None or dst is None or dst <= src:
            return None
        # a READS/WRITES flow from a workload stands for the grant (ALLOWS) that reaches the asset
        return next((i for i, h in enumerate(hops, start=1) if i > src and h.type == "ALLOWS" and name.get(h.dst) == dst), None)
    at = name.get(row["element"])
    if at is None:
        return None
    way, types = PACK_HOPS.get(row["threat_id"], ("in", None))
    if way == "out":
        return next((i for i, h in enumerate(hops, start=1) if i > at and h.type in types), None)
    return next((i for i, h in enumerate(hops, start=1) if i == at and (types is None or h.type in types)), None)


def link_paths(classification: dict, paths) -> dict:
    """Add ``on_paths`` (path ID and hop number) to every published finding that speaks about an attack-path hop."""
    for row in classification["findings"]:
        if row["class"] == "ruled_out":
            continue
        on = [{"path": p.id, "hop": h} for p in paths if (h := _hop_of(row, p))]
        if on:
            row["on_paths"] = on
    s = classification["summary"]
    s["on_path_hops"] = sum(1 for r in classification["findings"] if r.get("on_paths"))
    s["confirmed_on_path_hops"] = sum(1 for r in classification["findings"]
                                      if r.get("on_paths") and r["class"] in ("confirmed", "mitigated"))
    return classification


def explain_in_process(model: Path, facts: dict, element_types: tuple[str, ...]) -> list[dict]:
    """For every threat that targets one of ``element_types``: does it fire whatever the undecided attributes are
    ("fires"), for some values of them ("depends"), or for none ("cannot_fire")?"""
    from pytm import TM

    TM.reset()
    ns = runpy.run_path(str(model), run_name="tapm_classify")
    c = Classifier(ns, facts)
    c.tm.check()
    out = []
    for e in c._elements():
        kind = type(e).__name__
        if kind not in element_types:
            continue
        for t in c.TM._threats:
            if kind not in [x if isinstance(x, str) else x.__name__ for x in t.target]:
                continue
            decided, unknown, opaque = c._split_attrs(e, t.condition)
            if opaque or len(unknown) > MAX_UNKNOWN:
                every, some = False, True
            else:
                every, some = c._fires_for_all(t, e, unknown)
            status = "fires" if every else ("depends" if some else "cannot_fire")
            out.append({**c._row(t, e, decided, unknown + opaque), "status": status, "fires_with_defaults": bool(t.apply(e))})
    return sorted(out, key=lambda r: (r["threat_id"], r["element"]))


def render_in_process(model: Path, facts: dict | None, out_dir: Path) -> None:
    """Everything pytm's CLI would do for ``--seq --dfd --json``, in the same order, in one interpreter, then the
    classification (last: it temporarily changes attributes). Writes _seq.puml, _dfd.dot, _pytm.json and, with
    facts, pytm-findings.json into ``out_dir``."""
    from pytm import TM
    from pytm.pytm import to_serializable

    from ..util import dump_json

    TM.reset()
    ns = runpy.run_path(str(model), run_name="tapm_classify")
    tm = ns["tm"]
    tm.check()
    (out_dir / "_seq.puml").write_text(tm.seq() + "\n", encoding="utf-8")
    (out_dir / "_dfd.dot").write_text(tm.dfd(colormap=False, levels=set()) + "\n", encoding="utf-8")
    def undraw() -> None:  # pytm draws each element once per process; reset before another diagram
        for x in list(TM._elements) + list(TM._boundaries):
            x.is_drawn = False

    # level 0: only what the generator put on an attack path (the overview a non-specialist reads)
    undraw()
    (out_dir / "_dfd_overview.dot").write_text(tm.dfd(colormap=False, levels={0}) + "\n", encoding="utf-8")
    tm.resolve()
    for e in TM._elements:  # pytm 1.4.0 leaks findings onto out-of-scope elements (fixed on pytm main, #338)
        if not getattr(e, "inScope", True):
            e.findings = []
    (out_dir / "_pytm.json").write_text(json.dumps(tm, default=to_serializable), encoding="utf-8")
    if facts is not None:
        cls = Classifier(ns, facts).run(prepared=True)
        dump_json(cls, out_dir / "pytm-findings.json")
        # pytm's --colormap, coloured by what the plan decides rather than by every generic threat
        by_name = {e.name: e for e in TM._elements}
        for e in TM._elements:
            e.severity = 0
        for r in cls["findings"]:
            if r["class"] == "confirmed" and r["element"] in by_name:
                by_name[r["element"]]._set_severity(r["severity"])
        undraw()
        (out_dir / "_dfd_risk.dot").write_text(tm.dfd(colormap=True, levels=set()) + "\n", encoding="utf-8")


def render_model(model: str | Path, controls: str | Path | None, out_dir: str | Path) -> None:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(Path(__file__).parents[2]), os.environ.get("PYTHONPATH")]))}
    cp = subprocess.run([sys.executable, "-m", "tapm.pytm_gen.classify", "--render", str(model), str(controls or "-"), str(out_dir)],
                        capture_output=True, text=True, timeout=600, env=env)
    if cp.returncode != 0:
        raise RuntimeError(f"pytm failed: {cp.stderr[-2000:]}")


def classify_in_process(model: Path, facts: dict) -> dict:
    from pytm import TM

    TM.reset()
    ns = runpy.run_path(str(model), run_name="tapm_classify")
    return Classifier(ns, facts).run()


def classify_model(model: str | Path, controls: str | Path, out: str | Path) -> dict:
    """Run the classifier in a fresh interpreter and return (and write) pytm-findings.json."""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(Path(__file__).parents[2]), os.environ.get("PYTHONPATH")]))}
    cp = subprocess.run([sys.executable, "-m", "tapm.pytm_gen.classify", str(model), str(controls), str(out)],
                        capture_output=True, text=True, timeout=600, env=env)
    if cp.returncode != 0:
        raise RuntimeError(f"pytm classification failed: {cp.stderr[-2000:]}")
    return json.loads(Path(out).read_text(encoding="utf-8"))


def explain_model(model: str | Path, controls: str | Path, out: str | Path, element_types: tuple[str, ...]) -> list[dict]:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(Path(__file__).parents[2]), os.environ.get("PYTHONPATH")]))}
    cp = subprocess.run([sys.executable, "-m", "tapm.pytm_gen.classify", "--explain", ",".join(element_types),
                         str(model), str(controls), str(out)], capture_output=True, text=True, timeout=600, env=env)
    if cp.returncode != 0:
        raise RuntimeError(f"pytm explanation failed: {cp.stderr[-2000:]}")
    return json.loads(Path(out).read_text(encoding="utf-8"))


def main(argv: list[str]) -> None:
    from ..util import dump_json

    if argv and argv[0] == "--render":
        model, controls, out = argv[1:4]
        facts = json.loads(Path(controls).read_text(encoding="utf-8")) if controls != "-" else None
        render_in_process(Path(model), facts, Path(out))
        return
    explain = None
    if argv and argv[0] == "--explain":
        explain, argv = tuple(argv[1].split(",")), argv[2:]
    model, controls, out = (Path(a) for a in argv)
    facts = json.loads(controls.read_text(encoding="utf-8"))
    if explain:
        dump_json(explain_in_process(model, facts, explain), out)
    else:
        dump_json(classify_in_process(model, facts), out)


if __name__ == "__main__":
    main(sys.argv[1:])
