"""pytm threat model of this pipeline's own AI layer.

pytm 1.4 ships ``LLM`` and ``Agent`` elements and nine threats for them (LLM01-LLM09:
prompt injection, data leakage to a provider, excessive agency, code execution,
jailbreaks, ...). This module models the AI layer twice with them:

* **this pipeline**, derived from the AI configuration: which backend, whether a
  decision model is called, and the controls the code enforces. Every attribute
  cites the code or test that enforces it, so a regression that, say, offers the
  model a tool shows up as a threat here as well as a failing test;
* **an unsafe design**: a *hypothetical* LLM pull-request reviewer assembled from
  common patterns (raw diff in the prompt, tools, repository credentials). It is
  not a measurement of any product; it is there to show which design decisions
  each pytm threat depends on.

Both are plain pytm files. The classifier (``tapm.pytm_gen.classify --explain``)
then says, for each LLM/Agent threat, whether it fires whatever the undecided
attributes are, depends on them, or cannot fire, and which attribute decides it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

from ..pytm_gen.classify import explain_model
from ..util import dump_json, write_text
from .agents import ROSTER

AGENTS = ROSTER
THIRD_PARTY = {"anthropic", "openai"}
ELEMENT_TYPES = ("LLM", "Agent")

NO_TOOLS = ["src/tapm/ai/llm.py (single request, JSON schema, no tools)", "run-manifest.json: tools_offered_to_models = []",
            "tests/test_ai_boundary.py::test_ai_stage_cannot_mutate_security_truth"]
FILTERING = ["src/tapm/ai/bundle.py: comments withheld, _withhold() for instruction-like plan values",
             "tests/test_ai_boundary.py::test_instruction_like_plan_values_are_withheld_from_the_model",
             "src/tapm/ai/validator.py: 14 checks; make security-tests", "make inject"]
HYPOTHETICAL = ["hypothetical design (not a measurement of any product)"]


# what "cannot fire" in pytm's binary terms does not cover (said next to the result, not hidden behind it)
RESIDUAL = {
    "LLM01": "pytm treats filtering as yes/no. Instruction-like text that passes the filter (resource names, tags) can "
             "still reach the model; the validator rejects any output it cannot support (make inject, lab Level 3).",
    "LLM03": "Nothing sensitive is sent; the provider's retention policy is still a question for the provider.",
    "LLM04": "Depends on how the decision model is trained and updated: a question for the provider.",
    "LLM07": "A jailbroken model can still write text; it only reaches the report if every sentence cites evidence.",
}


def _f(value, evidence, basis) -> dict:
    return {"value": value, "evidence": list(evidence), "basis": basis}


def _this_pipeline(llm: str, jev: str) -> dict:
    third = llm in THIRD_PARTY
    model = {
        "isThirdParty": _f(third, ["src/tapm/ai/llm.py"], f"{llm} API" if third else
                           ("self-hosted model" if llm == "ollama" else f"{llm}: no model call at run time")),
        "isSelfHosted": _f(llm == "ollama", ["src/tapm/ai/llm.py"], "Ollama on the runner" if llm == "ollama" else "not self-hosted"),
        "processesUntrustedInput": _f(True, ["docs/threat-model.md"],
                                      "a pull request is attacker-controlled: resource names, tags and values in the bundle come from it"),
        "hasContentFiltering": _f(True, FILTERING, "comments never reach the model, instruction-like plan values are withheld, "
                                                   "and every output sentence must cite evidence or is rejected"),
        "hasSystemPrompt": _f(True, ["src/tapm/ai/prompts/"], "one system prompt per agent"),
        "hasRAG": _f(False, ["src/tapm/ai/bundle.py: path_bundle()"], "the evidence bundle is built by code for each path; no retrieval"),
        "hasFineTuning": _f(False, ["src/tapm/ai/llm.py"], "a hosted base model, no fine-tuning"),
        "hasAgentCapabilities": _f(False, NO_TOOLS, "no tools, no function calling, no network or shell"),
        "hasAccessToSensitiveSystems": _f(False, NO_TOOLS, "no credentials and no write path: the harness only reads the graph, paths and evidence"),
        "executesCode": _f(False, ["src/tapm/ai/harness.py", "src/tapm/ai/validator.py"],
                           "output is parsed as JSON against a schema and validated; nothing is executed"),
        "processesPersonalData": _f(False, ["src/tapm/ai/bundle.py", "src/tapm/terraform/sanitize.py", "SECURITY.md"],
                                    "an allowlisted view: addresses, evidence IDs and summaries; never the plan, state or secrets"),
    }
    elements = [("n_llm", "LLM", f"Annotation model ({llm})", model, "model provider" if third else "runner")]
    for a in AGENTS:
        elements.append((f"n_{a}", "Agent", f"{a} agent", {
            "usesExternalTools": _f(False, NO_TOOLS, "the agent is one prompt and one JSON reply; no tool servers"),
        }, "runner"))
    if jev == "typesafe":
        elements.append(("n_jev", "LLM", "Decision model (TypeSafe Jev)", {
            "isThirdParty": _f(True, ["src/tapm/ai/jev.py: TypeSafeJev"], "TypeSafe API"),
            "processesUntrustedInput": _f(False, ["src/tapm/ai/jev.py: path_state()"],
                                          "sees counts, enums and IDs derived by code, never configuration text"),
            "hasContentFiltering": _f(True, ["src/tapm/ai/jev.py: path_state()"], "the only input is a typed feature vector"),
            "hasRAG": _f(False, ["src/tapm/ai/jev.py"], "no retrieval"),
            "hasAgentCapabilities": _f(False, ["src/tapm/ai/jev.py"], "returns a decision; the harness acts on it"),
            "hasAccessToSensitiveSystems": _f(False, ["src/tapm/ai/jev.py"], "no credentials"),
            "executesCode": _f(False, ["src/tapm/ai/jev.py"], "decisions are enums checked by code"),
            "processesPersonalData": _f(False, ["src/tapm/ai/jev.py: path_state()"], "no configuration values"),
        }, "decision provider"))
    return {"title": "This pipeline's AI layer", "llm": llm, "jev": jev, "elements": elements,
            "assumptions": ["Scope: the models and agents. The deterministic core, validator and report are modelled in docs/threat-model.md.",
                            "Undecided attributes (provider retention, the decision model's training) are questions for the provider."]}


def _unsafe_design() -> dict:
    h = HYPOTHETICAL
    model = {
        "isThirdParty": _f(True, h, "hosted model API"),
        "processesUntrustedInput": _f(True, h + ["src/tapm/ai/injection.py (the unsafe stand-in)"], "the raw pull-request diff is pasted into the prompt"),
        "hasContentFiltering": _f(False, h + ["src/tapm/ai/injection.py (the unsafe stand-in)"], "comments and values reach the model unfiltered"),
        "hasSystemPrompt": _f(True, h, "a reviewer persona prompt"),
        "hasRAG": _f(True, h, "retrieves repository files for context"),
        "hasFineTuning": _f(False, h, "a hosted base model"),
        "hasAgentCapabilities": _f(True, h, "posts comments, approves pull requests, runs commands"),
        "hasAccessToSensitiveSystems": _f(True, h, "the CI token can write to the repository; cloud credentials are in the runner"),
        "executesCode": _f(True, h, "runs the terraform commands it suggests"),
        "processesPersonalData": _f(True, h + ["SECURITY.md"], "the full plan output: plans can contain secrets in cleartext"),
        "controls.providesConfidentiality": _f(False, h, "the full plan leaves the organisation"),
        "controls.encodesOutput": _f(False, h, "model text is posted verbatim"),
        "controls.implementsPOLP": _f(False, h, "one broad CI token"),
        "controls.isHardened": _f(False, h, "commands run on the CI runner"),
    }
    agent = {
        "usesExternalTools": _f(True, h, "tool servers (MCP) for the repository and the cloud"),
        "validatesToolLaunchConfig": _f(False, h, "tool servers are configured from files the pull request can change"),
    }
    return {"title": "Unsafe design (hypothetical LLM pull-request reviewer)", "llm": "hosted", "jev": "none",
            "elements": [("n_llm", "LLM", "Review model (hosted)", model, "model provider"),
                         ("n_agent", "Agent", "Review agent", agent, "runner")],
            "assumptions": ["A hypothetical composite of common patterns, not a measurement of any product."]}


def _render(value) -> str:
    return repr(value)


def generate_model(profile: dict) -> str:
    L: list[str] = []
    w = L.append
    w("#!/usr/bin/env python3")
    w("# GENERATED by terraform-attack-paths-pytm (tapm ai-model). Plain OWASP pytm 1.4; every attribute cites the code,")
    w("# test or design statement that decides it. Attributes not set are undecided.")
    w("from pytm import TM, Actor, Agent, Boundary, Dataflow, LLM, Process")
    w("")
    w(f"tm = TM({profile['title']!r}, description={('pytm model of an AI layer that reviews Terraform pull requests. ' + profile['assumptions'][0])!r})")
    w("tm.isOrdered = True")
    w(f"tm.assumptions = {profile['assumptions']!r}")
    w("")
    bounds = sorted({b for *_, b in profile["elements"]})
    for b in bounds:
        w(f"b_{re.sub(r'[^a-z]', '_', b)} = Boundary({('CI runner' if b == 'runner' else b.capitalize())!r})")
    w("b_internet = Boundary('Internet')")
    w("author = Actor('Pull-request author (untrusted)')")
    w("author.inBoundary = b_internet")
    w("reviewer = Actor('Human reviewer')")
    w("reviewer.inBoundary = b_internet")
    w("core = Process('Harness: deterministic core, validator, report')")
    w("core.inBoundary = b_runner")
    w("core.inScope = False  # modelled in docs/threat-model.md")
    w("")
    for var, cls, name, facts, b in profile["elements"]:
        w(f"{var} = {cls}({name!r})")
        w(f"{var}.inBoundary = b_{re.sub(r'[^a-z]', '_', b)}")
        for attr, f in sorted(facts.items()):
            ev = "; ".join(f["evidence"])
            w(f"{var}.{attr} = {_render(f['value'])}  # {f['basis']} [{ev}]")
    w("")
    w("# flows are drawn for the DFD; the element threats above are what this model evaluates")
    flows = [("author", "core", "Terraform change (pull request)")]
    agents = [v for v, cls, *_ in profile["elements"] if cls == "Agent"]
    for a in agents:
        flows += [("core", a, "evidence bundle"), (a, "n_llm", "prompt + schema"), ("n_llm", a, "JSON reply"), (a, "core", "annotation")]
    if any(v == "n_jev" for v, *_ in profile["elements"]):
        flows += [("core", "n_jev", "feature vector"), ("n_jev", "core", "decision")]
    flows.append(("core", "reviewer", "report (validated annotations only)" if profile["jev"] != "none" else "review comment"))
    for i, (s, d, label) in enumerate(flows, start=1):
        w(f"df_{i:03d} = Dataflow({s}, {d}, {label!r})")
        w(f"df_{i:03d}.inScope = False")
    w("")
    w('if __name__ == "__main__":')
    w("    tm.process()")
    return "\n".join(L) + "\n"


def controls_json(profile: dict) -> dict:
    return {name: facts for _, _, name, facts, _ in profile["elements"]}


def run_ai_models(out_dir: str | Path, llm: str = "anthropic", jev: str = "typesafe") -> dict:
    """Write both models, run pytm's LLM/Agent threats over them, and write ai-threats.json."""
    out = Path(out_dir)
    profiles = {"this_pipeline": _this_pipeline(llm, jev), "unsafe_design": _unsafe_design()}
    explained: dict[str, list] = {}
    hashes = {}
    for key, prof in profiles.items():
        d = out / key
        d.mkdir(parents=True, exist_ok=True)
        hashes[f"{key}/threat-model.py"] = write_text(d / "threat-model.py", generate_model(prof))
        hashes[f"{key}/pytm-controls.json"] = dump_json(controls_json(prof), d / "pytm-controls.json")
        explained[key] = explain_model(d / "threat-model.py", d / "pytm-controls.json", d / "pytm-explained.json", ELEMENT_TYPES)
        _render_dfd(d)
    threats: dict[str, dict] = {}
    for key, rows in explained.items():
        for r in rows:
            t = threats.setdefault(r["threat_id"], {"threat_id": r["threat_id"], "description": r["description"],
                                                    "condition": r["condition"], "this_pipeline": [], "unsafe_design": []})
            t[key].append({k: r[k] for k in ("element", "status", "decided", "undecided")})
    table = []
    for tid in sorted(threats, key=lambda x: int(x[3:])):
        t = threats[tid]
        t["this_pipeline_status"] = _worst(t["this_pipeline"])
        t["unsafe_design_status"] = _worst(t["unsafe_design"])
        if tid in RESIDUAL:
            t["residual"] = RESIDUAL[tid]
        table.append(t)
    count = lambda key, st: sum(1 for t in table if t[f"{key}_status"] == st)  # noqa: E731
    summary = {k: {st: count(k, st) for st in ("fires", "depends", "cannot_fire")} for k in profiles}
    result = {"llm": llm, "jev": jev, "summary": summary, "threats": table,
              "note": "pytm 1.4's LLM01-LLM09. 'fires': whatever the undecided attributes are; 'depends': for some values "
                      "of them; 'cannot_fire': for none. The unsafe design is hypothetical."}
    hashes["ai-threats.json"] = dump_json(result, out / "ai-threats.json")
    result["hashes"] = hashes
    return result


def _worst(rows: list[dict]) -> str:
    order = ("fires", "depends", "cannot_fire")
    return min((r["status"] for r in rows), key=order.index, default="n/a")


def _render_dfd(d: Path) -> None:
    dfd = subprocess.run([sys.executable, str(d / "threat-model.py"), "--dfd"], capture_output=True, text=True, timeout=120)
    if dfd.returncode != 0:
        raise RuntimeError(f"pytm --dfd failed: {dfd.stderr[-2000:]}")
    from ..pytm_gen.runner import _portable_dot

    (d / "dfd.dot").write_text(_portable_dot(dfd.stdout), encoding="utf-8")
    dot = shutil.which("dot")
    if dot:
        raw = d / "_raw.dot"
        raw.write_text(dfd.stdout, encoding="utf-8")
        subprocess.run([dot, "-Tpng", str(raw), "-o", str(d / "dfd.png")], check=True, timeout=120)
        raw.unlink()
