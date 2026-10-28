"""Every artifact the pipeline writes conforms to the published JSON Schemas."""

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from tapm.ai.harness import run_ai

from conftest import FIXTURES, ROOT

SCHEMAS = ROOT / "schemas"


def schema(name):
    return json.loads((SCHEMAS / name).read_text())


def test_graph_paths_evidence_conform(demo_run):
    out = Path(demo_run.cfg.out_dir)
    graph = json.loads((out / "resource-graph.json").read_text())
    for n in graph["nodes"]:
        jsonschema.validate(n, schema("resource.schema.json"))
    for e in graph["edges"]:
        jsonschema.validate(e, schema("edge.schema.json"))
    for p in json.loads((out / "attack-paths.json").read_text())["paths"]:
        jsonschema.validate(p, schema("path.schema.json"))
    jsonschema.validate(json.loads((out / "evidence.json").read_text()), schema("evidence.schema.json"))


def test_ai_artifacts_conform(demo_run, tmp_path):
    out = run_ai(demo_run, {"llm": "simulated", "jev": "local", "cassette_dir": str(tmp_path)})
    for a in out["annotations"]:
        jsonschema.validate(a, schema("annotation.schema.json"))
    for d in out["decisions"]:
        jsonschema.validate(d, schema("jev-decision.schema.json"))


@pytest.mark.parametrize("gold", sorted(FIXTURES.glob("*/gold.yaml")), ids=lambda p: p.parent.name)
def test_gold_labels_conform(gold):
    jsonschema.validate(yaml.safe_load(gold.read_text()), schema("gold.schema.json"))
