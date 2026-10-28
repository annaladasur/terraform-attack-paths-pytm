"""Tests verifying the unified seven-role agent roster across code, schemas, prompts, and docs."""

from __future__ import annotations

import json
from pathlib import Path

from tapm.ai.agents import PROMPTS, ROSTER, SCHEMAS, simulate
import tapm.ai.agents as agents_mod
import tapm.ai.jev as jev_mod
import tapm.ai.self_model as self_model_mod

EXPECTED_ROSTER = (
    "path_narrator",
    "plain_explainer",
    "finding_explainer",
    "remediation",
    "framework_mapper",
    "adversarial_reviewer",
    "patch_author",
)


def test_roster_exact_seven_roles():
    assert ROSTER == EXPECTED_ROSTER
    assert len(ROSTER) == 7


def test_roster_consistency_across_modules():
    assert agents_mod.ROSTER == EXPECTED_ROSTER
    assert agents_mod.AGENTS == EXPECTED_ROSTER
    assert jev_mod.AGENTS == EXPECTED_ROSTER
    assert self_model_mod.AGENTS == EXPECTED_ROSTER


def test_every_role_has_schema():
    for role in ROSTER:
        assert role in SCHEMAS, f"Missing schema for role {role}"
        assert SCHEMAS[role]["type"] == "object"
        assert "properties" in SCHEMAS[role]


def test_every_role_has_prompt_file():
    for role in ROSTER:
        prompt_path = PROMPTS / f"{role}.md"
        assert prompt_path.exists(), f"Missing prompt file {prompt_path}"
        assert len(prompt_path.read_text(encoding="utf-8").strip()) > 0


def test_every_role_simulates_valid_json(demo_run):
    from tapm.ai.bundle import path_bundle
    from tapm.ai.remediate import patch_bundle

    path = demo_run.paths[0]
    bundle = path_bundle(demo_run, path, demo_run.remedies)
    ctx = {"bundle": bundle}

    for role in ROSTER:
        if role == "adversarial_reviewer":
            ctx_rev = {"bundle": bundle, "annotation": {"statement": "Test statement [GRAPH-001]."}}
            out_str = simulate(role, ctx_rev)
        elif role == "patch_author":
            pb = patch_bundle(demo_run, path, demo_run.remedies, [])
            out_str = simulate(role, {"bundle": pb})
        else:
            out_str = simulate(role, ctx)

        data = json.loads(out_str)
        assert isinstance(data, dict), f"Role {role} did not return a JSON object"


def test_deck_and_architecture_roster_alignment():
    root = Path(__file__).resolve().parent.parent.parent
    build_deck = (root / "deck" / "build-deck.js").read_text(encoding="utf-8")
    arch_doc = (root / "terraform-attack-paths-pytm" / "docs" / "architecture.md").read_text(encoding="utf-8")

    # All seven roles appear in Slide 10 and B8 in build-deck.js
    for role in ("path narrator", "plain explainer", "finding explainer", "remediation", "framework mapper", "adversarial reviewer", "patch author"):
        assert role in build_deck, f"Missing role '{role}' in deck/build-deck.js"

    # All seven role identifiers appear in architecture.md
    for role in EXPECTED_ROSTER:
        assert f"`{role}`" in arch_doc, f"Missing role '{role}' in docs/architecture.md"
