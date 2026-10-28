"""An attack path in plain words: the card a developer (or anyone) reads instead of a threat list."""

from __future__ import annotations

import re

import pytest

from conftest import DEMO, FIXTURES, config_for, fixture_dirs

# what a non-technical reader must never see: Terraform addresses, file:line, evidence IDs
_JARGON = re.compile(r"aws_\w+\.\w+|\b(?:GRAPH|IAM|TF|NET|SCAN|PATH|APP)-\d+|\.tf\b")


def _res(fx, tmp):
    from tapm.pipeline import run_deterministic

    return run_deterministic(config_for(fx, tmp, no_dfd=False))


@pytest.fixture(scope="module")
def res006(tmp_path_factory):
    return _res(DEMO, tmp_path_factory.mktemp("s006"))


def test_developer_card_tells_the_path_with_the_line_to_change(res006):
    from tapm.report.story import path_story

    st = path_story(res006, res006.paths[0], "developer")
    assert st["headline"].startswith("HIGH: Someone on the internet could list and read the customer-data bucket")
    assert "SSRF" in st["what_could_happen"]
    assert [s["where"] for s in st["steps"]] == ["alb.tf:3", "network.tf:94-100", "app.tf:10-13", "iam.tf:25-35"]
    assert [s["assumption"] for s in st["steps"]] == [False, False, True, False]
    assert "wildcard" in st["steps"][-1]["text"]
    assert st["fix"]["where"] == "iam.tf:25-35" and "the path disappears" in st["fix"]["text"]
    assert any("personal data" in q["question"] for q in st["questions"])


def test_everyone_card_has_no_jargon_and_explains_its_words(res006):
    from tapm.report.story import path_story, render_story

    st = path_story(res006, res006.paths[0], "everyone")
    text = render_story(st)
    assert not _JARGON.search(text), _JARGON.findall(text)
    assert {"IMDS", "SSRF", "wildcard", "condition"} <= set(st["glossary"])
    assert all(not s["where"] and not s["evidence"] for s in st["steps"])


@pytest.mark.parametrize("fx", [d for d in fixture_dirs()], ids=lambda d: d.name[:3])
def test_every_path_in_every_fixture_gets_a_jargon_free_card(fx, tmp_path):
    from tapm.report.story import path_story, render_story

    res = _res(fx, tmp_path)
    for p in res.paths:
        dev = path_story(res, p, "developer")
        assert dev["steps"] and dev["fix"], (fx.name, p.id)
        text = render_story(path_story(res, p, "everyone"))
        assert not _JARGON.search(text), (fx.name, p.id, _JARGON.findall(text))


@pytest.mark.parametrize("fx,headline,fix", [
    ("002-public-s3", "Someone on the internet could read the exports bucket", "S3 Block Public Access"),
    ("021-passrole-escalation", "could become administrator of the whole AWS account", "Stop the dev user from taking on the ops role"),
    ("017-cross-module-references", "could read the data bucket", "Narrow the permission of the iam role"),
])
def test_other_path_shapes_read_naturally(fx, headline, fix, tmp_path):
    from tapm.report.story import path_story

    res = _res(FIXTURES / fx, tmp_path)
    st = path_story(res, res.paths[0], "everyone")
    assert headline in st["headline"] and fix in st["fix"]["text"]


def test_report_and_story_artifacts(tmp_path):
    from tapm.pipeline import run

    res = run(config_for(DEMO, tmp_path, no_dfd=False))
    report = (tmp_path / "report.md").read_text()
    assert report.index("## In plain words") < report.index("## PATH-001")
    story = (tmp_path / "story.md").read_text()
    body = story.split("\n", 3)[3]
    assert "## Path 1" in story and not _JARGON.search(body), _JARGON.findall(body)
    assert "story.md" not in res.hashes  # derived output, like report.md: not part of the determinism contract


def test_a_verified_patch_is_told_without_file_names_to_everyone(tmp_path):
    """With the remediation loop on, the fix comes from the proven patch; the everyone card still names no file."""
    from tapm.pipeline import run

    cfg = config_for(DEMO, tmp_path, no_dfd=False)
    cfg.remediate = {"llm": "simulated"}
    res = run(cfg)
    from tapm.report.story import path_story

    dev, every = path_story(res, res.paths[0], "developer"), path_story(res, res.paths[0], "everyone")
    assert dev["fix"]["proven"] and every["fix"]["proven"]
    assert "remediation-PATH-001.diff" in dev["fix"]["text"] and dev["fix"]["where"].endswith(".tf")
    body = (tmp_path / "story.md").read_text().split("\n", 3)[3]
    assert not _JARGON.search(body), _JARGON.findall(body)
