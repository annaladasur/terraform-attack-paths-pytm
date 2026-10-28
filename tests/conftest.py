from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
DEMO = FIXTURES / "006-public-workload-iam-sensitive-bucket"


def fixture_dirs() -> list[Path]:
    return sorted(d for d in FIXTURES.iterdir() if d.is_dir() and (d / "plan.json").exists() and (d / "gold.yaml").exists())


def config_for(fx: Path, out: Path, **kw):
    from tapm.cli import fixture_config

    cfg = fixture_config(fx, str(out), no_dfd=kw.pop("no_dfd", True))
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


@pytest.fixture(scope="session")
def demo_run(tmp_path_factory):
    from tapm.pipeline import run_deterministic

    return run_deterministic(config_for(DEMO, tmp_path_factory.mktemp("demo")))


@pytest.fixture(scope="session", autouse=True)
def clean_git_tree_check():
    import subprocess

    proc = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
    initial_status = set(proc.stdout.strip().splitlines()) if proc.stdout.strip() else set()
    yield
    proc_after = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
    final_status = set(proc_after.stdout.strip().splitlines()) if proc_after.stdout.strip() else set()
    added_or_changed = final_status - initial_status
    removed = initial_status - final_status
    if added_or_changed or removed:
        msg = ["Test suite modified git working tree:"]
        if added_or_changed:
            msg.append("New/modified:")
            msg.extend(f"  {line}" for line in sorted(added_or_changed))
        if removed:
            msg.append("Removed:")
            msg.extend(f"  {line}" for line in sorted(removed))
        pytest.fail("\n".join(msg))



# These checks compare code against speaker slides, which are deliberately outside
# the standalone research package. Core runtime, evidence and security tests remain.
_STANDALONE_PRESENTATION_ONLY = {
    "test_false_path_story.py::test_slide_14_contains_blind_numbers_first_and_held_out",
    "test_false_path_story.py::test_b51_metrics_slide_reconciliation",
    "test_false_path_story.py::test_seven_of_seven_always_qualified_across_deck",
    "test_false_path_story.py::test_no_zero_false_paths_without_denominator",
    "test_m1_parity.py::test_deck_before_matches_executive_report_m1",
    "test_roster.py::test_deck_and_architecture_roster_alignment",
}


def pytest_collection_modifyitems(items):
    if not (ROOT / "release-manifest.json").exists():
        return
    for item in items:
        name = item.nodeid.removeprefix("tests/")
        if name in _STANDALONE_PRESENTATION_ONLY:
            item.add_marker(pytest.mark.skip(reason="Standalone scope excludes the private speaker deck; see PUBLIC-RELEASE.md"))
