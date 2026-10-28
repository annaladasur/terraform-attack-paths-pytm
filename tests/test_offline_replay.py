"""Tests for Task A11: Offline replay on a fresh clone (Check C6).

Verifies that evaluation replays (heldout and realworld) run completely offline
without network access and without pre-existing .tools/tier2-repos or
.tools/realworld-repos clones, producing scores identical to committed results.
"""

import json
import os
import sys
import subprocess
from pathlib import Path
import pytest

from tapm.eval.tier2 import run_tier2, T2
from tapm.eval.realworld import run_realworld, RW
from tapm.util import PROJECT_ROOT


def _extract_trailing_json(output: str) -> dict:
    """Extract trailing JSON payload from tapm command output."""
    brace_idx = output.find("{\n  \"tag\":")
    if brace_idx == -1:
        brace_idx = output.find("{")
    assert brace_idx != -1, f"No JSON found in output: {output}"
    return json.loads(output[brace_idx:])


def test_heldout_offline_replay_fresh_clone_isolated(tmp_path: Path):
    """Offline replay of heldout cases with empty repos dir and dummy proxy yields identical scores."""
    empty_repos = tmp_path / "empty_tier2_repos"
    empty_repos.mkdir()

    env = {
        **os.environ,
        "TAPM_TIER2_REPOS": str(empty_repos),
        "https_proxy": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "http_proxy": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "AWS_ACCESS_KEY_ID": "",
        "AWS_SECRET_ACCESS_KEY": "",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    }

    # Run CLI command in subprocess matching verbatim AC: `tapm tier2 --heldout`
    cmd = [
        sys.executable, "-m", "tapm.cli",
        "tier2",
        "--heldout",
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"tapm tier2 --heldout failed: {proc.stderr}\nstdout:\n{proc.stdout}"

    data = _extract_trailing_json(proc.stdout)
    assert data["tag"] == "heldout"
    assert data["cases"] == 5
    assert data["paths_emitted"] == 9
    assert data["paths_scored"] == 2
    assert data["tp"] == 2
    assert data["fn"] == 0
    assert data["fp"] == 0
    assert data["reachability_precision"] == 1.0
    assert data["reachability_recall"] == 1.0

    # Cross-reference with committed gold result
    committed = json.loads((PROJECT_ROOT / "evaluations" / "results" / "tier2-heldout.json").read_text())
    summary = committed["summary"]
    assert data["tp"] == summary["tp"]
    assert data["fn"] == summary["fn"]
    assert data["fp"] == summary["fp"]
    assert data["paths_emitted"] == summary["paths_emitted"]
    assert data["reachability_precision"] == summary["reachability_precision"]
    assert data["reachability_recall"] == summary["reachability_recall"]


def test_realworld_offline_replay_fresh_clone_isolated(tmp_path: Path):
    """Offline replay of realworld benign cases with empty repos dir and dummy proxy yields identical scores."""
    empty_repos = tmp_path / "empty_rw_repos"
    empty_repos.mkdir()

    env = {
        **os.environ,
        "TAPM_TIER2_REPOS": str(empty_repos),
        "TAPM_REALWORLD_REPOS": str(empty_repos),
        "https_proxy": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "http_proxy": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "AWS_ACCESS_KEY_ID": "",
        "AWS_SECRET_ACCESS_KEY": "",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    }

    # Run CLI command in subprocess matching verbatim AC: `tapm realworld`
    cmd = [
        sys.executable, "-m", "tapm.cli",
        "realworld",
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"tapm realworld failed: {proc.stderr}\nstdout:\n{proc.stdout}"

    data = _extract_trailing_json(proc.stdout)
    assert data["tag"] == "benign"
    assert data["cases"] == 5
    assert data["tp"] == 0
    assert data["fn"] == 0
    assert data["fp"] == 0
    assert data["tn"] == 5
    assert data["paths_emitted"] == 0
    assert data["reachability_precision"] is None
    assert data["reachability_recall"] is None

    # Cross-reference with committed gold result
    committed = json.loads((PROJECT_ROOT / "evaluations" / "results" / "realworld-benign.json").read_text())
    summary = committed["summary"]
    assert data["cases"] == summary["cases"]
    assert data["tp"] == summary["tp"]
    assert data["fn"] == summary["fn"]
    assert data["fp"] == summary["fp"]
    assert data["tn"] == summary["tn"]
    assert data["paths_emitted"] == summary["paths_emitted"]


def test_ensure_repo_skipped_when_cached(monkeypatch, tmp_path: Path):
    """Direct assertion that ensure_repo is not invoked when plans and baselines are cached."""
    def fail_if_called(*args, **kwargs):
        raise AssertionError("ensure_repo was called even though plans and baselines are cached!")

    monkeypatch.setattr("tapm.eval.tier2.ensure_repo", fail_if_called)
    monkeypatch.setattr("tapm.eval.realworld.ensure_repo", fail_if_called)

    # Both run_tier2 and run_realworld should complete without calling ensure_repo
    t2_res = run_tier2(manifest_name="manifest-heldout.yaml", out_dir=tmp_path / "t2")
    assert t2_res["summary"]["cases"] == 5
    assert t2_res["summary"]["tp"] == 2

    rw_res = run_realworld(manifest_name="manifest.yaml", out_dir=tmp_path / "rw")
    assert len(rw_res["cases"]) == 5
    assert rw_res["summary"]["tn"] == 5
