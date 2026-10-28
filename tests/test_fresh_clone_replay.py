"""Tests for Task A11: Automated fresh-clone offline replay test on Mac hardware (Check C6 / Gate G3).

Verifies that cloning the repository to a fresh directory with network blocked
(https_proxy=http://127.0.0.1:9) and cloud credentials blanked runs the CLI,
canary, Tier-2 heldout replay, realworld replay, and test suite with zero errors.
"""

import os
import sys
import subprocess
from pathlib import Path
import pytest

from tapm.util import PROJECT_ROOT


def test_fresh_clone_script_exists_and_executable():
    """Verify scripts/test-fresh-clone.sh exists and has execute permission."""
    script = PROJECT_ROOT / "scripts" / "test-fresh-clone.sh"
    assert script.exists(), f"Missing script: {script}"
    assert os.access(script, os.X_OK), f"Script not executable: {script}"


def test_fresh_clone_offline_replay_runner_execution():
    """Execute scripts/test-fresh-clone.sh and verify all 4 phases pass offline."""
    script = PROJECT_ROOT / "scripts" / "test-fresh-clone.sh"
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        env={**os.environ, "TAPM_TEST_PYTHON": sys.executable},
    )
    assert proc.returncode == 0, f"test-fresh-clone.sh failed: {proc.stderr}\nstdout:\n{proc.stdout}"

    out = proc.stdout
    assert "✓ Cloned into" in out
    assert "[PASS] tapm --help" in out
    assert "[PASS] tapm paths 006 (emitted PATH-001)" in out
    assert "[PASS] tapm canary (0/6 control failures)" in out
    assert "[PASS] tapm tier2 --heldout: 5 cases, TP=2, FN=0, FP=0, precision=1.0, recall=1.0" in out
    assert "[PASS] tapm realworld: 5 cases, TN=5, FP=0, paths_emitted=0" in out
    assert "[PASS] tests/test_offline_replay.py (3/3 passed offline)" in out
    assert "✓ Task A11 Fresh Clone Offline Replay Test PASSED on Mac" in out


def test_standalone_fresh_clone_offline_replay_runner_execution():
    """Execute scripts/test-fresh-clone.sh --standalone and verify standalone split repo passes offline on Mac (Task W6.2)."""
    script = PROJECT_ROOT / "scripts" / "test-fresh-clone.sh"
    proc = subprocess.run(
        ["bash", str(script), "--standalone"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        env={**os.environ, "TAPM_TEST_PYTHON": sys.executable},
    )
    assert proc.returncode == 0, f"test-fresh-clone.sh --standalone failed: {proc.stderr}\nstdout:\n{proc.stdout}"

    out = proc.stdout
    assert "✓ Cloned standalone package into" in out
    assert "[PASS] tapm --help" in out
    assert "[PASS] tapm paths 006 (emitted PATH-001)" in out
    assert "[PASS] tapm canary (0/6 control failures)" in out
    assert "[PASS] tapm tier2 --heldout: 5 cases, TP=2, FN=0, FP=0, precision=1.0, recall=1.0" in out
    assert "[PASS] tapm realworld: 5 cases, TN=5, FP=0, paths_emitted=0" in out
    assert "[PASS] tests/test_offline_replay.py (3/3 passed offline)" in out
    assert "✓ Task W6.2 Standalone Fresh Clone Offline Replay Test PASSED on Mac" in out



def test_full_suite_clone_contract_rejects_standalone_combination():
    """The full monorepo suite must not pretend to cover omitted deck/history artifacts."""
    script = PROJECT_ROOT / "scripts/test-fresh-clone.sh"
    result = subprocess.run(["bash", str(script), "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "--full-suite" in result.stdout
    result = subprocess.run(["bash", str(script), "--standalone", "--full-suite"], capture_output=True, text=True)
    assert result.returncode == 2
    assert "monorepo" in result.stderr
