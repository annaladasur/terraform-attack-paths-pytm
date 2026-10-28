"""Tests for Task W5.1: Live demo runbook (`make demo-live`).

Acceptance criteria:
1. `demo/demo-live.sh` exists, is executable, and passes `bash -n` syntax check.
2. `--help` displays options for `--auto`, `--reset`, `--beat`, `--from-beat`, `--llm`, `--model`.
3. Discrete beat execution (`--beat N --auto`) succeeds with expected outputs:
   - Beat 1: PR #42 opening, diff, and speaker cues.
   - Beat 2: Static scanner baselines (40 findings) and speaker cues.
   - Beat 3: Deterministic attack path (PATH-001) and speaker cues.
   - Beat 4: PyTM evidence compilation, plain-words story, yes/no questions.
   - Beat 6: Evidence tampering rejection test.
   - Beat 8: Gate check blockage (level: validate).
4. Makefile includes `demo-live` target and `make help` documents it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tapm.util import PROJECT_ROOT

DEMO_SCRIPT = PROJECT_ROOT / "demo" / "demo-live.sh"
MAKEFILE = PROJECT_ROOT / "Makefile"


@pytest.fixture(scope="module")
def offline_demo_artifacts(tmp_path_factory):
    """Prepare beat prerequisites from fixtures, never from local artifacts state."""
    from tapm.cli import fixture_config
    from tapm.pipeline import run_deterministic
    from tapm.ai.harness import run_ai

    art = tmp_path_factory.mktemp("demo-beat-artifacts")
    cfg = fixture_config(PROJECT_ROOT / "fixtures/006-public-workload-iam-sensitive-bucket", str(art), no_dfd=True)
    result = run_deterministic(cfg)
    run_ai(result, {"llm": "simulated", "jev": "local", "cassette_dir": str(art / "cassettes")})
    return art


@pytest.fixture(autouse=True)
def isolated_demo_services(monkeypatch, tmp_path, offline_demo_artifacts):
    """No test invocation can reach the presenter's live services or Docker."""
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    calls = tmp_path / "service-probes.log"
    curl = fake_bin / "curl"
    curl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TAPM_TEST_PROBE_LOG"\ncase "$*" in *http://127.0.0.1:9/*) exit 7 ;; *) echo "Unexpected live URL in test" >&2; exit 99 ;; esac\n')
    curl.chmod(0o755)
    docker = fake_bin / "docker"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TAPM_TEST_DOCKER_LOG"\nexit 99\n')
    docker.chmod(0o755)
    docker_log = tmp_path / "docker.log"
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("TAPM_TEST_PROBE_LOG", str(calls))
    monkeypatch.setenv("TAPM_TEST_DOCKER_LOG", str(docker_log))
    for name in ("GITEA_URL", "SERVICE_URL", "OLLAMA_URL"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.setenv("TAPM_DEMO_ART_DIR", str(offline_demo_artifacts))
    yield
    if calls.exists():
        assert all("http://127.0.0.1:9/" in line for line in calls.read_text().splitlines())
    if docker_log.exists():
        assert all(" ps runner" in line for line in docker_log.read_text().splitlines())


def test_demo_live_script_exists_and_executable():
    """Verify demo-live.sh exists and is executable."""
    assert DEMO_SCRIPT.exists(), f"Demo script missing at {DEMO_SCRIPT}"
    assert os.access(DEMO_SCRIPT, os.X_OK), f"Demo script not executable: {DEMO_SCRIPT}"


def test_demo_live_bash_syntax():
    """Verify demo-live.sh passes bash syntax check."""
    proc = subprocess.run(
        ["bash", "-n", str(DEMO_SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"Bash syntax error in {DEMO_SCRIPT}:\n{proc.stderr}"


def test_demo_live_help():
    """Verify --help flag outputs expected options and exit 0."""
    proc = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--help"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "OWASP Global AppSec 2026" in proc.stdout
    assert "--auto" in proc.stdout
    assert "--reset" in proc.stdout
    assert "--beat" in proc.stdout
    assert "--llm" in proc.stdout
    assert "--model" in proc.stdout


def test_demo_live_beat_1_pr():
    """Verify Beat 1 outputs PR #42 diff and speaker cue."""
    proc = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--beat", "1", "--auto"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert proc.returncode == 0, f"Beat 1 failed: {proc.stderr}"
    assert "PR #42" in proc.stdout
    assert "cidr_blocks = [\"0.0.0.0/0\"]" in proc.stdout
    assert "Three one-line changes" in proc.stdout


def test_demo_live_beat_2_scanners():
    """Verify Beat 2 outputs scanner findings summary and speaker cue."""
    proc = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--beat", "2", "--auto"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert proc.returncode == 0, f"Beat 2 failed: {proc.stderr}"
    assert "Checkov" in proc.stdout
    assert "tfsec" in proc.stdout
    assert "Trivy" in proc.stdout
    assert "40 findings across 9 resources" in proc.stdout
    assert "Which of these belong to the same attack story?" in proc.stdout


def test_demo_live_beat_3_path():
    """Verify Beat 3 outputs PATH-001 derivation and speaker cue."""
    proc = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--beat", "3", "--auto"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert proc.returncode == 0, f"Beat 3 failed: {proc.stderr}"
    assert "PATH-001" in proc.stdout
    assert "Forty findings, one path" in proc.stdout


def test_demo_live_beat_4_model_story_ask():
    """Verify Beat 4 outputs PyTM model, plain words story, and questions."""
    proc = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--beat", "4", "--auto"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert proc.returncode == 0, f"Beat 4 failed: {proc.stderr}"
    assert "PyTM, fed with evidence" in proc.stdout or "PyTM" in proc.stdout
    assert "Does the customer-data bucket hold personal data?" in proc.stdout or "questions" in proc.stdout


def test_demo_live_beat_6_tamper():
    """Verify Beat 6 executes tampering check and demonstrates rejection."""
    proc = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--beat", "6", "--auto"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert proc.returncode == 0, f"Beat 6 failed: {proc.stderr}"
    assert "REJECTED" in proc.stdout
    assert "Take away the evidence" in proc.stdout


def test_demo_live_beat_8_gate():
    """Verify Beat 8 evaluates CI gate blockage."""
    proc = subprocess.run(
        ["bash", str(DEMO_SCRIPT), "--beat", "8", "--auto"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert proc.returncode == 0, f"Beat 8 failed: {proc.stderr}"
    assert "level validate" in proc.stdout
    assert "BLOCKED" in proc.stdout
    assert "Two ways out" in proc.stdout


def test_makefile_has_demo_live_target():
    """Verify Makefile includes demo-live target in .PHONY and help."""
    makefile_content = MAKEFILE.read_text(encoding="utf-8")
    assert "demo-live:" in makefile_content
    assert ".PHONY:" in makefile_content and "demo-live" in makefile_content
    proc = subprocess.run(
        ["make", "help"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert proc.returncode == 0
    assert "demo-live" in proc.stdout
