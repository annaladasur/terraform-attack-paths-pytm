"""Determinism: identical inputs produce byte-identical artifacts, including the PyTM model and DFD."""

import shutil

import pytest

from tapm.eval.replay import replay
from tapm.pytm_gen.generator import generate

from conftest import DEMO, config_for


def test_replay_is_byte_identical(tmp_path):
    rep = replay(config_for(DEMO, tmp_path, no_dfd=shutil.which("dot") is None), n=3)
    assert rep["identical_runs"] == 3
    assert all(a["identical"] for a in rep["artifacts"].values())


def test_generated_pytm_model_is_executable(demo_run, tmp_path):
    import subprocess
    import sys

    model = tmp_path / "threat-model.py"
    model.write_text(generate(demo_run.build, "demo", "0" * 64))
    out = subprocess.run([sys.executable, str(model), "--dfd"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert "digraph tm" in out.stdout and "GRAPH-017" in out.stdout
