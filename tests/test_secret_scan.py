"""Tests for secret scanning before publishing (Task A23 / Finding F32 / Check C16).

Verifies pinned gitleaks scanner configuration, allowlist rules for standard
AWS example keys, clean scan across all plans, baselines and fixtures, negative
detection on synthetic leaked keys, and CI workflow integration.
"""

import gzip
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from tapm.util import PROJECT_ROOT


def test_gitleaks_config_exists_and_contains_documented_allowlists():
    """Verify .gitleaks.toml exists, extends default rules, and documents allowlisted example keys."""
    config_file = PROJECT_ROOT / ".gitleaks.toml"
    assert config_file.exists(), f"Missing {config_file}"

    content = config_file.read_text(encoding="utf-8")
    assert "[extend]" in content
    assert "useDefault = true" in content
    assert "[allowlist]" in content

    # Standard AWS documentation example keys and fixture placeholders
    required_allowlist = [
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAIOSFODNN7EXAMAAA",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY",
        "Sup3rSecr3tPassw0rd1",
        "T2kVB3zgeN3YbrKS",
        "655877f0f8ade541e1d21a48fe396ddb",
    ]
    for key in required_allowlist:
        assert key in content, f"Missing required allowlist entry: {key}"

    # Documentation explanation comments present for the allowlisted keys
    assert "Moto STS mock" in content
    assert "TerraGoat" in content


def test_plans_and_baselines_contain_zero_unallowlisted_akia_keys():
    """Verify all 9+ plans and baselines with AKIA keys contain strictly allowlisted example keys."""
    pattern = re.compile(r"AKIA[0-9A-Z]{16}")
    allowed_keys = {"AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMAAA"}

    plan_files = list(PROJECT_ROOT.glob("evaluations/**/plans/*.json.gz"))
    plan_files.extend(PROJECT_ROOT.glob("fixtures/*/plan.json"))
    plan_files.append(PROJECT_ROOT / "conference-snapshot" / "terraform-plan.json")

    baseline_files = list(PROJECT_ROOT.glob("evaluations/**/baselines/**/*.json"))

    assert len(plan_files) >= 20, f"Expected >= 20 plans, found {len(plan_files)}"
    assert len(baseline_files) >= 10, f"Expected >= 10 baselines, found {len(baseline_files)}"

    unallowlisted = {}
    found_allowed = set()

    for p in plan_files + baseline_files:
        if p.name.endswith(".gz"):
            with gzip.open(p, "rt", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        else:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

        matches = set(pattern.findall(text))
        found_allowed.update(matches & allowed_keys)
        bad = matches - allowed_keys
        if bad:
            unallowlisted[str(p.relative_to(PROJECT_ROOT))] = bad

    assert not unallowlisted, f"Found unallowlisted AKIA keys: {unallowlisted}"
    # Confirm both allowlisted example patterns exist in the scanned corpus
    assert "AKIAIOSFODNN7EXAMPLE" in found_allowed
    assert "AKIAIOSFODNN7EXAMAAA" in found_allowed


def test_src_contains_zero_live_aws_access_keys():
    """Verify zero live or hardcoded AWS access keys in src/."""
    pattern = re.compile(r"AKIA[0-9A-Z]{16}")
    src_dir = PROJECT_ROOT / "src"

    for py_file in src_dir.glob("**/*.py"):
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        matches = pattern.findall(text)
        assert not matches, f"AWS access key pattern found in {py_file}: {matches}"


def test_critic_check_c16_passes():
    """Verify scripts/critic.sh C16 runs and passes."""
    critic_sh = PROJECT_ROOT / "scripts" / "critic.sh"
    res = subprocess.run(["bash", str(critic_sh), "C16"], capture_output=True, text=True, cwd=PROJECT_ROOT)
    assert res.returncode == 0, f"Check C16 failed:\n{res.stdout}\n{res.stderr}"
    assert "gitleaks clean over all plans, baselines, and fixtures" in res.stdout


def test_gitleaks_negative_detection_on_synthetic_leak():
    """Verify gitleaks fails on synthetic leaked AWS key not on the allowlist."""
    gitleaks_bin = shutil.which("gitleaks") or (PROJECT_ROOT / ".tools" / "bin" / "gitleaks")
    if not (isinstance(gitleaks_bin, Path) and gitleaks_bin.exists()) and not shutil.which("gitleaks"):
        pytest.skip("gitleaks binary not found on PATH or in .tools/bin")

    synthetic_key = "AKIA" + "IOSFODNN7EXAM" + "ZZZ"
    with tempfile.TemporaryDirectory() as tmpdir:
        leak_file = Path(tmpdir) / "leaked_secret.tf"
        leak_file.write_text(f'access_key = "{synthetic_key}"\n', encoding="utf-8")

        cmd = [
            str(gitleaks_bin),
            "detect",
            "--source",
            tmpdir,
            "--no-git",
            "--config",
            str(PROJECT_ROOT / ".gitleaks.toml"),
            "--no-banner",
            "--verbose",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode != 0, f"Expected gitleaks to detect synthetic leak, but exited 0:\n{res.stdout}"
        combined_output = res.stdout + res.stderr
        assert "aws-access-token" in combined_output or synthetic_key in combined_output


def test_pinned_gitleaks_in_fetch_tools_and_ci():
    """Verify gitleaks version is pinned in scripts/fetch-tools.sh and .github/workflows/critic.yml."""
    fetch_tools = PROJECT_ROOT / "scripts" / "fetch-tools.sh"
    fetch_content = fetch_tools.read_text(encoding="utf-8")
    assert "GITLEAKS_VERSION=8.30.0" in fetch_content
    assert "gitleaks_${GITLEAKS_VERSION}_checksums.txt" in fetch_content

    critic_yml = (PROJECT_ROOT if (PROJECT_ROOT / "release-manifest.json").exists() else PROJECT_ROOT.parent.parent) / ".github" / "workflows" / "critic.yml"
    ci_content = critic_yml.read_text(encoding="utf-8")
    assert "GITLEAKS_VERSION=8.30.0" in ci_content
    assert "gitleaks_${GITLEAKS_VERSION}_checksums.txt" in ci_content
    assert "gitleaks version" in ci_content
