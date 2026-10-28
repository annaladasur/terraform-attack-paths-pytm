"""Tests for Task W6.1: Standalone repository preparation.

Verifies standalone CI workflows, 100% SHA-pinned GitHub Actions, zero monorepo path leaks,
issue templates YAML validity, README quick start and lab documentation, and split script integrity.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from tapm.util import PROJECT_ROOT


def test_standalone_workflows_exist_and_pin_actions_by_sha():
    """Verify standalone workflows exist and all uses: directives are pinned by full 40-char commit SHA."""
    workflows_dir = PROJECT_ROOT / ".github" / "workflows"
    assert workflows_dir.exists(), f"Missing workflows directory: {workflows_dir}"

    ci_yml = workflows_dir / "ci.yml"
    critic_yml = workflows_dir / "critic.yml"

    assert ci_yml.exists(), "Missing .github/workflows/ci.yml"
    assert critic_yml.exists(), "Missing .github/workflows/critic.yml"

    sha_pattern = re.compile(r"^\s*uses:\s+([^@\s]+)@([0-9a-f]{40})\b")
    any_uses_pattern = re.compile(r"^\s*uses:\s+([^#\n]+)")

    for wf in [ci_yml, critic_yml]:
        content = wf.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict)
        assert "jobs" in parsed

        # Check action pinning by full commit SHA
        lines = content.splitlines()
        uses_count = 0
        for line in lines:
            m_any = any_uses_pattern.match(line)
            if m_any:
                action_ref = m_any.group(1).strip()
                if action_ref.startswith("./"):
                    continue  # local action
                uses_count += 1
                m_sha = sha_pattern.match(line)
                assert m_sha, f"Unpinned action in {wf.name}: {line.strip()}"
                sha = m_sha.group(2)
                assert len(sha) == 40, f"Action SHA not 40 chars in {wf.name}: {sha}"

        assert uses_count >= 1, f"Expected actions in {wf.name}"


def test_standalone_workflows_contain_zero_monorepo_path_leaks():
    """Verify standalone workflows contain no monorepo prefix paths."""
    workflows_dir = PROJECT_ROOT / ".github" / "workflows"
    for wf in workflows_dir.glob("*.yml"):
        content = wf.read_text(encoding="utf-8")
        assert "OWASP-GLOBAL-AppSec-US-2026" not in content, (
            f"Monorepo path leak in {wf.name}: OWASP-GLOBAL-AppSec-US-2026 found"
        )


def test_issue_templates_exist_and_parse_as_valid_yaml():
    """Ordinary issues remain enabled; no unmonitored audience intake is offered."""
    template_dir = PROJECT_ROOT / ".github" / "ISSUE_TEMPLATE"
    config = yaml.safe_load((template_dir / "config.yml").read_text(encoding="utf-8"))
    assert config == {"blank_issues_enabled": True}
    retired = ["1-commitment.yml", "2-report-30.yml", "3-report-90.yml", "4-report-180.yml"]
    assert not any((template_dir / name).exists() for name in retired)


def test_readme_documents_quick_starts_and_all_labs():
    """Verify README documents offline quickstart, local stack (<= 10 min), 3-level lab, and enhanced cluster lab."""
    readme_path = PROJECT_ROOT / "README.md"
    assert readme_path.exists(), "Missing README.md"
    content = readme_path.read_text(encoding="utf-8")

    # Offline CLI
    assert "make setup" in content
    assert "make demo" in content
    assert "make remediate" in content

    # Local stack
    assert "Local stack" in content
    assert "make local-up" in content
    assert "examples/local-stack/README.md" in content

    # 3-level audience lab
    assert "make lab-1" in content
    assert "make lab-2" in content
    assert "make lab-3" in content
    assert "labs/README.md" in content

    # Enhanced cluster lab
    assert "Enhanced lab" in content
    assert "make lab-cluster" in content
    assert "examples/local-cluster/README.md" in content


def test_split_script_exists_and_passes_verify():
    """Verify scripts/split-repo.sh exists, is executable, and passes verification."""
    split_sh = PROJECT_ROOT / "scripts" / "split-repo.sh"
    assert split_sh.exists(), "Missing scripts/split-repo.sh"
    assert os.access(split_sh, os.X_OK), "scripts/split-repo.sh is not executable"

    res = subprocess.run(
        ["bash", str(split_sh), "--verify"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert res.returncode == 0, f"split-repo.sh --verify failed:\n{res.stdout}\n{res.stderr}"
    assert "Standalone package tree contains all required files" in res.stdout
