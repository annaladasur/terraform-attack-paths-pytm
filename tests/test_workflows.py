"""Unit and integration tests for example CI/CD workflows and trigger filters (W0.5).

Verifies that GitHub Actions (pr-security.yml, nightly-canary.yml) and GitLab CI (.gitlab-ci.yml)
correctly implement §5 Trigger Matrix:
  - PR triggers on *.tf, *.tfvars, *.tfvars.json, .terraform.lock.hcl,
    attack-path-exceptions.yaml, and threat-answers.yaml.
  - tapm run passes --remediate so verified fixes reach the PR.
  - Verified remediation diffs and remediations.json are uploaded as artifacts.
  - Path cache avoids re-planning when only exceptions or answers change.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
GHA_PR = EXAMPLES / "github-actions" / "pr-security.yml"
GHA_CANARY = EXAMPLES / "github-actions" / "nightly-canary.yml"
GITLAB_CI = EXAMPLES / "gitlab" / ".gitlab-ci.yml"


def test_github_actions_pr_workflow_valid_yaml():
    assert GHA_PR.exists(), f"Missing {GHA_PR}"
    content = yaml.safe_load(GHA_PR.read_text(encoding="utf-8"))
    assert content["name"] == "Terraform attack-path review"
    assert "pull_request" in content[True] or "pull_request" in content.get("on", {})


def test_github_actions_pr_trigger_filters():
    content = yaml.safe_load(GHA_PR.read_text(encoding="utf-8"))
    on_clause = content.get("on") or content.get(True)
    pr_paths = on_clause["pull_request"]["paths"]

    # Must cover *.tf
    assert any("*.tf" in p or "**.tf" in p for p in pr_paths)

    # Must cover *.tfvars and *.tfvars.json
    assert any("tfvars" in p for p in pr_paths)
    assert any("tfvars.json" in p for p in pr_paths)

    # Must cover .terraform.lock.hcl (both root and nested)
    assert any("terraform.lock.hcl" in p for p in pr_paths)

    # Must cover attack-path-exceptions.yaml (both root and nested)
    assert any("attack-path-exceptions.yaml" in p for p in pr_paths)

    # Must cover threat-answers.yaml (both root and nested)
    assert any("threat-answers.yaml" in p for p in pr_paths)


def test_github_actions_pr_steps_remediation_and_cache():
    text = GHA_PR.read_text(encoding="utf-8")
    content = yaml.safe_load(text)
    steps = content["jobs"]["attack-paths"]["steps"]

    # Must have cache step for attack-paths
    cache_steps = [s for s in steps if s.get("id") == "path-cache" or "actions/cache" in s.get("uses", "")]
    assert len(cache_steps) >= 1
    cache_step = cache_steps[0]
    assert "attack-paths" in cache_step.get("with", {}).get("path", "")

    # tapm run step must pass --remediate
    run_steps = [s for s in steps if "tapm run" in s.get("run", "")]
    assert len(run_steps) >= 1
    assert "--remediate" in run_steps[0]["run"]

    # Artifact upload must include remediation artifacts
    upload_steps = [s for s in steps if "actions/upload-artifact" in s.get("uses", "")]
    assert len(upload_steps) >= 1
    artifact_paths = upload_steps[0].get("with", {}).get("path", "")
    assert "attack-paths/remediations.json" in artifact_paths
    assert "attack-paths/remediation-*.diff" in artifact_paths


def test_gitlab_ci_workflow_valid_yaml():
    assert GITLAB_CI.exists(), f"Missing {GITLAB_CI}"
    content = yaml.safe_load(GITLAB_CI.read_text(encoding="utf-8"))
    job = content["attack-paths"]
    assert "rules" in job
    rule = job["rules"][0]
    changes = rule["changes"]

    # Must cover *.tf
    assert any("*.tf" in c for c in changes)

    # Must cover tfvars
    assert any("tfvars" in c for c in changes)
    assert any("tfvars.json" in c for c in changes)

    # Must cover lock file
    assert any("terraform.lock.hcl" in c for c in changes)

    # Must cover exceptions and answers
    assert any("attack-path-exceptions.yaml" in c for c in changes)
    assert any("threat-answers.yaml" in c for c in changes)

    # Script must include --remediate
    script_str = " ".join(job["script"])
    assert "--remediate" in script_str

    # Artifacts must include remediations
    artifacts = job["artifacts"]["paths"]
    assert "attack-paths/remediations.json" in artifacts
    assert "attack-paths/remediation-*.diff" in artifacts


def test_nightly_canary_workflow():
    assert GHA_CANARY.exists()
    content = yaml.safe_load(GHA_CANARY.read_text(encoding="utf-8"))
    on_clause = content.get("on") or content.get(True)
    assert "schedule" in on_clause
    assert "workflow_dispatch" in on_clause
    assert "canary" in content["jobs"]
    assert "default-branch" in content["jobs"]


def _matches_any(path: str, patterns: list[str]) -> bool:
    """Simulate GitHub/GitLab glob path matching."""
    norm = path.replace("\\", "/")
    for pat in patterns:
        if pat.startswith("infra/**."):
            # e.g. infra/**.tf -> match infra/.*\.tf
            suffix = pat[len("infra/**."):]
            if norm.startswith("infra/") and norm.endswith("." + suffix):
                return True
        elif fnmatch.fnmatch(norm, pat):
            return True
        # Handle **/ matching within directory
        elif "**/" in pat:
            prefix, rest = pat.split("**/", 1)
            if norm.startswith(prefix) and (norm.endswith("/" + rest) or norm[len(prefix):].endswith(rest) or fnmatch.fnmatch(norm[len(prefix):], rest)):
                return True
    return False


def test_path_matching_simulation():
    content = yaml.safe_load(GHA_PR.read_text(encoding="utf-8"))
    on_clause = content.get("on") or content.get(True)
    patterns = on_clause["pull_request"]["paths"]

    # Files that MUST match
    must_match = [
        "infra/main.tf",
        "infra/modules/vpc/main.tf",
        "infra/terraform.tfvars",
        "infra/envs/prod.tfvars",
        "infra/app.tfvars.json",
        "infra/.terraform.lock.hcl",
        "infra/modules/vpc/.terraform.lock.hcl",
        "infra/attack-path-exceptions.yaml",
        "infra/modules/vpc/attack-path-exceptions.yaml",
        "infra/threat-answers.yaml",
        "infra/modules/vpc/threat-answers.yaml",
    ]
    for path in must_match:
        assert _matches_any(path, patterns), f"Expected pattern to match {path}"

    # Files that MUST NOT match
    must_not_match = [
        "README.md",
        "docs/architecture.md",
        "app/main.py",
        "app/requirements.txt",
        ".github/workflows/pr-security.yml",
        "other/file.tf",
    ]
    for path in must_not_match:
        assert not _matches_any(path, patterns), f"Expected pattern NOT to match {path}"
