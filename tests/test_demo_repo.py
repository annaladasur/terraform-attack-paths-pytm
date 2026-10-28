"""Tests for Task W2.4: Demo repository seed and open-pr script.

Acceptance criteria:
1. examples/local-stack/demo-repo/ with the base infrastructure, the PR #42 branch,
   the fix branch, and the injection branch (fixture 019's comments, already committed);
2. All four branches reproduce fixture 006/019 plans byte for byte;
3. open-pr.sh creates the pull request through the Gitea API (tested with mock API);
4. seed-demo-repo.sh initializes local git repository and creates bundles cleanly.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from tapm.terraform.offline_plan import plan_fixture, source_key
from tapm.util import PROJECT_ROOT

LOCAL_STACK_DIR = PROJECT_ROOT / "examples" / "local-stack"
DEMO_REPO_DIR = LOCAL_STACK_DIR / "demo-repo"
SEED_SCRIPT = LOCAL_STACK_DIR / "seed-demo-repo.sh"
OPEN_PR_SCRIPT = LOCAL_STACK_DIR / "open-pr.sh"
BUNDLE_FILE = LOCAL_STACK_DIR / "demo-repo.bundle"

BASE_DIR = PROJECT_ROOT / "demo" / "base"
FX_006_DIR = PROJECT_ROOT / "fixtures" / "006-public-workload-iam-sensitive-bucket"
FX_019_DIR = PROJECT_ROOT / "fixtures" / "019-prompt-injection-comments"
FIX_CACHE_KEY = (DEMO_REPO_DIR / "branches/fix/.plan-source-key").read_text().strip()
FIX_PLAN_CACHE = PROJECT_ROOT / "plan-cache" / f"{FIX_CACHE_KEY}.json.gz"


def canonical_fix_plan():
    # Independent committed planner cache, never a developer's artifacts directory.
    with gzip.open(FIX_PLAN_CACHE, "rb") as source:
        return source.read()


# ------------------------------------------------------------------------------
# 1. Directory Structure & File Verification
# ------------------------------------------------------------------------------


def test_demo_repo_directory_structure():
    """Verify demo-repo directory exists and contains all required base and branch files."""
    assert DEMO_REPO_DIR.exists() and DEMO_REPO_DIR.is_dir()

    # Base files
    for fname in ("alb.tf", "app.tf", "iam.tf", "network.tf", "providers.tf", "storage.tf", "plan.json"):
        assert (DEMO_REPO_DIR / fname).exists(), f"Missing {fname} in demo-repo root"

    assert (DEMO_REPO_DIR / "baselines").exists() and (DEMO_REPO_DIR / "baselines").is_dir()
    assert (DEMO_REPO_DIR / ".gitea" / "workflows" / "attack-paths.yml").exists()
    assert (DEMO_REPO_DIR / "README.md").exists()

    # Branch directories
    branches_dir = DEMO_REPO_DIR / "branches"
    assert branches_dir.exists()
    for branch in ("pr-42", "fix", "injection"):
        bdir = branches_dir / branch
        assert bdir.exists() and bdir.is_dir(), f"Missing branch directory: {branch}"
        assert (bdir / "plan.json").exists(), f"Missing plan.json in branch {branch}"


# ------------------------------------------------------------------------------
# 2. Byte-for-Byte Plan Equivalence
# ------------------------------------------------------------------------------


def test_four_branches_plans_byte_for_byte():
    """Verify the four branches reproduce fixture 006/019/base/fix plans byte for byte."""
    # 1. Base branch plan
    base_expected = (BASE_DIR / "plan.json").read_bytes()
    base_actual = (DEMO_REPO_DIR / "plan.json").read_bytes()
    assert base_actual == base_expected, "Base plan does not match demo/base/plan.json byte for byte"

    # 2. PR #42 branch plan
    pr42_expected = (FX_006_DIR / "plan.json").read_bytes()
    pr42_actual = (DEMO_REPO_DIR / "branches" / "pr-42" / "plan.json").read_bytes()
    assert pr42_actual == pr42_expected, "PR #42 plan does not match fixture 006 plan.json byte for byte"

    # 3. Fix branch plan
    fix_expected = canonical_fix_plan()
    fix_actual = (DEMO_REPO_DIR / "branches" / "fix" / "plan.json").read_bytes()
    assert fix_actual == fix_expected, "Fix plan does not match committed planner cache byte for byte"

    # 4. Injection branch plan
    inj_expected = (FX_019_DIR / "plan.json").read_bytes()
    inj_actual = (DEMO_REPO_DIR / "branches" / "injection" / "plan.json").read_bytes()
    assert inj_actual == inj_expected, "Injection plan does not match fixture 019 plan.json byte for byte"


def test_plan_generator_offline_reproduction():
    """Verify plan_fixture generates exact cached plans from each branch's Terraform sources."""
    # 1. Base sources -> Base plan
    with tempfile.TemporaryDirectory() as td:
        for f in DEMO_REPO_DIR.glob("*.tf"):
            shutil.copy(f, td)
        plan_fixture(td, Path(td) / "plan.json")
        assert (Path(td) / "plan.json").read_bytes() == (BASE_DIR / "plan.json").read_bytes()

    # 2. PR #42 sources -> 006 plan
    with tempfile.TemporaryDirectory() as td:
        for f in DEMO_REPO_DIR.glob("*.tf"):
            shutil.copy(f, td)
        for f in (DEMO_REPO_DIR / "branches" / "pr-42").glob("*.tf"):
            shutil.copy(f, td)
        plan_fixture(td, Path(td) / "plan.json")
        assert (Path(td) / "plan.json").read_bytes() == (FX_006_DIR / "plan.json").read_bytes()

    # 3. Fix sources -> Fix plan
    with tempfile.TemporaryDirectory() as td:
        for f in DEMO_REPO_DIR.glob("*.tf"):
            shutil.copy(f, td)
        for f in (DEMO_REPO_DIR / "branches" / "pr-42").glob("*.tf"):
            shutil.copy(f, td)
        for f in (DEMO_REPO_DIR / "branches" / "fix").glob("*.tf"):
            shutil.copy(f, td)
        plan_fixture(td, Path(td) / "plan.json")
        assert (Path(td) / "plan.json").read_bytes() == canonical_fix_plan()

    # 4. Injection sources -> 006 cached plan
    with tempfile.TemporaryDirectory() as td:
        for f in DEMO_REPO_DIR.glob("*.tf"):
            shutil.copy(f, td)
        for f in (DEMO_REPO_DIR / "branches" / "injection").glob("*.tf"):
            shutil.copy(f, td)
        plan_fixture(td, Path(td) / "plan.json")
        # Injection has comments only; offline cache resolves key to 006
        assert (Path(td) / "plan.json").read_bytes() == (FX_006_DIR / "plan.json").read_bytes()


# ------------------------------------------------------------------------------
# 3. Git Seed Script & Bundle Cloning
# ------------------------------------------------------------------------------


def test_seed_demo_repo_script():
    """Verify seed-demo-repo.sh initializes git repository with all 4 branches."""
    assert SEED_SCRIPT.exists() and os.access(SEED_SCRIPT, os.X_OK)

    # bash -n check
    res = subprocess.run(["bash", "-n", str(SEED_SCRIPT)], capture_output=True, text=True)
    assert res.returncode == 0, f"bash -n failed: {res.stderr}"

    with tempfile.TemporaryDirectory() as td:
        target_dir = Path(td) / "seeded-repo"
        res = subprocess.run(
            [str(SEED_SCRIPT), "--target", str(target_dir), "--quiet"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"seed-demo-repo.sh failed: {res.stderr}"

        # Verify branches
        branch_res = subprocess.run(
            ["git", "-C", str(target_dir), "branch"],
            capture_output=True,
            text=True,
        )
        branches = [b.strip().replace("* ", "") for b in branch_res.stdout.splitlines()]
        assert "main" in branches
        assert "pr-42" in branches
        assert "fix" in branches
        assert "injection" in branches

        # Verify commits and plans on each branch
        for b in ("main", "pr-42", "fix", "injection"):
            subprocess.run(["git", "-C", str(target_dir), "checkout", b, "-q"], check=True)
            plan_file = target_dir / "plan.json"
            assert plan_file.exists()
            assert plan_file.stat().st_size > 70000


def test_bundle_cloning():
    """Verify demo-repo.bundle exists and can be cloned into a working git repository."""
    assert BUNDLE_FILE.exists() and BUNDLE_FILE.stat().st_size > 0

    with tempfile.TemporaryDirectory() as td:
        clone_dir = Path(td) / "cloned"
        res = subprocess.run(
            ["git", "clone", str(BUNDLE_FILE), str(clone_dir), "-q"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"git clone bundle failed: {res.stderr}"

        # Check all branches exist in remote
        res = subprocess.run(
            ["git", "-C", str(clone_dir), "branch", "-a"],
            capture_output=True,
            text=True,
        )
        out = res.stdout
        assert "remotes/origin/main" in out
        assert "remotes/origin/pr-42" in out
        assert "remotes/origin/fix" in out
        assert "remotes/origin/injection" in out


def test_bundle_byte_stability(tmp_path: Path):
    """Verify demo-repo.bundle is byte-stable upon rebuild (Check C1, C3)."""
    assert BUNDLE_FILE.exists()
    committed_hash = hashlib.sha256(BUNDLE_FILE.read_bytes()).hexdigest()

    rebuilt_bundle = tmp_path / "rebuilt-demo-repo.bundle"
    target_repo = tmp_path / "target-repo"

    res = subprocess.run(
        [str(SEED_SCRIPT), "--target", str(target_repo), "--bundle", str(rebuilt_bundle), "--quiet"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"seed-demo-repo.sh failed: {res.stderr}"
    assert rebuilt_bundle.exists()

    rebuilt_hash = hashlib.sha256(rebuilt_bundle.read_bytes()).hexdigest()
    assert rebuilt_hash == committed_hash, f"Bundle hash mismatch: {rebuilt_hash} != {committed_hash}"


# ------------------------------------------------------------------------------
# 4. open-pr.sh Validation & Mock Gitea API Integration
# ------------------------------------------------------------------------------


def test_open_pr_script_syntax_and_dry_run():
    """Verify open-pr.sh syntax and dry-run output."""
    assert OPEN_PR_SCRIPT.exists() and os.access(OPEN_PR_SCRIPT, os.X_OK)

    # Syntax check
    res = subprocess.run(["bash", "-n", str(OPEN_PR_SCRIPT)], capture_output=True, text=True)
    assert res.returncode == 0, f"bash -n failed: {res.stderr}"

    # Dry run for PR #42
    res = subprocess.run([str(OPEN_PR_SCRIPT), "--dry-run"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "[DRY-RUN]" in res.stdout
    assert "Head:     pr-42" in res.stdout
    assert "Base:     main" in res.stdout
    assert "PR #42" in res.stdout

    # Dry run for fix branch
    res = subprocess.run(
        [str(OPEN_PR_SCRIPT), "--branch", "fix", "--dry-run"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Head:     fix" in res.stdout
    assert "remediation" in res.stdout.lower() or "scope" in res.stdout.lower()

    # Dry run for injection branch
    res = subprocess.run(
        [str(OPEN_PR_SCRIPT), "--branch", "injection", "--dry-run"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Head:     injection" in res.stdout
    assert "injection" in res.stdout.lower()


class MockPrHandler(BaseHTTPRequestHandler):
    """Mock HTTP server simulating Gitea PR API."""

    prs: list[dict[str, Any]] = []
    created: list[dict[str, Any]] = []

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if "/pulls" in self.path:
            self._send_json(200, MockPrHandler.prs)
        else:
            self._send_json(404, {"message": "Not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        parsed = json.loads(body) if body else {}

        MockPrHandler.created.append(parsed)

        new_pr = {
            "number": len(MockPrHandler.prs) + 1,
            "title": parsed.get("title", ""),
            "body": parsed.get("body", ""),
            "head": {"ref": parsed.get("head", "")},
            "base": {"ref": parsed.get("base", "")},
            "html_url": f"http://127.0.0.1/demo-org/infra-demo/pulls/{len(MockPrHandler.prs) + 1}",
        }
        MockPrHandler.prs.append(new_pr)
        self._send_json(201, new_pr)


@pytest.fixture
def mock_pr_server():
    MockPrHandler.prs = []
    MockPrHandler.created = []
    server = HTTPServer(("127.0.0.1", 0), MockPrHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_open_pr_create_and_idempotent(mock_pr_server):
    """Test open-pr.sh creating a PR against mock Gitea and handling subsequent calls idempotently."""
    # 1. Create PR
    res = subprocess.run(
        [
            str(OPEN_PR_SCRIPT),
            "--url", mock_pr_server,
            "--branch", "pr-42",
            "--token", "test-token",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"open-pr.sh failed: {res.stderr}"
    assert "Pull Request Created Successfully!" in res.stdout
    assert "#1" in res.stdout
    assert len(MockPrHandler.created) == 1
    assert MockPrHandler.created[0]["head"] == "pr-42"

    # 2. Re-run should detect existing PR and exit 0 without duplicate creation
    res2 = subprocess.run(
        [
            str(OPEN_PR_SCRIPT),
            "--url", mock_pr_server,
            "--branch", "pr-42",
            "--token", "test-token",
        ],
        capture_output=True,
        text=True,
    )
    assert res2.returncode == 0
    assert "Pull request already exists: #1" in res2.stdout
    # No second PR created
    assert len(MockPrHandler.created) == 1
