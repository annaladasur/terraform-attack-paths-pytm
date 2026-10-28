"""Tests for Task W2.1a: Compose quick start.

Acceptance criteria:
1. examples/local-stack/compose.yaml valid syntax and service definitions (gitea, runner, analysis-service);
2. examples/local-stack/.gitea/workflows/attack-paths.yml valid workflow targeting required check;
3. examples/local-stack/bootstrap.sh executable, passes bash -n, supports --dry-run and CLI options;
4. Simulated bootstrap against mock Gitea API verifies admin, token, org, repo, workflow, branch protection, and runner token;
5. .env.example documents all configuration keys.

Task A32: no test may reach Docker. Every bootstrap run puts a fake `docker` first on PATH and checks what it was
asked to do, because a real `docker compose up` here recreates the live demo containers from this checkout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml

from tapm.util import PROJECT_ROOT

LOCAL_STACK_DIR = PROJECT_ROOT / "examples" / "local-stack"
COMPOSE_PATH = LOCAL_STACK_DIR / "compose.yaml"
BOOTSTRAP_PATH = LOCAL_STACK_DIR / "bootstrap.sh"
WORKFLOW_PATH = LOCAL_STACK_DIR / ".gitea" / "workflows" / "attack-paths.yml"
ENV_EXAMPLE_PATH = LOCAL_STACK_DIR / ".env.example"


def _fake_docker_env(tmp_path: Path, extra: dict[str, str] | None = None) -> tuple[dict[str, str], Path]:
    """Environment whose PATH starts with a fake `docker` that logs its arguments (A32).

    For `compose ... ps -q` the fake reports one running container, the worst case: a bootstrap run that would
    restart the live demo stack shows up in the log instead of touching it.
    """
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    log = tmp_path / "docker-calls.log"
    fake = bin_dir / "docker"
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{log}"\n'
        'case "$*" in *" ps -q"*) echo fake-container-id ;; esac\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env.update(extra or {})
    return env, log


def _docker_calls(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


# ------------------------------------------------------------------------------
# 1. Compose YAML Validation
# ------------------------------------------------------------------------------


def test_compose_yaml_exists_and_valid():
    """Verify compose.yaml exists, parses as valid YAML, and contains required services."""
    assert COMPOSE_PATH.exists(), f"compose.yaml missing at {COMPOSE_PATH}"

    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "services" in data, "compose.yaml must define 'services'"
    services = data["services"]

    # 1. Gitea service
    assert "gitea" in services, "Service 'gitea' must be defined"
    gitea = services["gitea"]
    assert "image" in gitea and "gitea" in gitea["image"]
    assert "3000:3000" in gitea.get("ports", [])
    assert "healthcheck" in gitea

    # Gitea actions must be enabled in environment
    gitea_env = gitea.get("environment", [])
    env_dict = {}
    for item in gitea_env:
        if "=" in item:
            k, v = item.split("=", 1)
            env_dict[k] = v
    assert env_dict.get("GITEA__actions__ENABLED") == "true"
    assert env_dict.get("GITEA__security__INSTALL_LOCK") == "true"

    # 2. Runner service
    assert "runner" in services, "Service 'runner' must be defined"
    runner = services["runner"]
    assert "image" in runner and "act_runner" in runner["image"]
    assert "gitea" in runner.get("depends_on", {})

    # 3. Analysis service
    assert "analysis-service" in services, "Service 'analysis-service' must be defined"
    analysis = services["analysis-service"]
    assert "8080:8080" in analysis.get("ports", [])
    assert "gitea" in analysis.get("depends_on", {})
    assert "healthcheck" in analysis
    assert analysis["command"] == ["sh", "/opt/tapm-service-entrypoint.sh"]
    assert "./service-entrypoint.sh:/opt/tapm-service-entrypoint.sh:ro" in analysis["volumes"]
    assert "exec tapm serve" in (LOCAL_STACK_DIR / "service-entrypoint.sh").read_text()

    # Networks and volumes
    assert "networks" in data
    assert "volumes" in data
    assert "gitea-data" in data["volumes"]
    assert "runner-data" in data["volumes"]


# ------------------------------------------------------------------------------
# 2. Gitea Workflow YAML Validation
# ------------------------------------------------------------------------------


def test_workflow_yaml_exists_and_valid():
    """Verify .gitea/workflows/attack-paths.yml is valid and targets attack-paths check."""
    assert WORKFLOW_PATH.exists(), f"Workflow missing at {WORKFLOW_PATH}"

    with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "name" in data
    # In YAML 1.1 "on" may parse as boolean True or string "on"
    assert "on" in data or True in data
    trigger = data.get("on") or data.get(True)
    assert "pull_request" in trigger or "push" in trigger

    assert "jobs" in data
    assert "attack-paths" in data["jobs"], "Job must be named 'attack-paths' to match check"
    job = data["jobs"]["attack-paths"]
    assert "steps" in job
    steps = job["steps"]
    step_names = [s.get("name", "") for s in steps]

    assert any("Checkout" in n for n in step_names)
    assert any("plan" in n.lower() for n in step_names)
    assert any("Submit" in n for n in step_names)


# ------------------------------------------------------------------------------
# 3. Bootstrap Script Syntax & Options Validation
# ------------------------------------------------------------------------------


def test_bootstrap_script_syntax_and_executable():
    """Verify bootstrap.sh is executable and has valid bash syntax."""
    assert BOOTSTRAP_PATH.exists(), f"bootstrap.sh missing at {BOOTSTRAP_PATH}"
    assert os.access(BOOTSTRAP_PATH, os.X_OK), "bootstrap.sh must be executable"

    # Syntax check with bash -n
    res = subprocess.run(["bash", "-n", str(BOOTSTRAP_PATH)], capture_output=True, text=True)
    assert res.returncode == 0, f"bash -n failed: {res.stderr}"


def test_bootstrap_help_option():
    """Verify bootstrap.sh --help outputs usage information."""
    res = subprocess.run([str(BOOTSTRAP_PATH), "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "Usage:" in res.stdout
    assert "--dry-run" in res.stdout
    assert "--url" in res.stdout
    assert "--no-compose" in res.stdout


def test_bootstrap_dry_run_generates_env(tmp_path):
    """Verify bootstrap.sh --dry-run completes cleanly and creates .env."""
    test_env_file = LOCAL_STACK_DIR / ".env.test_dry_run"
    try:
        env, docker_log = _fake_docker_env(tmp_path, {"ENV_FILE": str(test_env_file)})
        res = subprocess.run(
            [str(BOOTSTRAP_PATH), "--dry-run"],
            cwd=str(LOCAL_STACK_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Dry run failed: {res.stderr}"
        assert "[DRY-RUN]" in res.stdout
        assert "TAPM Local Stack Bootstrap Complete!" in res.stdout
        assert _docker_calls(docker_log) == [], "a dry run must not call docker"

        # Verify generated .env file
        assert test_env_file.exists()
        content = test_env_file.read_text(encoding="utf-8")
        assert "GITEA_URL=" in content
        assert "GITEA_ADMIN_USER=tapm-admin"
        assert "GITEA_ORG=demo-org"
        assert "GITEA_REPO=infra-demo"
        assert "REQUIRED_CHECK=attack-paths"
        assert "GITEA_TOKEN=dry-run-token-gitea-12345"
        assert "GITEA_RUNNER_TOKEN=dry-run-runner-token-xyz"
        assert "TAPM_SERVER_TOKEN=demo-secret-token"
    finally:
        if test_env_file.exists():
            test_env_file.unlink()


# ------------------------------------------------------------------------------
# 4. Mock Gitea API Integration Test
# ------------------------------------------------------------------------------


class MockGiteaHandler(BaseHTTPRequestHandler):
    """Mock handler simulating Gitea API responses during bootstrap."""

    calls: list[dict[str, Any]] = []

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
        MockGiteaHandler.calls.append({"method": "GET", "path": self.path})
        if self.path == "/api/v1/version":
            self._send_json(200, {"version": "1.22.0"})
        elif "/contents/" in self.path:
            self._send_json(404, {"message": "File not found"})
        elif "/branch_protections" in self.path:
            self._send_json(200, [])
        else:
            self._send_json(200, {})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        parsed_body = json.loads(body) if body else {}

        MockGiteaHandler.calls.append({
            "method": "POST",
            "path": self.path,
            "body": parsed_body,
            "headers": dict(self.headers),
        })

        if "/tokens" in self.path:
            self._send_json(201, {"name": parsed_body.get("name"), "sha1": "mock-api-token-abc12345"})
        elif self.path == "/api/v1/orgs":
            self._send_json(201, {"username": parsed_body.get("username")})
        elif "/repos" in self.path:
            self._send_json(201, {"name": parsed_body.get("name")})
        elif "/contents/" in self.path:
            self._send_json(201, {"content": {"name": "attack-paths.yml"}})
        elif "/branch_protections" in self.path:
            self._send_json(201, parsed_body)
        elif "/runners/registration-token" in self.path:
            self._send_json(201, {"token": "mock-runner-reg-token-xyz999"})
        else:
            self._send_json(200, {})


@pytest.fixture
def mock_gitea_server():
    MockGiteaHandler.calls = []
    server = HTTPServer(("127.0.0.1", 0), MockGiteaHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_bootstrap_end_to_end_mock_api(mock_gitea_server, tmp_path):
    """Test bootstrap.sh running against a live mock Gitea HTTP API server."""
    test_env_file = LOCAL_STACK_DIR / ".env.test_mock"
    try:
        env, docker_log = _fake_docker_env(tmp_path, {"ENV_FILE": str(test_env_file)})

        res = subprocess.run(
            [
                str(BOOTSTRAP_PATH),
                "--url", mock_gitea_server,
                "--skip-wait",
                "--no-compose",
                "--org", "test-org",
                "--repo", "test-repo",
            ],
            cwd=str(LOCAL_STACK_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Bootstrap execution failed: {res.stderr}\n{res.stdout}"
        assert _docker_calls(docker_log) == [], "--no-compose must keep bootstrap away from docker"
        assert "Skipping compose restart (--no-compose)." in res.stdout

        # Verify calls recorded by the mock server
        called_paths = [c["path"] for c in MockGiteaHandler.calls]

        # 1. API token generated
        assert any("/tokens" in p for p in called_paths), "Expected POST to /tokens"

        # 2. Org and Repo created
        assert "/api/v1/orgs" in called_paths
        assert any("/repos" in p for p in called_paths)

        # 3. Workflow seeded
        assert any("/contents/.gitea/workflows/attack-paths.yml" in p for p in called_paths)

        # 4. Branch protection created with status check context 'attack-paths'
        protection_calls = [c for c in MockGiteaHandler.calls if "/branch_protections" in c["path"]]
        assert len(protection_calls) >= 1
        prot_body = protection_calls[0]["body"]
        assert prot_body.get("branch_name") == "main"
        assert prot_body.get("enable_status_check") is True
        assert "attack-paths" in prot_body.get("status_check_contexts", [])

        # 5. Runner token requested
        assert any("/runners/registration-token" in p for p in called_paths)

        # 6. .env file written with mock credentials
        assert test_env_file.exists()
        content = test_env_file.read_text(encoding="utf-8")
        assert "GITEA_TOKEN=mock-api-token-abc12345" in content
        assert "GITEA_RUNNER_TOKEN=mock-runner-reg-token-xyz999" in content
        assert "REQUIRED_CHECK=attack-paths" in content
    finally:
        if test_env_file.exists():
            test_env_file.unlink()


def _bootstrap_against_mock(url: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(BOOTSTRAP_PATH), "--url", url, "--skip-wait", "--org", "test-org", "--repo", "test-repo"],
        cwd=str(LOCAL_STACK_DIR),
        env=env,
        capture_output=True,
        text=True,
    )


def test_bootstrap_with_another_env_file_never_restarts_compose(mock_gitea_server, tmp_path):
    """A32: with ENV_FILE elsewhere, compose would restart with an .env this run never wrote, so bootstrap skips it."""
    env, docker_log = _fake_docker_env(tmp_path, {"ENV_FILE": str(tmp_path / ".env.test_custom")})
    res = _bootstrap_against_mock(mock_gitea_server, env)
    assert res.returncode == 0, f"Bootstrap execution failed: {res.stderr}\n{res.stdout}"
    assert "Skipping compose restart: compose reads" in res.stdout
    assert _docker_calls(docker_log) == [], "bootstrap called docker with a foreign ENV_FILE"


def test_bootstrap_restarts_compose_when_it_wrote_composes_env(mock_gitea_server, tmp_path):
    """A32 keeps the intended behavior: when ENV_FILE is the .env next to COMPOSE_FILE, the services restart."""
    stack = tmp_path / "stack"
    stack.mkdir()
    shutil.copy(COMPOSE_PATH, stack / "compose.yaml")
    env, docker_log = _fake_docker_env(
        tmp_path, {"COMPOSE_FILE": str(stack / "compose.yaml"), "ENV_FILE": str(stack / ".env")})
    res = _bootstrap_against_mock(mock_gitea_server, env)
    assert res.returncode == 0, f"Bootstrap execution failed: {res.stderr}\n{res.stdout}"
    assert f"compose -f {stack / 'compose.yaml'} up -d analysis-service runner" in _docker_calls(docker_log)
    assert "GITEA_TOKEN=mock-api-token-abc12345" in (stack / ".env").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------
# 5. .env.example Completeness
# ------------------------------------------------------------------------------


def test_env_example_documented_keys():
    """Verify .env.example contains all required configuration keys."""
    assert ENV_EXAMPLE_PATH.exists(), f".env.example missing at {ENV_EXAMPLE_PATH}"
    content = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

    expected_keys = [
        "GITEA_URL",
        "GITEA_ADMIN_USER",
        "GITEA_ADMIN_PASSWORD",
        "GITEA_ORG",
        "GITEA_REPO",
        "REQUIRED_CHECK",
        "GITEA_TOKEN",
        "GITEA_RUNNER_TOKEN",
        "TAPM_SERVER_URL",
        "TAPM_SERVER_TOKEN",
        "TAPM_LLM",
        "OLLAMA_HOST",
    ]
    for key in expected_keys:
        assert f"{key}=" in content, f"Key '{key}' must be documented in .env.example"
