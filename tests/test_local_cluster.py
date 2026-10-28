"""Tests for Task W2.3a: Enhanced lab manifests for a local cluster (k3d / kind).

Acceptance criteria:
1. Manifests for namespaces `git`, `ci`, and `tapm` exist and parse as valid YAML;
2. Gitea deployment, service, configmap, secret, and PVC correctly configured in namespace `git`;
3. Analysis service (`tapm serve`) deployment, service, configmap, and secret correctly configured in namespace `tapm`;
4. Gitea act_runner deployment, configmap, secret, and RBAC correctly configured in namespace `ci`;
5. Cross-namespace DNS resolution and endpoints configured (gitea.git, tapm-service.tapm, host.k3d.internal);
6. Top-level kustomization.yaml includes all namespace resources;
7. Provider configs (k3d-config.yaml, kind-config.yaml) define port mappings for 3000, 2222, and 8080;
8. cluster.sh, bootstrap.sh, and open-pr.sh are executable, pass `bash -n`, and support `--help` and `--dry-run`;
9. Simulated bootstrap against mock Gitea API verifies token sync, repo/org creation, branch protection, and runner registration.
"""

from __future__ import annotations

import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from pathlib import Path
from typing import Any

import pytest
import yaml

from tapm.util import PROJECT_ROOT

CLUSTER_DIR = PROJECT_ROOT / "examples" / "local-cluster"
MANIFESTS_DIR = CLUSTER_DIR / "manifests"
CLUSTER_SCRIPT = CLUSTER_DIR / "cluster.sh"
BOOTSTRAP_SCRIPT = CLUSTER_DIR / "bootstrap.sh"
OPEN_PR_SCRIPT = CLUSTER_DIR / "open-pr.sh"
WORKFLOW_PATH = CLUSTER_DIR / ".gitea" / "workflows" / "attack-paths.yml"
K3D_CONFIG = CLUSTER_DIR / "k3d-config.yaml"
KIND_CONFIG = CLUSTER_DIR / "kind-config.yaml"
ENV_EXAMPLE = CLUSTER_DIR / ".env.example"


# ------------------------------------------------------------------------------
# 1. Namespaces Validation
# ------------------------------------------------------------------------------


def test_namespaces_manifest():
    """Verify 00-namespaces.yaml defines git, ci, and tapm namespaces."""
    ns_file = MANIFESTS_DIR / "00-namespaces.yaml"
    assert ns_file.exists(), f"Namespaces file missing: {ns_file}"

    with open(ns_file, "r", encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    ns_names = {doc["metadata"]["name"] for doc in docs if doc and doc.get("kind") == "Namespace"}
    assert "git" in ns_names, "Namespace 'git' must be defined"
    assert "ci" in ns_names, "Namespace 'ci' must be defined"
    assert "tapm" in ns_names, "Namespace 'tapm' must be defined"


# ------------------------------------------------------------------------------
# 2. Git Namespace Manifests Validation
# ------------------------------------------------------------------------------


def test_git_manifests():
    """Verify manifests in 01-git/ for Gitea server."""
    git_dir = MANIFESTS_DIR / "01-git"
    assert git_dir.exists(), f"01-git directory missing: {git_dir}"

    # 1. ConfigMap
    cm_path = git_dir / "configmap.yaml"
    assert cm_path.exists()
    cm = yaml.safe_load(cm_path.read_text(encoding="utf-8"))
    assert cm["kind"] == "ConfigMap"
    assert cm["metadata"]["namespace"] == "git"
    assert "app.ini" in cm["data"]
    app_ini = cm["data"]["app.ini"]
    assert "INSTALL_LOCK = true" in app_ini
    assert "ENABLED = true" in app_ini

    # 2. Secret
    sec_path = git_dir / "secret.yaml"
    assert sec_path.exists()
    sec = yaml.safe_load(sec_path.read_text(encoding="utf-8"))
    assert sec["kind"] == "Secret"
    assert sec["metadata"]["namespace"] == "git"
    assert "admin-username" in sec.get("stringData", {})

    # 3. PVC
    pvc_path = git_dir / "pvc.yaml"
    assert pvc_path.exists()
    pvc = yaml.safe_load(pvc_path.read_text(encoding="utf-8"))
    assert pvc["kind"] == "PersistentVolumeClaim"
    assert pvc["metadata"]["namespace"] == "git"

    # 4. Deployment
    dep_path = git_dir / "deployment.yaml"
    assert dep_path.exists()
    dep = yaml.safe_load(dep_path.read_text(encoding="utf-8"))
    assert dep["kind"] == "Deployment"
    assert dep["metadata"]["namespace"] == "git"
    container = dep["spec"]["template"]["spec"]["containers"][0]
    assert "gitea" in container["image"]
    ports = [p["containerPort"] for p in container.get("ports", [])]
    assert 3000 in ports
    assert "livenessProbe" in container
    assert "readinessProbe" in container

    # 5. Service
    svc_path = git_dir / "service.yaml"
    assert svc_path.exists()
    svc = yaml.safe_load(svc_path.read_text(encoding="utf-8"))
    assert svc["kind"] == "Service"
    assert svc["metadata"]["namespace"] == "git"
    svc_ports = {p["name"]: p["port"] for p in svc["spec"]["ports"]}
    assert svc_ports.get("http") == 3000


# ------------------------------------------------------------------------------
# 3. TAPM Namespace Manifests Validation
# ------------------------------------------------------------------------------


def test_tapm_manifests():
    """Verify manifests in 02-tapm/ for analysis service."""
    tapm_dir = MANIFESTS_DIR / "02-tapm"
    assert tapm_dir.exists(), f"02-tapm directory missing: {tapm_dir}"

    # 1. ConfigMap
    cm_path = tapm_dir / "configmap.yaml"
    assert cm_path.exists()
    cm = yaml.safe_load(cm_path.read_text(encoding="utf-8"))
    assert cm["kind"] == "ConfigMap"
    assert cm["metadata"]["namespace"] == "tapm"
    assert "gitea.git.svc.cluster.local" in cm["data"]["GITEA_BASE_URL"]
    assert "host.k3d.internal" in cm["data"]["OLLAMA_HOST"]

    # 2. Secret
    sec_path = tapm_dir / "secret.yaml"
    assert sec_path.exists()
    sec = yaml.safe_load(sec_path.read_text(encoding="utf-8"))
    assert sec["kind"] == "Secret"
    assert sec["metadata"]["namespace"] == "tapm"
    assert "tapm-server-token" in sec.get("stringData", {})

    # 3. Deployment
    dep_path = tapm_dir / "deployment.yaml"
    assert dep_path.exists()
    dep = yaml.safe_load(dep_path.read_text(encoding="utf-8"))
    assert dep["kind"] == "Deployment"
    assert dep["metadata"]["namespace"] == "tapm"
    container = dep["spec"]["template"]["spec"]["containers"][0]
    assert "terraform-attack-paths-pytm" in container["image"]
    ports = [p["containerPort"] for p in container.get("ports", [])]
    assert 8080 in ports
    assert "livenessProbe" in container
    assert "readinessProbe" in container
    assert "/health" in container["readinessProbe"]["httpGet"]["path"]

    # 4. Service
    svc_path = tapm_dir / "service.yaml"
    assert svc_path.exists()
    svc = yaml.safe_load(svc_path.read_text(encoding="utf-8"))
    assert svc["kind"] == "Service"
    assert svc["metadata"]["namespace"] == "tapm"
    svc_ports = {p["name"]: p["port"] for p in svc["spec"]["ports"]}
    assert svc_ports.get("http") == 8080


# ------------------------------------------------------------------------------
# 4. CI Namespace Manifests Validation
# ------------------------------------------------------------------------------


def test_ci_manifests():
    """Verify manifests in 03-ci/ for act_runner."""
    ci_dir = MANIFESTS_DIR / "03-ci"
    assert ci_dir.exists(), f"03-ci directory missing: {ci_dir}"

    # 1. ConfigMap
    cm_path = ci_dir / "configmap.yaml"
    assert cm_path.exists()
    cm = yaml.safe_load(cm_path.read_text(encoding="utf-8"))
    assert cm["kind"] == "ConfigMap"
    assert cm["metadata"]["namespace"] == "ci"
    assert "gitea.git.svc.cluster.local" in cm["data"]["GITEA_INSTANCE_URL"]
    assert "tapm" in cm["data"]["GITEA_RUNNER_LABELS"]

    # 2. Secret
    sec_path = ci_dir / "secret.yaml"
    assert sec_path.exists()
    sec = yaml.safe_load(sec_path.read_text(encoding="utf-8"))
    assert sec["kind"] == "Secret"
    assert sec["metadata"]["namespace"] == "ci"

    # 3. RBAC
    rbac_path = ci_dir / "rbac.yaml"
    assert rbac_path.exists()
    docs = list(yaml.safe_load_all(rbac_path.read_text(encoding="utf-8")))
    kinds = {d["kind"] for d in docs if d}
    assert "ServiceAccount" in kinds
    assert "Role" in kinds
    assert "RoleBinding" in kinds

    # 4. Deployment
    dep_path = ci_dir / "deployment.yaml"
    assert dep_path.exists()
    dep = yaml.safe_load(dep_path.read_text(encoding="utf-8"))
    assert dep["kind"] == "Deployment"
    assert dep["metadata"]["namespace"] == "ci"
    container = dep["spec"]["template"]["spec"]["containers"][0]
    assert "act_runner" in container["image"]

    # Volume mounts for docker socket
    vol_names = {v["name"] for v in dep["spec"]["template"]["spec"]["volumes"]}
    assert "docker-sock" in vol_names


# ------------------------------------------------------------------------------
# 5. Kustomization & Cluster Config Validation
# ------------------------------------------------------------------------------


def test_kustomization_yaml():
    """Verify kustomization.yaml exists and references all manifest components."""
    kust_file = MANIFESTS_DIR / "kustomization.yaml"
    assert kust_file.exists()
    data = yaml.safe_load(kust_file.read_text(encoding="utf-8"))
    assert "resources" in data
    resources = data["resources"]
    assert "00-namespaces.yaml" in resources
    assert any("01-git" in r for r in resources)
    assert any("02-tapm" in r for r in resources)
    assert any("03-ci" in r for r in resources)


def test_cluster_provider_configs():
    """Verify k3d and kind configuration files define port forwards."""
    assert K3D_CONFIG.exists()
    k3d = yaml.safe_load(K3D_CONFIG.read_text(encoding="utf-8"))
    k3d_ports = [p["port"] for p in k3d.get("ports", [])]
    assert any("3000:30000" in p for p in k3d_ports)
    assert any("8080:30080" in p for p in k3d_ports)

    assert KIND_CONFIG.exists()
    kind = yaml.safe_load(KIND_CONFIG.read_text(encoding="utf-8"))
    nodes = kind.get("nodes", [])
    mappings = nodes[0].get("extraPortMappings", [])
    host_ports = [m.get("hostPort") for m in mappings]
    assert 3000 in host_ports
    assert 8080 in host_ports


def test_workflow_yaml():
    """Verify cluster .gitea/workflows/attack-paths.yml is valid."""
    assert WORKFLOW_PATH.exists()
    wf = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert "attack-paths" in wf.get("jobs", {})
    assert "tapm-service.tapm.svc.cluster.local:8080" in WORKFLOW_PATH.read_text(encoding="utf-8")


# ------------------------------------------------------------------------------
# 6. Scripts Syntax and Options Validation
# ------------------------------------------------------------------------------


def test_scripts_executable_and_syntax():
    """Verify cluster.sh, bootstrap.sh, and open-pr.sh pass bash -n and are executable."""
    for script in (CLUSTER_SCRIPT, BOOTSTRAP_SCRIPT, OPEN_PR_SCRIPT):
        assert script.exists(), f"Missing script: {script}"
        assert os.access(script, os.X_OK), f"Not executable: {script}"
        res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert res.returncode == 0, f"Syntax error in {script}: {res.stderr}"


def test_scripts_help():
    """Verify scripts support --help with usage instructions."""
    for script in (CLUSTER_SCRIPT, BOOTSTRAP_SCRIPT):
        res = subprocess.run([str(script), "--help"], capture_output=True, text=True)
        assert res.returncode == 0
        assert "Usage:" in res.stdout


def test_cluster_script_dry_run():
    """Verify cluster.sh dry-run commands execute without errors."""
    for cmd in ("up", "down", "status"):
        res = subprocess.run(
            [str(CLUSTER_SCRIPT), cmd, "--dry-run"],
            cwd=str(CLUSTER_DIR),
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"cluster.sh {cmd} --dry-run failed: {res.stderr}"
        assert "[DRY-RUN]" in res.stdout


def test_bootstrap_dry_run_generates_env():
    """Verify bootstrap.sh --dry-run generates .env with cluster endpoints."""
    test_env = CLUSTER_DIR / ".env.test_cluster_dry_run"
    try:
        env = os.environ.copy()
        env["ENV_FILE"] = str(test_env)
        res = subprocess.run(
            [str(BOOTSTRAP_SCRIPT), "--dry-run"],
            cwd=str(CLUSTER_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"bootstrap --dry-run failed: {res.stderr}"
        assert "[DRY-RUN]" in res.stdout
        assert test_env.exists()

        content = test_env.read_text(encoding="utf-8")
        assert "GITEA_URL=http://localhost:3000" in content
        assert "TAPM_SERVER_URL=http://tapm-service.tapm.svc.cluster.local:8080" in content
        assert "GITEA_TOKEN=" in content
        assert "GITEA_RUNNER_TOKEN=" in content
    finally:
        if test_env.exists():
            test_env.unlink()


# ------------------------------------------------------------------------------
# 7. Mock Gitea API Integration Test
# ------------------------------------------------------------------------------


class MockClusterGiteaHandler(BaseHTTPRequestHandler):
    """Mock HTTP handler simulating Gitea responses during cluster bootstrap."""

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
        MockClusterGiteaHandler.calls.append({"method": "GET", "path": self.path})
        if self.path == "/api/v1/version":
            self._send_json(200, {"version": "1.22.0"})
        elif self.path == "/api/v1/user":
            self._send_json(200, {"id": 1, "username": "tapm-admin"})
        elif "/users/tapm-admin/tokens" in self.path:
            self._send_json(200, [])
        elif "/actions/runners/registration-token" in self.path:
            self._send_json(200, {"token": "mock-cluster-runner-token-999"})
        else:
            self._send_json(404, {"message": "Not found"})

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        MockClusterGiteaHandler.calls.append({"method": "POST", "path": self.path, "body": body})

        if "/users/tapm-admin/tokens" in self.path or "/tokens" in self.path:
            self._send_json(201, {"id": 1, "name": "tapm-service", "sha1": "cluster-sha1-token-12345"})
        elif self.path == "/api/v1/orgs":
            self._send_json(201, {"id": 1, "username": "demo-org"})
        elif "/org/demo-org/repos" in self.path or "/repos" in self.path:
            self._send_json(201, {"id": 1, "name": "infra-demo"})
        elif "/branch_protections" in self.path:
            self._send_json(201, {"rule_name": "main"})
        elif "/contents/" in self.path:
            self._send_json(201, {"content": {"name": "attack-paths.yml"}})
        elif "/actions/runners/registration-token" in self.path or "/runners/registration-token" in self.path:
            self._send_json(201, {"token": "mock-cluster-runner-token-999"})
        else:
            self._send_json(200, {})


def test_bootstrap_against_mock_gitea():
    """Verify cluster bootstrap against live mock Gitea server."""
    MockClusterGiteaHandler.calls.clear()
    server = HTTPServer(("127.0.0.1", 0), MockClusterGiteaHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    test_env = CLUSTER_DIR / ".env.test_mock_server"
    try:
        env = os.environ.copy()
        env["ENV_FILE"] = str(test_env)
        res = subprocess.run(
            [
                str(BOOTSTRAP_SCRIPT),
                "--url", f"http://127.0.0.1:{port}",
                "--skip-wait",
                "--no-k8s",
            ],
            cwd=str(CLUSTER_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"bootstrap against mock failed: {res.stderr}\nOutput: {res.stdout}"

        # Verify calls occurred
        paths = [c["path"] for c in MockClusterGiteaHandler.calls]
        assert any("/api/v1/user" in p for p in paths)
        assert any("/tokens" in p for p in paths)
        assert any("/orgs" in p for p in paths)
        assert any("/branch_protections" in p for p in paths)
        assert any("/actions/runners/registration-token" in p for p in paths)

        # Verify saved tokens in .env
        assert test_env.exists()
        content = test_env.read_text(encoding="utf-8")
        assert "cluster-sha1-token-12345" in content
        assert "mock-cluster-runner-token-999" in content
    finally:
        server.shutdown()
        server.server_close()
        if test_env.exists():
            test_env.unlink()
