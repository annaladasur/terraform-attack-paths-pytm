#!/usr/bin/env bash
# ==============================================================================
# TAPM Local Cluster Management Script (Task W2.3a)
#
# Manages local Kubernetes clusters (k3d or kind) for the enhanced lab:
# - Provider detection (k3d, kind)
# - Cluster creation with port mappings (3000, 2222, 8080)
# - Container image loading into cluster nodes
# - Manifests deployment across namespaces: git, ci, tapm
# - Automated bootstrap of Gitea, tokens, demo repo, and runner
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/manifests"
CLUSTER_NAME="${CLUSTER_NAME:-tapm-lab}"
PROVIDER="${PROVIDER:-}"
DRY_RUN=false
SKIP_BOOTSTRAP=false

# Auto-detect provider if not explicitly given
detect_provider() {
  if [ -n "$PROVIDER" ]; then
    return 0
  fi
  if command -v k3d >/dev/null 2>&1; then
    PROVIDER="k3d"
  elif command -v kind >/dev/null 2>&1; then
    PROVIDER="kind"
  else
    PROVIDER="kind" # fallback default
  fi
}

usage() {
  cat << EOF
Usage: $(basename "$0") <command> [options]

Commands:
  up          Create local cluster, apply manifests, and run bootstrap
  down        Tear down local cluster and purge resources
  status      Display cluster nodes, namespaces, and pod health
  bootstrap   Run bootstrap configuration against running cluster
  pr          Open demo pull request (PR #42) on cluster Gitea

Options:
  --provider P     Cluster provider ('k3d' or 'kind'; auto-detected)
  --name NAME      Cluster name (default: tapm-lab)
  --skip-bootstrap Skip automated bootstrap after cluster up
  --dry-run        Print actions without executing
  -h, --help       Show this help message
EOF
  exit 0
}

COMMAND="${1:-}"
if [ -z "$COMMAND" ] || [ "$COMMAND" = "-h" ] || [ "$COMMAND" = "--help" ]; then
  usage
fi
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider)
      PROVIDER="$2"
      shift 2
      ;;
    --name)
      CLUSTER_NAME="$2"
      shift 2
      ;;
    --skip-bootstrap)
      SKIP_BOOTSTRAP=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

detect_provider

echo "============================================================"
echo " TAPM Cluster Manager: ${COMMAND}"
echo " Provider:  ${PROVIDER}"
echo " Cluster:   ${CLUSTER_NAME}"
echo " Dry Run:   ${DRY_RUN}"
echo "============================================================"

cmd_up() {
  echo "1. Checking provider prerequisites (${PROVIDER})..."
  if [ "$DRY_RUN" = false ]; then
    if ! command -v "${PROVIDER}" >/dev/null 2>&1; then
      echo "Error: Provider binary '${PROVIDER}' not found in PATH." >&2
      exit 1
    fi
  fi

  echo "2. Creating local cluster '${CLUSTER_NAME}' using ${PROVIDER}..."
  if [ "$PROVIDER" = "k3d" ]; then
    K3D_CONFIG="${SCRIPT_DIR}/k3d-config.yaml"
    if [ "$DRY_RUN" = false ]; then
      if k3d cluster list 2>/dev/null | grep -q "^${CLUSTER_NAME} "; then
        echo "Cluster '${CLUSTER_NAME}' already exists."
      else
        k3d cluster create --config "${K3D_CONFIG}"
      fi
    else
      echo "[DRY-RUN] k3d cluster create --config ${K3D_CONFIG}"
    fi
  else
    KIND_CONFIG="${SCRIPT_DIR}/kind-config.yaml"
    if [ "$DRY_RUN" = false ]; then
      if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        echo "Cluster '${CLUSTER_NAME}' already exists."
      else
        kind create cluster --config "${KIND_CONFIG}" --name "${CLUSTER_NAME}"
      fi
    else
      echo "[DRY-RUN] kind create cluster --config ${KIND_CONFIG} --name ${CLUSTER_NAME}"
    fi
  fi

  echo "3. Pre-loading container images into cluster..."
  if [ "$DRY_RUN" = false ]; then
    if docker image inspect terraform-attack-paths-pytm:latest >/dev/null 2>&1; then
      echo "Loading terraform-attack-paths-pytm:latest into cluster..."
      if [ "$PROVIDER" = "k3d" ]; then
        k3d image import terraform-attack-paths-pytm:latest -c "${CLUSTER_NAME}" || true
      else
        kind load docker-image terraform-attack-paths-pytm:latest --name "${CLUSTER_NAME}" || true
      fi
    fi
  else
    echo "[DRY-RUN] Load image terraform-attack-paths-pytm:latest into ${CLUSTER_NAME}"
  fi

  echo "4. Applying Kubernetes manifests (namespaces: git, ci, tapm)..."
  if [ "$DRY_RUN" = false ]; then
    kubectl apply -k "${MANIFESTS_DIR}"
    echo "Waiting for deployments rollout..."
    kubectl rollout status deployment/gitea -n git --timeout=120s || true
    kubectl rollout status deployment/tapm-service -n tapm --timeout=120s || true
  else
    echo "[DRY-RUN] kubectl apply -k ${MANIFESTS_DIR}"
    echo "[DRY-RUN] kubectl rollout status deployment/gitea -n git"
    echo "[DRY-RUN] kubectl rollout status deployment/tapm-service -n tapm"
  fi

  if [ "$SKIP_BOOTSTRAP" = false ]; then
    echo "5. Running cluster bootstrap..."
    if [ "$DRY_RUN" = false ]; then
      bash "${SCRIPT_DIR}/bootstrap.sh"
    else
      echo "[DRY-RUN] bash ${SCRIPT_DIR}/bootstrap.sh --dry-run"
    fi
  fi

  echo "✓ Cluster up complete!"
}

cmd_down() {
  echo "Deleting cluster '${CLUSTER_NAME}' (${PROVIDER})..."
  if [ "$DRY_RUN" = false ]; then
    if [ "$PROVIDER" = "k3d" ]; then
      k3d cluster delete "${CLUSTER_NAME}" 2>/dev/null || true
    else
      kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    fi
    echo "✓ Cluster '${CLUSTER_NAME}' removed."
  else
    echo "[DRY-RUN] ${PROVIDER} delete cluster ${CLUSTER_NAME}"
  fi
}

cmd_status() {
  echo "Checking status of cluster '${CLUSTER_NAME}'..."
  if [ "$DRY_RUN" = false ]; then
    if command -v kubectl >/dev/null 2>&1; then
      echo "--- Nodes ---"
      kubectl get nodes -o wide || true
      echo ""
      echo "--- Namespaces: git, ci, tapm ---"
      kubectl get pods,svc -n git || true
      kubectl get pods,svc -n ci || true
      kubectl get pods,svc -n tapm || true
      echo ""
      echo "--- Health Checks ---"
      curl -sf http://localhost:3000/api/v1/version && echo " gitea: healthy" || echo " gitea: unreachable (port 3000)"
      curl -sf http://localhost:8080/health && echo " tapm-service: healthy" || echo " tapm-service: unreachable (port 8080)"
    fi
  else
    echo "[DRY-RUN] kubectl get nodes"
    echo "[DRY-RUN] kubectl get pods,svc -n git"
    echo "[DRY-RUN] kubectl get pods,svc -n ci"
    echo "[DRY-RUN] kubectl get pods,svc -n tapm"
    echo "[DRY-RUN] Health checks for :3000 and :8080"
  fi
}

cmd_bootstrap() {
  if [ "$DRY_RUN" = false ]; then
    bash "${SCRIPT_DIR}/bootstrap.sh"
  else
    bash "${SCRIPT_DIR}/bootstrap.sh" --dry-run
  fi
}

cmd_pr() {
  if [ "$DRY_RUN" = false ]; then
    bash "${SCRIPT_DIR}/open-pr.sh"
  else
    bash "${SCRIPT_DIR}/open-pr.sh" --dry-run
  fi
}

case "$COMMAND" in
  up)
    cmd_up
    ;;
  down)
    cmd_down
    ;;
  status)
    cmd_status
    ;;
  bootstrap)
    cmd_bootstrap
    ;;
  pr)
    cmd_pr
    ;;
  *)
    echo "Unknown command: ${COMMAND}" >&2
    usage
    ;;
esac
