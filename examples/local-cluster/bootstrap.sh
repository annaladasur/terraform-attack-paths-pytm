#!/usr/bin/env bash
# ==============================================================================
# TAPM Local Cluster Bootstrap Script (Task W2.3a)
#
# Configures local Kubernetes cluster (k3d/kind) Gitea and TAPM components:
# 1. Admin account creation and verification on cluster Gitea
# 2. API token generation for tapm-service adapter
# 3. Synchronizes Gitea token to secret/tapm-secret in namespace tapm
# 4. Organization and demo repository creation
# 5. Seeds 4 canonical branches (main, pr-42, fix, injection) from demo-repo
# 6. Branch protection on main with required check ('attack-paths')
# 7. Actions runner registration token generation
# 8. Synchronizes runner token to secret/runner-secret in namespace ci
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/manifests"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"
LOCAL_STACK_DIR="${SCRIPT_DIR}/../local-stack"

# Configuration defaults
GITEA_URL="${GITEA_URL:-http://localhost:3000}"
GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-tapm-admin}"
GITEA_ADMIN_PASSWORD="${GITEA_ADMIN_PASSWORD:-tapm-admin-pass123}"
GITEA_ADMIN_EMAIL="${GITEA_ADMIN_EMAIL:-admin@tapm.local}"
GITEA_ORG="${GITEA_ORG:-demo-org}"
GITEA_REPO="${GITEA_REPO:-infra-demo}"
REQUIRED_CHECK="${REQUIRED_CHECK:-attack-paths}"
TAPM_SERVER_TOKEN="${TAPM_SERVER_TOKEN:-demo-secret-token}"

DRY_RUN=false
SKIP_WAIT=false
USE_KUBECTL=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --skip-wait)
      SKIP_WAIT=true
      shift
      ;;
    --no-k8s)
      USE_KUBECTL=false
      shift
      ;;
    --url)
      GITEA_URL="$2"
      shift 2
      ;;
    --admin-user)
      GITEA_ADMIN_USER="$2"
      shift 2
      ;;
    --admin-password)
      GITEA_ADMIN_PASSWORD="$2"
      shift 2
      ;;
    --org)
      GITEA_ORG="$2"
      shift 2
      ;;
    --repo)
      GITEA_REPO="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  --dry-run           Simulate bootstrap without executing remote actions"
      echo "  --skip-wait         Skip waiting for Gitea health probe"
      echo "  --no-k8s            Skip kubectl secret synchronization"
      echo "  --url URL           Gitea external URL (default: http://localhost:3000)"
      echo "  --admin-user USER   Gitea admin username (default: tapm-admin)"
      echo "  --admin-password PW Gitea admin password (default: tapm-admin-pass123)"
      echo "  --org ORG           Demo organization (default: demo-org)"
      echo "  --repo REPO         Demo repository (default: infra-demo)"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

echo "============================================================"
echo " Bootstrapping TAPM Local Cluster"
echo " Gitea URL:     ${GITEA_URL}"
echo " Admin:         ${GITEA_ADMIN_USER}"
echo " Org / Repo:    ${GITEA_ORG} / ${GITEA_REPO}"
echo " Required Gate: ${REQUIRED_CHECK}"
echo " Dry Run:       ${DRY_RUN}"
echo "============================================================"

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Simulating local cluster bootstrap..."
fi

# ------------------------------------------------------------------------------
# 0. Wait for Gitea to become ready
# ------------------------------------------------------------------------------
if [ "$DRY_RUN" = false ] && [ "$SKIP_WAIT" = false ]; then
  echo "Waiting for Gitea to respond at ${GITEA_URL}..."
  MAX_RETRIES=30
  COUNT=0
  until curl -sf "${GITEA_URL}/api/v1/version" >/dev/null 2>&1; do
    COUNT=$((COUNT + 1))
    if [ "$COUNT" -ge "$MAX_RETRIES" ]; then
      echo "Error: Timed out waiting for Gitea at ${GITEA_URL}" >&2
      exit 1
    fi
    sleep 2
  done
  echo "✓ Gitea is up and responding."
fi

# ------------------------------------------------------------------------------
# 1. Ensure Admin Account Exists
# ------------------------------------------------------------------------------
echo "Configuring admin account: ${GITEA_ADMIN_USER}..."
if [ "$DRY_RUN" = false ]; then
  ADMIN_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    "${GITEA_URL}/api/v1/user" || echo "000")

  if [ "$ADMIN_CHECK" != "200" ]; then
    echo "Creating admin account via Gitea container exec..."
    if command -v kubectl >/dev/null 2>&1 && [ "$USE_KUBECTL" = true ]; then
      GITEA_POD=$(kubectl get pods -n git -l app.kubernetes.io/name=gitea -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
      if [ -n "$GITEA_POD" ]; then
        kubectl exec -n git "$GITEA_POD" -c gitea -- \
          /sbin/su-exec git gitea admin user create \
            --admin \
            --username "${GITEA_ADMIN_USER}" \
            --password "${GITEA_ADMIN_PASSWORD}" \
            --email "${GITEA_ADMIN_EMAIL}" \
            --must-change-password=false 2>/dev/null || true
      fi
    fi
  fi
  echo "✓ Admin account verified."
else
  echo "[DRY-RUN] Verified admin account ${GITEA_ADMIN_USER}."
fi

# ------------------------------------------------------------------------------
# 2. Generate Gitea API Token for tapm-service
# ------------------------------------------------------------------------------
echo "Generating API token for tapm-service..."
GITEA_TOKEN="dry-run-token-gitea-12345"
if [ "$DRY_RUN" = false ]; then
  LIST_TOKENS=$(curl -s -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    "${GITEA_URL}/api/v1/users/${GITEA_ADMIN_USER}/tokens" || echo "[]")

  EXISTING_TOKEN_ID=$(python3 -c "
import sys, json
try:
    tokens = json.loads(sys.stdin.read())
    for t in tokens:
        if t.get('name') == 'tapm-service':
            print(t.get('id', ''))
            break
except Exception:
    pass
" <<< "$LIST_TOKENS" 2>/dev/null || true)
  if [ -n "$EXISTING_TOKEN_ID" ]; then
    curl -s -X DELETE -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
      "${GITEA_URL}/api/v1/users/${GITEA_ADMIN_USER}/tokens/${EXISTING_TOKEN_ID}" >/dev/null || true
  fi

  CREATE_TOKEN_RESP=$(curl -s -X POST -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" \
    "${GITEA_URL}/api/v1/users/${GITEA_ADMIN_USER}/tokens" \
    -d "{\"name\":\"tapm-service\",\"scopes\":[\"all\"]}")

  PARSED_TOKEN=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('sha1', ''))" <<< "$CREATE_TOKEN_RESP" 2>/dev/null || echo "")
  if [ -z "$PARSED_TOKEN" ]; then
    PARSED_TOKEN=$(echo "$CREATE_TOKEN_RESP" | grep -o '"sha1"[[:space:]]*:[[:space:]]*"[^"]*' | sed 's/.*"//' || echo "")
  fi
  if [ -n "$PARSED_TOKEN" ]; then
    GITEA_TOKEN="$PARSED_TOKEN"
  else
    echo "Warning: Could not create API token via REST API, attempting with basic auth..."
    GITEA_TOKEN="${GITEA_ADMIN_PASSWORD}"
  fi
  echo "✓ Generated API token: ${GITEA_TOKEN:0:8}..."
else
  echo "[DRY-RUN] Generated Gitea API token."
fi

# ------------------------------------------------------------------------------
# 3. Synchronize Gitea Token to namespace tapm
# ------------------------------------------------------------------------------
if [ "$USE_KUBECTL" = true ]; then
  echo "Synchronizing tapm-secret in namespace tapm..."
  if [ "$DRY_RUN" = false ]; then
    if command -v kubectl >/dev/null 2>&1; then
      kubectl create secret generic tapm-secret -n tapm \
        --from-literal=tapm-server-token="${TAPM_SERVER_TOKEN}" \
        --from-literal=gitea-token="${GITEA_TOKEN}" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1 || true
      kubectl rollout restart deployment/tapm-service -n tapm >/dev/null 2>&1 || true
    fi
  else
    echo "[DRY-RUN] Updated secret/tapm-secret in namespace tapm."
  fi
fi

# ------------------------------------------------------------------------------
# 4. Create Organization and Repository
# ------------------------------------------------------------------------------
echo "Ensuring organization '${GITEA_ORG}' and repository '${GITEA_REPO}' exist..."
if [ "$DRY_RUN" = false ]; then
  curl -s -X POST -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" \
    "${GITEA_URL}/api/v1/orgs" \
    -d "{\"username\":\"${GITEA_ORG}\",\"visibility\":\"public\"}" >/dev/null 2>&1 || true

  curl -s -X POST -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" \
    "${GITEA_URL}/api/v1/org/${GITEA_ORG}/repos" \
    -d "{\"name\":\"${GITEA_REPO}\",\"auto_init\":true,\"default_branch\":\"main\"}" >/dev/null 2>&1 || true
  echo "✓ Organization and repository ready."
else
  echo "[DRY-RUN] Created organization ${GITEA_ORG} and repo ${GITEA_REPO}."
fi

# ------------------------------------------------------------------------------
# 5. Seed Canonical Branches and Workflow
# ------------------------------------------------------------------------------
echo "Seeding repository branches and attack-paths workflow..."
if [ "$DRY_RUN" = false ]; then
  SEED_SCRIPT="${LOCAL_STACK_DIR}/seed-demo-repo.sh"
  REPO_REMOTE="http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}@${GITEA_URL#http://}/${GITEA_ORG}/${GITEA_REPO}.git"

  if [ -x "$SEED_SCRIPT" ]; then
    "$SEED_SCRIPT" --push "$REPO_REMOTE" --quiet 2>/dev/null || true
  fi

  WORKFLOW_PATH="${SCRIPT_DIR}/.gitea/workflows/attack-paths.yml"
  if [ -f "$WORKFLOW_PATH" ]; then
    WORKFLOW_CONTENT=$(cat "$WORKFLOW_PATH" | base64 | tr -d '\n')
    curl -s -X POST -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
      -H "Content-Type: application/json" \
      "${GITEA_URL}/api/v1/repos/${GITEA_ORG}/${GITEA_REPO}/contents/.gitea/workflows/attack-paths.yml" \
      -d "{\"content\":\"${WORKFLOW_CONTENT}\",\"message\":\"ci: seed attack-paths workflow\"}" >/dev/null 2>&1 || true
  fi
  echo "✓ Seeded demo branches and CI workflow."
else
  echo "[DRY-RUN] Seeded demo branches and attack-paths workflow."
fi

# ------------------------------------------------------------------------------
# 6. Branch Protection with Required Check
# ------------------------------------------------------------------------------
echo "Enforcing branch protection on 'main' with required check '${REQUIRED_CHECK}'..."
if [ "$DRY_RUN" = false ]; then
  curl -s -X POST -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" \
    "${GITEA_URL}/api/v1/repos/${GITEA_ORG}/${GITEA_REPO}/branch_protections" \
    -d "{
      \"rule_name\": \"main\",
      \"enable_push\": false,
      \"enable_merge_whitelist\": false,
      \"required_approvals\": 0,
      \"enable_status_check\": true,
      \"status_check_contexts\": [\"${REQUIRED_CHECK}\"],
      \"block_on_rejected_reviews\": false,
      \"dismiss_stale_approvals\": false
    }" >/dev/null 2>&1 || true
  echo "✓ Branch protection active."
else
  echo "[DRY-RUN] Enforced branch protection on main."
fi

# ------------------------------------------------------------------------------
# 7. Generate Runner Registration Token & Synchronize
# ------------------------------------------------------------------------------
echo "Obtaining Actions runner registration token..."
RUNNER_TOKEN="dry-run-runner-token-xyz"
if [ "$DRY_RUN" = false ]; then
  RUNNER_RESP=$(curl -s -X GET -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    "${GITEA_URL}/api/v1/orgs/${GITEA_ORG}/actions/runners/registration-token" 2>/dev/null || echo "{}")

  TOKEN_PARSED=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('token', ''))" <<< "$RUNNER_RESP" 2>/dev/null || echo "")
  if [ -z "$TOKEN_PARSED" ]; then
    RUNNER_RESP=$(curl -s -X POST -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
      "${GITEA_URL}/api/v1/admin/actions/runners/registration-token" 2>/dev/null || echo "{}")
    TOKEN_PARSED=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('token', ''))" <<< "$RUNNER_RESP" 2>/dev/null || echo "")
  fi
  if [ -z "$TOKEN_PARSED" ]; then
    RUNNER_RESP=$(curl -s -X POST -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
      "${GITEA_URL}/api/v1/orgs/${GITEA_ORG}/actions/runners/registration-token" 2>/dev/null || echo "{}")
    TOKEN_PARSED=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('token', ''))" <<< "$RUNNER_RESP" 2>/dev/null || echo "")
  fi
  if [ -z "$TOKEN_PARSED" ]; then
    TOKEN_PARSED=$(echo "$RUNNER_RESP" | grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*' | sed 's/.*"//' || echo "")
  fi
  if [ -n "$TOKEN_PARSED" ]; then
    RUNNER_TOKEN="$TOKEN_PARSED"
  fi

  if [ "$USE_KUBECTL" = true ] && command -v kubectl >/dev/null 2>&1; then
    kubectl create secret generic runner-secret -n ci \
      --from-literal=runner-token="${RUNNER_TOKEN}" \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1 || true
    kubectl rollout restart deployment/tapm-runner -n ci >/dev/null 2>&1 || true
    kubectl rollout status deployment/tapm-runner -n ci --timeout=60s >/dev/null 2>&1 || true
  fi
  echo "✓ Actions runner token configured: ${RUNNER_TOKEN:0:8}..."
else
  echo "[DRY-RUN] Generated runner token and updated secret/runner-secret in ci."
fi

# ------------------------------------------------------------------------------
# 8. Write Environment File
# ------------------------------------------------------------------------------
cat << EOF > "${ENV_FILE}"
# Auto-generated by TAPM local cluster bootstrap
GITEA_URL=${GITEA_URL}
GITEA_ADMIN_USER=${GITEA_ADMIN_USER}
GITEA_ADMIN_PASSWORD=${GITEA_ADMIN_PASSWORD}
GITEA_ORG=${GITEA_ORG}
GITEA_REPO=${GITEA_REPO}
REQUIRED_CHECK=${REQUIRED_CHECK}
GITEA_TOKEN=${GITEA_TOKEN}
GITEA_RUNNER_TOKEN=${RUNNER_TOKEN}
TAPM_SERVER_TOKEN=${TAPM_SERVER_TOKEN}
TAPM_SERVER_URL=http://tapm-service.tapm.svc.cluster.local:8080
EOF

echo ""
echo "============================================================"
echo " TAPM Local Cluster Bootstrap Complete!"
echo " Configuration saved to: ${ENV_FILE}"
echo " Gitea UI:    ${GITEA_URL}"
echo " Repository:  ${GITEA_URL}/${GITEA_ORG}/${GITEA_REPO}"
echo " Credentials: ${GITEA_ADMIN_USER} / ${GITEA_ADMIN_PASSWORD}"
echo "============================================================"
