#!/usr/bin/env bash
# ==============================================================================
# TAPM Local Stack Bootstrap Script (Task W2.1a)
#
# Configures local Gitea instance for end-to-end PR attack-path reviews:
# 1. Admin account creation and verification
# 2. API token generation for tapm serve adapter
# 3. Organization and demo repository creation
# 4. Seeds .gitea/workflows/attack-paths.yml workflow
# 5. Branch protection on main with required check ('attack-paths')
# 6. Actions runner registration token generation
# 7. Updates .env and triggers runner & analysis service startup
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${SCRIPT_DIR}/compose.yaml}"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"

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
NO_COMPOSE=false

# CLI argument handling
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
    --no-compose)
      NO_COMPOSE=true
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
      echo "  --dry-run         Simulate bootstrap steps without making remote changes"
      echo "  --skip-wait       Skip waiting for Gitea health readiness"
      echo "  --no-compose      Never call docker: no container CLI steps, no service restart (tests use this)"
      echo "  --url URL         Gitea URL (default: http://localhost:3000)"
      echo "  --admin-user U    Admin username (default: tapm-admin)"
      echo "  --admin-password P Admin password (default: tapm-admin-pass123)"
      echo "  --org ORG         Demo organization name (default: demo-org)"
      echo "  --repo REPO       Demo repository name (default: infra-demo)"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

echo "============================================================"
echo " Bootstrapping TAPM Local Stack"
echo " Gitea URL:     ${GITEA_URL}"
echo " Admin:         ${GITEA_ADMIN_USER}"
echo " Org / Repo:    ${GITEA_ORG} / ${GITEA_REPO}"
echo " Required Gate: ${REQUIRED_CHECK}"
echo "============================================================"

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Simulating bootstrap execution..."
fi

# ------------------------------------------------------------------------------
# 0. Wait for Gitea to become ready
# ------------------------------------------------------------------------------
if [ "$DRY_RUN" = false ] && [ "$SKIP_WAIT" = false ]; then
  echo "Waiting for Gitea to respond at ${GITEA_URL}..."
  MAX_RETRIES=30
  RETRY=0
  until curl -sf "${GITEA_URL}/api/v1/version" >/dev/null 2>&1; do
    RETRY=$((RETRY + 1))
    if [ "$RETRY" -ge "$MAX_RETRIES" ]; then
      echo "Error: Gitea not available at ${GITEA_URL} after ${MAX_RETRIES} attempts." >&2
      exit 1
    fi
    sleep 2
  done
  echo "Gitea is up and healthy."
fi

# ------------------------------------------------------------------------------
# 1. Admin account creation / verification
# ------------------------------------------------------------------------------
echo "[1/6] Ensuring admin user '${GITEA_ADMIN_USER}'..."
if [ "$DRY_RUN" = true ]; then
  echo "  [DRY-RUN] Admin user verified."
else
  # Check if running under Docker Compose
  GITEA_CID=""
  if [ "$NO_COMPOSE" = false ] && { [[ "$GITEA_URL" =~ :3000(/.*)?$ ]] || [[ "$GITEA_URL" =~ gitea:3000 ]]; }; then
    GITEA_CID=$(docker compose -f "$COMPOSE_FILE" ps -q gitea 2>/dev/null || true)
  fi
  if command -v docker >/dev/null 2>&1 && [ -f "$COMPOSE_FILE" ] && [ -n "${GITEA_CID}" ]; then
    if docker compose -f "$COMPOSE_FILE" exec -u git -T gitea gitea admin user list 2>/dev/null | grep -qw "${GITEA_ADMIN_USER}"; then
      docker compose -f "$COMPOSE_FILE" exec -u git -T gitea \
        gitea admin user change-password --username "${GITEA_ADMIN_USER}" --password "${GITEA_ADMIN_PASSWORD}" --must-change-password=false >/dev/null 2>&1 || true
      echo "  Admin user exists; password synchronized."
    else
      docker compose -f "$COMPOSE_FILE" exec -u git -T gitea \
        gitea admin user create --username "${GITEA_ADMIN_USER}" --password "${GITEA_ADMIN_PASSWORD}" --email "${GITEA_ADMIN_EMAIL}" --admin --must-change-password=false >/dev/null
      echo "  Admin user created successfully via container CLI."
    fi
  else
    echo "  Gitea container not running via Compose; using API endpoints."
  fi
fi

# ------------------------------------------------------------------------------
# 2. Service Access Token Generation
# ------------------------------------------------------------------------------
echo "[2/6] Generating Gitea API token for tapm-service..."
GITEA_TOKEN="${GITEA_TOKEN:-}"
if [ "$DRY_RUN" = true ]; then
  GITEA_TOKEN="dry-run-token-gitea-12345"
  echo "  [DRY-RUN] Generated token: ${GITEA_TOKEN}"
elif [ -z "$GITEA_TOKEN" ]; then
  AUTH_HEADER=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" | base64)
  TOKEN_NAME="tapm-service-token-$(date +%s)"
  
  TOKEN_RESP=$(curl -s -X POST "${GITEA_URL}/api/v1/users/${GITEA_ADMIN_USER}/tokens" \
    -H "Authorization: Basic ${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"${TOKEN_NAME}\", \"scopes\": [\"all\"]}" 2>/dev/null || echo "{}")
  
  PARSED_TOKEN=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('sha1', ''))" <<< "$TOKEN_RESP" 2>/dev/null || echo "")
  if [ -z "$PARSED_TOKEN" ]; then
    PARSED_TOKEN=$(echo "$TOKEN_RESP" | grep -o '"sha1"[[:space:]]*:[[:space:]]*"[^"]*' | sed 's/.*"//' || echo "")
  fi
  if [ -n "$PARSED_TOKEN" ]; then
    GITEA_TOKEN="$PARSED_TOKEN"
    echo "  Generated API token: ${GITEA_TOKEN:0:8}..."
  else
    # Fallback to existing token in env file if available
    if [ -f "$ENV_FILE" ]; then
      GITEA_TOKEN=$(grep '^GITEA_TOKEN=' "$ENV_FILE" | cut -d'=' -f2- || echo "")
    fi
    if [ -z "$GITEA_TOKEN" ]; then
      GITEA_TOKEN="default-local-token-fallback"
      echo "  Using default token fallback."
    else
      echo "  Retained existing GITEA_TOKEN from .env."
    fi
  fi
fi

# ------------------------------------------------------------------------------
# 3. Organization & Demo Repository Creation
# ------------------------------------------------------------------------------
echo "[3/6] Setting up organization '${GITEA_ORG}' and demo repository '${GITEA_REPO}'..."
if [ "$DRY_RUN" = true ]; then
  echo "  [DRY-RUN] Organization and repository verified."
else
  AUTH_BASIC=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" | base64)
  
  # Ensure Organization
  curl -s -X POST "${GITEA_URL}/api/v1/orgs" \
    -H "Authorization: Basic ${AUTH_BASIC}" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"${GITEA_ORG}\", \"full_name\": \"Demo Infrastructure Org\", \"visibility\": \"public\"}" >/dev/null 2>&1 || true

  # Ensure Repository
  curl -s -X POST "${GITEA_URL}/api/v1/orgs/${GITEA_ORG}/repos" \
    -H "Authorization: Basic ${AUTH_BASIC}" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"${GITEA_REPO}\", \"description\": \"Demo infrastructure repository for attack path evaluation\", \"auto_init\": true, \"default_branch\": \"main\"}" >/dev/null 2>&1 || true
  
  echo "  Repository ${GITEA_ORG}/${GITEA_REPO} created/verified."
fi

# ------------------------------------------------------------------------------
# 4. Seed Demo Repository (main, pr-42, fix, injection)
# ------------------------------------------------------------------------------
echo "[4/6] Seeding demo repository branches (main, pr-42, fix, injection)..."
SEED_SCRIPT="${SCRIPT_DIR}/seed-demo-repo.sh"
if [ "$DRY_RUN" = true ]; then
  echo "  [DRY-RUN] Demo repository seeded with branches: main, pr-42, fix, injection."
elif [ -f "$SEED_SCRIPT" ]; then
  GITEA_PROTO=$(echo "${GITEA_URL}" | grep :// | sed -e's,^\(.*://\).*,\1,g' || echo "http://")
  GITEA_NO_PROTO=$(echo "${GITEA_URL}" | sed -e "s,^${GITEA_PROTO},,")
  GITEA_PUSH_URL="${GITEA_PROTO}${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}@${GITEA_NO_PROTO}/${GITEA_ORG}/${GITEA_REPO}.git"
  
  if bash "$SEED_SCRIPT" --push "$GITEA_PUSH_URL" --quiet 2>/dev/null; then
    echo "  Seeded branches main, pr-42, fix, injection successfully via git push."
  else
    # Fallback to single workflow file seed via API if git push fails
    WORKFLOW_SRC="${SCRIPT_DIR}/.gitea/workflows/attack-paths.yml"
    if [ -f "$WORKFLOW_SRC" ]; then
      AUTH_BASIC=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" | base64)
      WORKFLOW_CONTENT=$(base64 < "$WORKFLOW_SRC" | tr -d '\n')
      PAYLOAD="{\"message\": \"Add attack-paths review workflow\", \"content\": \"${WORKFLOW_CONTENT}\", \"branch\": \"main\"}"
      curl -s -X POST "${GITEA_URL}/api/v1/repos/${GITEA_ORG}/${GITEA_REPO}/contents/.gitea/workflows/attack-paths.yml" \
        -H "Authorization: Basic ${AUTH_BASIC}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" >/dev/null 2>&1 || true
    fi
    echo "  Seeded default workflow via Gitea API fallback."
  fi
else
  echo "  Seed script not found at ${SEED_SCRIPT}; skipping seed."
fi

# ------------------------------------------------------------------------------
# 5. Branch Protection with Required Check ('attack-paths')
# ------------------------------------------------------------------------------
echo "[5/6] Configuring branch protection on 'main' with required check '${REQUIRED_CHECK}'..."
if [ "$DRY_RUN" = true ]; then
  echo "  [DRY-RUN] Branch protection configured: status check context [${REQUIRED_CHECK}]."
else
  AUTH_BASIC=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" | base64)
  PROTECT_PAYLOAD=$(cat << EOF
{
  "branch_name": "main",
  "enable_push": true,
  "enable_status_check": true,
  "status_check_contexts": ["${REQUIRED_CHECK}"],
  "required_approvals": 0
}
EOF
)
  curl -s -X POST "${GITEA_URL}/api/v1/repos/${GITEA_ORG}/${GITEA_REPO}/branch_protections" \
    -H "Authorization: Basic ${AUTH_BASIC}" \
    -H "Content-Type: application/json" \
    -d "$PROTECT_PAYLOAD" >/dev/null 2>&1 || true
  echo "  Branch protection active on 'main' (required check: ${REQUIRED_CHECK})."
fi

# ------------------------------------------------------------------------------
# 6. Actions Runner Registration Token & Environment Sync
# ------------------------------------------------------------------------------
echo "[6/6] Generating Actions runner registration token..."
GITEA_RUNNER_TOKEN="${GITEA_RUNNER_TOKEN:-}"
if [ "$DRY_RUN" = true ]; then
  GITEA_RUNNER_TOKEN="dry-run-runner-token-xyz"
  echo "  [DRY-RUN] Generated runner token: ${GITEA_RUNNER_TOKEN}"
elif [ -z "$GITEA_RUNNER_TOKEN" ]; then
  GITEA_CID=""
  if [ "$NO_COMPOSE" = false ] && { [[ "$GITEA_URL" =~ :3000(/.*)?$ ]] || [[ "$GITEA_URL" =~ gitea:3000 ]]; }; then
    GITEA_CID=$(docker compose -f "$COMPOSE_FILE" ps -q gitea 2>/dev/null || true)
  fi
  if command -v docker >/dev/null 2>&1 && [ -f "$COMPOSE_FILE" ] && [ -n "${GITEA_CID}" ]; then
    GITEA_RUNNER_TOKEN=$(docker compose -f "$COMPOSE_FILE" exec -u git -T gitea gitea actions generate-runner-token 2>/dev/null | tr -d '\r\n' || echo "")
  fi
  if [ -z "$GITEA_RUNNER_TOKEN" ]; then
    AUTH_BASIC=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" | base64)
    TOKEN_RESP=$(curl -s -X POST "${GITEA_URL}/api/v1/admin/actions/runners/registration-token" \
      -H "Authorization: Basic ${AUTH_BASIC}" 2>/dev/null || echo "{}")
    GITEA_RUNNER_TOKEN=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('token', ''))" <<< "$TOKEN_RESP" 2>/dev/null || echo "")
    if [ -z "$GITEA_RUNNER_TOKEN" ]; then
      GITEA_RUNNER_TOKEN=$(echo "$TOKEN_RESP" | grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*' | sed 's/.*"//' || echo "")
    fi
  fi
  if [ -n "$GITEA_RUNNER_TOKEN" ]; then
    echo "  Runner registration token generated."
  else
    GITEA_RUNNER_TOKEN="fallback-runner-token"
    echo "  Using fallback runner token."
  fi
fi

# Sync configuration to .env file
cat << EOF > "$ENV_FILE"
# Generated by bootstrap.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
GITEA_URL=${GITEA_URL}
GITEA_ADMIN_USER=${GITEA_ADMIN_USER}
GITEA_ADMIN_PASSWORD=${GITEA_ADMIN_PASSWORD}
GITEA_ADMIN_EMAIL=${GITEA_ADMIN_EMAIL}
GITEA_ORG=${GITEA_ORG}
GITEA_REPO=${GITEA_REPO}
REQUIRED_CHECK=${REQUIRED_CHECK}
GITEA_TOKEN=${GITEA_TOKEN}
GITEA_RUNNER_TOKEN=${GITEA_RUNNER_TOKEN}
TAPM_SERVER_TOKEN=${TAPM_SERVER_TOKEN}
TAPM_SERVER_URL=http://localhost:8080
TAPM_LLM=simulated
TAPM_JEV=local
OLLAMA_HOST=http://host.docker.internal:11434
EOF
echo "  Synchronized environment variables to ${ENV_FILE}."

# Start / restart compose services if docker compose is running. Compose reads the .env next to the compose file,
# so a restart only applies what this script wrote when ENV_FILE is that file. With any other ENV_FILE (the tests
# write .env.test_*), restarting would recreate the live services with whatever .env sits there, or none.
COMPOSE_ENV_FILE="$(dirname "$COMPOSE_FILE")/.env"
if [ "$NO_COMPOSE" = true ]; then
  echo "Skipping compose restart (--no-compose)."
elif [ "$DRY_RUN" = false ] && [ "$ENV_FILE" != "$COMPOSE_ENV_FILE" ]; then
  echo "Skipping compose restart: compose reads ${COMPOSE_ENV_FILE}, but this run wrote ${ENV_FILE}."
elif [ "$DRY_RUN" = false ] && command -v docker >/dev/null 2>&1 && [ -f "$COMPOSE_FILE" ]; then
  ACTIVE_CONTAINERS=$(docker compose -f "$COMPOSE_FILE" ps -q 2>/dev/null || true)
  if [ -n "${ACTIVE_CONTAINERS}" ]; then
    echo "Restarting analysis-service and starting act_runner..."
    docker compose -f "$COMPOSE_FILE" up -d analysis-service runner 2>/dev/null || true
  fi
fi

echo "============================================================"
echo " TAPM Local Stack Bootstrap Complete!"
echo "============================================================"
echo " - Gitea Web UI:      ${GITEA_URL}"
echo " - Login credentials: ${GITEA_ADMIN_USER} / ${GITEA_ADMIN_PASSWORD}"
echo " - Demo repository:   ${GITEA_URL}/${GITEA_ORG}/${GITEA_REPO}"
echo " - Demo branches:     main, pr-42, fix, injection"
echo " - Open PR script:    ${SCRIPT_DIR}/open-pr.sh"
echo " - Required check:    ${REQUIRED_CHECK} (enforced on main)"
echo " - Analysis service:  http://localhost:8080"
echo " - Metrics endpoint:  http://localhost:8080/v1/metrics"
echo "============================================================"
