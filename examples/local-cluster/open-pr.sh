#!/usr/bin/env bash
# ==============================================================================
# open-pr.sh - Create demo pull request on cluster Gitea instance (W2.3a)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_STACK_PR="${SCRIPT_DIR}/../local-stack/open-pr.sh"
CLUSTER_ENV="${SCRIPT_DIR}/.env"

if [ -f "$CLUSTER_ENV" ]; then
  # shellcheck disable=SC1090
  set -a
  source "$CLUSTER_ENV" 2>/dev/null || true
  set +a
fi

if [ -x "$LOCAL_STACK_PR" ]; then
  exec "$LOCAL_STACK_PR" --token "${GITEA_TOKEN:-}" "$@"
else
  echo "Error: Base open-pr.sh not found at ${LOCAL_STACK_PR}" >&2
  exit 1
fi
