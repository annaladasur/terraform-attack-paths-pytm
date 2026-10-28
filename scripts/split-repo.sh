#!/usr/bin/env bash
# scripts/split-repo.sh
# Verify standalone package files; history-preserving publication is disabled.
#
# Usage:
#   bash scripts/split-repo.sh [--branch <branch_name>] [--verify]
#
# Default branch name: standalone-package

set -euo pipefail

BRANCH="${SPLIT_BRANCH:-standalone-package}"
VERIFY_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)
      BRANCH="$2"
      shift 2
      ;;
    --verify)
      VERIFY_ONLY=1
      shift
      ;;
    -h|--help)
      echo "Usage: bash scripts/split-repo.sh [--branch <branch_name>] [--verify]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
PACKAGE_SUBDIR="OWASP-GLOBAL-AppSec-US-2026/terraform-attack-paths-pytm"

echo "== Verifying workspace state"
if [ -f "${REPO_ROOT}/pyproject.toml" ] && [ -d "${REPO_ROOT}/src/tapm" ]; then
  PACKAGE_SUBDIR="."
fi
if [ ! -d "${REPO_ROOT}/${PACKAGE_SUBDIR}" ]; then
  echo "ERROR: Subtree ${PACKAGE_SUBDIR} not found from repo root ${REPO_ROOT}" >&2
  exit 1
fi

if [ $VERIFY_ONLY -eq 1 ]; then
  echo "== Verification mode: checking standalone readiness of ${PACKAGE_SUBDIR}"
  REQUIRED_FILES=(
    "pyproject.toml"
    "Makefile"
    "README.md"
    "LICENSE"
    "SECURITY.md"
    ".github/workflows/ci.yml"
    ".github/workflows/critic.yml"
    ".github/ISSUE_TEMPLATE/config.yml"
    "examples/local-stack/compose.yaml"
    "examples/local-cluster/cluster.sh"
    "labs/README.md"
  )
  for rf in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "${REPO_ROOT}/${PACKAGE_SUBDIR}/${rf}" ]; then
      echo "FAIL: Required file missing: ${rf}" >&2
      exit 1
    fi
  done
  echo "✓ Standalone package tree contains all required files."
  exit 0
fi

echo "ERROR: History-preserving publication is disabled. Use scripts/export-public.py for a reviewed snapshot; do not publish private history or tags." >&2
exit 2

