#!/usr/bin/env bash
# ==============================================================================
# seed-demo-repo.sh - Initialize demo repository with 4 canonical branches
#
# Branches created:
#   1. main       - Pre-PR base infrastructure (0 attack paths, gate passes)
#   2. pr-42      - PR #42 go-live changes (PATH-001 HIGH, gate blocked)
#   3. fix        - Verified remediation applied (PATH-001 eliminated)
#   4. injection  - Adversarial prompt injection comments (fixture 019)
#
# Options:
#   --target DIR    Directory to initialize git repository in (default: temp dir)
#   --push URL      Remote git URL to push all 4 branches to
#   --bundle FILE   Generate git bundle file containing all 4 branches
#   --dry-run       Print planned actions without modifying filesystem
#   --help          Show this message
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_REPO_DIR="${SCRIPT_DIR}/demo-repo"

TARGET_DIR=""
PUSH_URL=""
BUNDLE_FILE=""
DRY_RUN=false
QUIET=false

usage() {
  cat << EOF
Usage: $(basename "$0") [options]

Options:
  --target DIR    Path to directory where git repository will be initialized
  --push URL      Remote git URL to push all 4 branches to (e.g. http://user:pass@localhost:3000/demo-org/infra-demo.git)
  --bundle FILE   Path to write git bundle file containing all 4 branches
  --dry-run       Preview actions without executing
  -q, --quiet     Suppress progress messages
  -h, --help      Show this help message
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      TARGET_DIR="$2"
      shift 2
      ;;
    --push)
      PUSH_URL="$2"
      shift 2
      ;;
    --bundle)
      BUNDLE_FILE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -q|--quiet)
      QUIET=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
done

log() {
  if [ "$QUIET" = false ]; then
    echo "$@"
  fi
}

if [ "$DRY_RUN" = true ]; then
  log "[DRY-RUN] Seeding demo repository with branches: main, pr-42, fix, injection"
  [ -n "$TARGET_DIR" ] && log "  Target directory: ${TARGET_DIR}"
  [ -n "$BUNDLE_FILE" ] && log "  Bundle output:    ${BUNDLE_FILE}"
  [ -n "$PUSH_URL" ] && log "  Push remote:      ${PUSH_URL}"
  exit 0
fi

if [ -n "$BUNDLE_FILE" ]; then
  case "$BUNDLE_FILE" in
    /*) ;;
    *) BUNDLE_FILE="${PWD}/${BUNDLE_FILE}" ;;
  esac
fi

CLEANUP_TARGET=false
if [ -z "$TARGET_DIR" ]; then
  TARGET_DIR=$(mktemp -d "/tmp/demo-repo-seed-XXXXXX")
  CLEANUP_TARGET=true
else
  case "$TARGET_DIR" in
    /*) ;;
    *) TARGET_DIR="${PWD}/${TARGET_DIR}" ;;
  esac
fi

cleanup() {
  if [ "$CLEANUP_TARGET" = true ] && [ -d "$TARGET_DIR" ]; then
    rm -rf "$TARGET_DIR"
  fi
}
trap cleanup EXIT

log "== Initializing demo repository at ${TARGET_DIR}"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

if [ ! -d ".git" ]; then
  git init -b main -q
fi

git config user.name "Demo Author"
git config user.email "demo@example.com"
export GIT_AUTHOR_NAME="Demo Author"
export GIT_AUTHOR_EMAIL="demo@example.com"
export GIT_COMMITTER_NAME="Demo Author"
export GIT_COMMITTER_EMAIL="demo@example.com"
export GIT_AUTHOR_DATE="2026-10-08T15:46:57-05:00"
export GIT_COMMITTER_DATE="2026-10-08T15:46:57-05:00"

# ------------------------------------------------------------------------------
# 1. Base branch ('main')
# ------------------------------------------------------------------------------
log " -> Creating 'main' branch (pre-PR base infrastructure)..."
git checkout -B main -q

# Copy base files from demo-repo
for f in "$DEMO_REPO_DIR"/*.tf; do
  [ -f "$f" ] && cp "$f" "$TARGET_DIR/"
done
cp "$DEMO_REPO_DIR/plan.json" "$TARGET_DIR/plan.json"
cp "$DEMO_REPO_DIR/.plan-source-key" "$TARGET_DIR/.plan-source-key"
cp "$DEMO_REPO_DIR/README.md" "$TARGET_DIR/README.md"
mkdir -p "$TARGET_DIR/.gitea/workflows"
cp "$DEMO_REPO_DIR/.gitea/workflows/attack-paths.yml" "$TARGET_DIR/.gitea/workflows/"
rm -rf "$TARGET_DIR/baselines"
cp -r "$DEMO_REPO_DIR/baselines" "$TARGET_DIR/baselines"

git add -A
git commit -q -m "Initial infrastructure baseline for orders service (pre-PR #42)" --allow-empty

# ------------------------------------------------------------------------------
# 2. PR #42 branch ('pr-42')
# ------------------------------------------------------------------------------
log " -> Creating 'pr-42' branch (go-live changes: open ALB, relax IMDS, widen IAM)..."
git checkout -B pr-42 main -q

PR42_SRC="${DEMO_REPO_DIR}/branches/pr-42"
cp "$PR42_SRC/app.tf" "$TARGET_DIR/app.tf"
cp "$PR42_SRC/iam.tf" "$TARGET_DIR/iam.tf"
cp "$PR42_SRC/network.tf" "$TARGET_DIR/network.tf"
cp "$PR42_SRC/plan.json" "$TARGET_DIR/plan.json"
cp "$PR42_SRC/.plan-source-key" "$TARGET_DIR/.plan-source-key"
if [ -d "$PR42_SRC/baselines" ]; then
  rm -rf "$TARGET_DIR/baselines"
  cp -r "$PR42_SRC/baselines" "$TARGET_DIR/baselines"
fi
cp "$PR42_SRC/README.md" "$TARGET_DIR/PR-42.md"

git add -A
git commit -q -m "PR #42: go-live: open orders ALB, relax IMDS for legacy agent, widen report export read"

# ------------------------------------------------------------------------------
# 3. Fix branch ('fix')
# ------------------------------------------------------------------------------
log " -> Creating 'fix' branch (verified remediation: scope reports bucket read)..."
git checkout -B fix pr-42 -q

FIX_SRC="${DEMO_REPO_DIR}/branches/fix"
cp "$FIX_SRC/iam.tf" "$TARGET_DIR/iam.tf"
cp "$FIX_SRC/plan.json" "$TARGET_DIR/plan.json"
cp "$FIX_SRC/.plan-source-key" "$TARGET_DIR/.plan-source-key"
cp "$FIX_SRC/README.md" "$TARGET_DIR/FIX.md"

git add -A
git commit -q -m "Fix: scope reports bucket read to eliminate attack path"

# ------------------------------------------------------------------------------
# 4. Injection branch ('injection')
# ------------------------------------------------------------------------------
log " -> Creating 'injection' branch (prompt injection stress test: fixture 019)..."
git checkout -B injection pr-42 -q

INJ_SRC="${DEMO_REPO_DIR}/branches/injection"
cp "$INJ_SRC/app.tf" "$TARGET_DIR/app.tf"
cp "$INJ_SRC/iam.tf" "$TARGET_DIR/iam.tf"
cp "$INJ_SRC/plan.json" "$TARGET_DIR/plan.json"
cp "$INJ_SRC/.plan-source-key" "$TARGET_DIR/.plan-source-key"
if [ -d "$INJ_SRC/baselines" ]; then
  rm -rf "$TARGET_DIR/baselines"
  cp -r "$INJ_SRC/baselines" "$TARGET_DIR/baselines"
fi
cp "$INJ_SRC/README.md" "$TARGET_DIR/INJECTION.md"

git add -A
GIT_AUTHOR_DATE="2026-10-08T15:46:58-05:00" GIT_COMMITTER_DATE="2026-10-08T15:46:58-05:00" git commit -q -m "Prompt injection test: add adversarial review comments (fixture 019)"

# Switch back to main
git checkout main -q

# ------------------------------------------------------------------------------
# 5. Optional Bundle Export
# ------------------------------------------------------------------------------
if [ -n "$BUNDLE_FILE" ]; then
  log " -> Generating git bundle at ${BUNDLE_FILE}..."
  mkdir -p "$(dirname "$BUNDLE_FILE")"
  git bundle create "$BUNDLE_FILE" --all
  log "  Bundle created successfully."
fi

# ------------------------------------------------------------------------------
# 6. Optional Remote Push
# ------------------------------------------------------------------------------
if [ -n "$PUSH_URL" ]; then
  log " -> Pushing 4 branches to remote: ${PUSH_URL}..."
  remote_main=$(git ls-remote "$PUSH_URL" refs/heads/main)
  if [ -n "$remote_main" ]; then
    git fetch -q "$PUSH_URL" refs/heads/main
    if [ "$(git rev-parse FETCH_HEAD^{tree})" != "$(git rev-parse main^{tree})" ]; then
      echo "Refusing reset: remote main differs from the canonical baseline; protected main was not changed." >&2
      exit 2
    fi
  else
    git push -q "$PUSH_URL" main:main
  fi
  # Force-with-lease protects concurrent updates to the disposable demo branches.
  for branch in pr-42 fix injection; do
    remote_ref=$(git ls-remote "$PUSH_URL" "refs/heads/$branch")
    remote_sha=${remote_ref%%[[:space:]]*}
    git push -q "--force-with-lease=refs/heads/$branch:$remote_sha" "$PUSH_URL" "$branch:$branch"
  done
  log "  Branches pushed successfully."
fi

log "Demo repository seeded successfully with 4 branches (main, pr-42, fix, injection)."
