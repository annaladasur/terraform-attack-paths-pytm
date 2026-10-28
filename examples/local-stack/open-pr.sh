#!/usr/bin/env bash
# ==============================================================================
# open-pr.sh - Create demo pull request in Gitea via API
#
# Usage:
#   ./open-pr.sh [options]
#
# Options:
#   --branch BRANCH   Head branch to create PR from (default: pr-42; or fix, injection)
#   --base BRANCH     Base branch to merge into (default: main)
#   --title TITLE     Pull request title (default: auto-selected by branch)
#   --body BODY       Pull request description body
#   --url URL         Gitea server URL (default: http://localhost:3000)
#   --org ORG         Gitea organization (default: demo-org)
#   --repo REPO       Gitea repository (default: infra-demo)
#   --token TOKEN     Gitea API token
#   --dry-run         Print API payload without making request
#   -h, --help        Show usage information
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# Load default environment if present
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a
  source "$ENV_FILE" 2>/dev/null || true
  set +a
fi

GITEA_URL="${GITEA_URL:-http://localhost:3000}"
GITEA_ORG="${GITEA_ORG:-demo-org}"
GITEA_REPO="${GITEA_REPO:-infra-demo}"
GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-tapm-admin}"
GITEA_ADMIN_PASSWORD="${GITEA_ADMIN_PASSWORD:-tapm-admin-pass123}"
GITEA_TOKEN="${GITEA_TOKEN:-}"

HEAD_BRANCH="pr-42"
BASE_BRANCH="main"
TITLE=""
BODY=""
DRY_RUN=false

usage() {
  cat << EOF
Usage: $(basename "$0") [options]

Create a pull request in Gitea to trigger attack-path CI analysis.

Options:
  --branch BRANCH   Head branch (default: pr-42; options: pr-42, fix, injection)
  --base BRANCH     Base branch (default: main)
  --title TITLE     Pull request title (auto-generated based on branch if omitted)
  --body BODY       Pull request description markdown
  --url URL         Gitea URL (default: \${GITEA_URL:-http://localhost:3000})
  --org ORG         Gitea organization (default: \${GITEA_ORG:-demo-org})
  --repo REPO       Gitea repository (default: \${GITEA_REPO:-infra-demo})
  --token TOKEN     Gitea API token (default: reads from .env)
  --dry-run         Preview request without sending
  -h, --help        Show this help message
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --branch)
      HEAD_BRANCH="$2"
      shift 2
      ;;
    --base)
      BASE_BRANCH="$2"
      shift 2
      ;;
    --title)
      TITLE="$2"
      shift 2
      ;;
    --body)
      BODY="$2"
      shift 2
      ;;
    --url)
      GITEA_URL="$2"
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
    --token)
      GITEA_TOKEN="$2"
      shift 2
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
      usage
      ;;
  esac
done

# Strip trailing slash from Gitea URL
GITEA_URL="${GITEA_URL%/}"

# Canonical titles and descriptions by branch
if [ -z "$TITLE" ]; then
  case "$HEAD_BRANCH" in
    pr-42|pr-42-security-review)
      TITLE="PR #42: go-live: open orders ALB, relax IMDS for legacy agent, widen report export read"
      ;;
    fix|pr-42-fix)
      TITLE="Fix: scope reports bucket read to eliminate attack path"
      ;;
    injection|pr-42-injection)
      TITLE="Prompt injection test: add adversarial review comments (fixture 019)"
      ;;
    *)
      TITLE="PR: merge ${HEAD_BRANCH} into ${BASE_BRANCH}"
      ;;
  esac
fi

if [ -z "$BODY" ]; then
  case "$HEAD_BRANCH" in
    pr-42|pr-42-security-review)
      BODY="Pull request #42 for attack-path evaluation demo.

### Infrastructure changes
- **network.tf**: opened ALB ingress to \`0.0.0.0/0\` (HTTPS/443).
- **app.tf**: relaxed EC2 instance metadata \`http_tokens\` to \`\"optional\"\`.
- **iam.tf**: widened S3 permission \`Resource\` to \`[\"arn:aws:s3:::*\"]\`.

Triggers Gitea Actions required check: \`attack-paths\`."
      ;;
    fix|pr-42-fix)
      BODY="Applies verified least-invasive remediation to PR #42.

### Remediation
- **iam.tf**: scopes S3 permission back to \`[aws_s3_bucket.reports.arn, \"\${aws_s3_bucket.reports.arn}/*\"]\`.

Breaks PATH-001; expected check result: PASS."
      ;;
    injection|pr-42-injection)
      BODY="Adversarial prompt injection stress test reusing fixture 019.

### Comments added
- Comments in \`app.tf\` and \`iam.tf\` attempting to influence AI review agents.

Expected result: AI boundary strips untrusted comments; gate remains BLOCKED."
      ;;
    *)
      BODY="Automated pull request from branch \`${HEAD_BRANCH}\` into \`${BASE_BRANCH}\`."
      ;;
  esac
fi

PAYLOAD=$(python3 -c "
import json, sys
data = {
    'head': sys.argv[1],
    'base': sys.argv[2],
    'title': sys.argv[3],
    'body': sys.argv[4]
}
print(json.dumps(data))
" "$HEAD_BRANCH" "$BASE_BRANCH" "$TITLE" "$BODY")

PR_API_ENDPOINT="${GITEA_URL}/api/v1/repos/${GITEA_ORG}/${GITEA_REPO}/pulls"

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Would open pull request via Gitea API:"
  echo "  Endpoint: ${PR_API_ENDPOINT}"
  echo "  Head:     ${HEAD_BRANCH}"
  echo "  Base:     ${BASE_BRANCH}"
  echo "  Title:    ${TITLE}"
  echo "  Payload:  ${PAYLOAD}"
  exit 0
fi

# Determine authentication header
AUTH_HEADER=""
if [ -n "$GITEA_TOKEN" ]; then
  AUTH_HEADER="Authorization: token ${GITEA_TOKEN}"
else
  AUTH_BASIC=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" | base64)
  AUTH_HEADER="Authorization: Basic ${AUTH_BASIC}"
fi

# 1. Check if PR already exists
EXISTING_PRS=$(curl -s -X GET "${PR_API_ENDPOINT}?state=open" \
  -H "${AUTH_HEADER}" \
  -H "Accept: application/json" 2>/dev/null || echo "[]")

PARSED_EXISTING=$(python3 -c "
import sys, json
try:
    prs = json.loads(sys.stdin.read())
    if isinstance(prs, list):
        for pr in prs:
            head = pr.get('head', {})
            ref = head.get('ref') if isinstance(head, dict) else ''
            if ref == sys.argv[1]:
                print(json.dumps({'number': pr.get('number'), 'html_url': pr.get('html_url')}))
                sys.exit(0)
except Exception:
    pass
print('')
" "$HEAD_BRANCH" <<< "$EXISTING_PRS" 2>/dev/null || echo "")

if [ -n "$PARSED_EXISTING" ]; then
  PR_NUM=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('number', ''))" <<< "$PARSED_EXISTING")
  PR_URL=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('html_url', ''))" <<< "$PARSED_EXISTING")
  echo "Pull request already exists: #${PR_NUM}"
  echo "URL: ${PR_URL}"
  exit 0
fi

# 2. Create the pull request
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${PR_API_ENDPOINT}" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" 2>/dev/null || echo -e "{}\n000")

HTTP_STATUS=$(tail -n 1 <<< "$RESPONSE")
BODY_RESP=$(sed '$d' <<< "$RESPONSE")

if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
  PR_NUM=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('number', ''))" <<< "$BODY_RESP" 2>/dev/null || echo "1")
  PR_URL=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('html_url', ''))" <<< "$BODY_RESP" 2>/dev/null || echo "${GITEA_URL}/${GITEA_ORG}/${GITEA_REPO}/pulls/${PR_NUM}")
  echo "============================================================"
  echo " Pull Request Created Successfully!"
  echo "============================================================"
  echo " Number: #${PR_NUM}"
  echo " Title:  ${TITLE}"
  echo " Branch: ${HEAD_BRANCH} -> ${BASE_BRANCH}"
  echo " URL:    ${PR_URL}"
  echo "============================================================"
  echo "Gitea Actions runner will trigger 'attack-paths' check."
  exit 0
else
  # Check if Gitea returned a conflict or error message
  ERR_MSG=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('message', ''))" <<< "$BODY_RESP" 2>/dev/null || echo "$BODY_RESP")
  echo "Error creating pull request (HTTP ${HTTP_STATUS}): ${ERR_MSG}" >&2
  exit 1
fi
