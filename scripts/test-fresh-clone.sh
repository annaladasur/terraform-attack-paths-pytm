#!/usr/bin/env bash
# ==============================================================================
# scripts/test-fresh-clone.sh
#
# Automated fresh-clone offline replay test on Mac hardware (Task A11 / Gate G3).
#
# Clones the repository to an isolated temporary directory, sets dead HTTP(S) proxies
# (http://127.0.0.1:9; loopback mocks allowed), blanks cloud credentials, and verifies:
#   Phase 1: CLI smoke checks (tapm --help, tapm paths 006, tapm canary)
#   Phase 2: Tier-2 held-out offline evaluation replay (tapm tier2 --heldout)
#   Phase 3: Real-world benign offline evaluation replay (tapm realworld)
#   Phase 4: Offline test suite execution inside the fresh clone
#
# Usage:
# Usage:
#   bash scripts/test-fresh-clone.sh [--standalone] [--full-suite] [--keep-clone] [--verbose]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${PROJECT_ROOT}" rev-parse --show-toplevel)"
HOST_PY="${TAPM_TEST_PYTHON:-${PROJECT_ROOT}/.venv/bin/python}"

STANDALONE=0
FULL_SUITE=0
KEEP_CLONE=0
VERBOSE=0

for arg in "$@"; do
  case "$arg" in
    --standalone)
      STANDALONE=1
      ;;
    --full-suite)
      FULL_SUITE=1
      ;;
    --keep-clone)
      KEEP_CLONE=1
      ;;
    --verbose|-v)
      VERBOSE=1
      ;;
    -h|--help)
      echo "Usage: bash scripts/test-fresh-clone.sh [--standalone] [--full-suite] [--keep-clone] [--verbose]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [ "$FULL_SUITE" -eq 1 ] && [ "$STANDALONE" -eq 1 ]; then
  echo "--full-suite validates the monorepo (including deck tests); use --standalone separately for the standalone replay contract." >&2
  exit 2
fi

echo "======================================================================"
if [ $STANDALONE -eq 1 ]; then
  echo "Task W6.2: Standalone Fresh Clone Offline Replay Test on Mac (Gate G5)"
else
  echo "Task A11: Fresh Clone Offline Replay Test on Mac (Gate G3)"
fi
echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Host Source: ${REPO_ROOT}"
echo "======================================================================"

# Determine host site-packages directory
PYTHON_VERSION=$("${HOST_PY}" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
HOST_SITE_PACKAGES=$("${HOST_PY}" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')

if [ ! -d "${HOST_SITE_PACKAGES}" ]; then
  echo "ERROR: Host site-packages not found at ${HOST_SITE_PACKAGES}" >&2
  exit 1
fi

# Create isolated temporary directory
TMP_DIR="$(mktemp -d /tmp/tapm-fresh-clone-XXXXXX)"
echo "Isolated temporary directory: ${TMP_DIR}"

SPLIT_BRANCH=""
cleanup() {
  if [ -n "${SPLIT_BRANCH}" ]; then
    git -C "${REPO_ROOT}" branch -D "${SPLIT_BRANCH}" >/dev/null 2>&1 || true
  fi
  if [ $KEEP_CLONE -eq 0 ]; then
    echo "Cleaning up temporary directory ${TMP_DIR}..."
    rm -rf "${TMP_DIR}"
  else
    echo "Preserving fresh clone at ${TMP_DIR}"
  fi
}
trap cleanup EXIT

CLONE_DIR="${TMP_DIR}/clone"

if [ -f "${REPO_ROOT}/release-manifest.json" ]; then
  git clone --quiet "${REPO_ROOT}" "${CLONE_DIR}"
  CLONE_PROJ="${CLONE_DIR}"
  if [ $STANDALONE -eq 1 ]; then
    echo "✓ Cloned standalone package into ${CLONE_DIR} at $(git -C "${CLONE_DIR}" rev-parse --short HEAD)"
  else
    echo "✓ Cloned into ${CLONE_DIR} at $(git -C "${CLONE_DIR}" rev-parse --short HEAD)"
  fi
elif [ $STANDALONE -eq 1 ]; then
  echo "== Step 1: Performing fresh git clone (standalone subtree split)"
  SPLIT_BRANCH="standalone-fresh-clone-$$"
  git -C "${REPO_ROOT}" subtree split --prefix="OWASP-GLOBAL-AppSec-US-2026/terraform-attack-paths-pytm" -b "${SPLIT_BRANCH}" >/dev/null
  git clone --branch "${SPLIT_BRANCH}" --quiet "${REPO_ROOT}" "${CLONE_DIR}"
  git -C "${REPO_ROOT}" branch -D "${SPLIT_BRANCH}" >/dev/null
  SPLIT_BRANCH=""
  CLONE_PROJ="${CLONE_DIR}"
  echo "✓ Cloned standalone package into ${CLONE_DIR} at $(git -C "${CLONE_DIR}" rev-parse --short HEAD)"
else
  echo "== Step 1: Performing fresh git clone"
  CLONE_PROJ="${CLONE_DIR}/OWASP-GLOBAL-AppSec-US-2026/terraform-attack-paths-pytm"
  git clone --quiet "${REPO_ROOT}" "${CLONE_DIR}"
  echo "✓ Cloned into ${CLONE_DIR} at $(git -C "${CLONE_DIR}" rev-parse --short HEAD)"
fi

# 2. Setup isolated venv inside the fresh clone
echo "== Step 2: Configuring isolated Python environment"
"${HOST_PY}" -m venv "${CLONE_PROJ}/.venv"

CLONE_SITE_PACKAGES="${CLONE_PROJ}/.venv/lib/python${PYTHON_VERSION}/site-packages"
"${HOST_PY}" - "${HOST_SITE_PACKAGES}" "${CLONE_SITE_PACKAGES}/host_site_packages.pth" <<'PY_DEPS'
import pathlib, sys
# Process .pth files too: the host itself may be a dependency-only test venv.
pathlib.Path(sys.argv[2]).write_text("import site; site.addsitedir(" + repr(sys.argv[1]) + ")\n")
PY_DEPS
echo "${CLONE_PROJ}/src" > "${CLONE_SITE_PACKAGES}/cloned_src.pth"

cat << 'EOF' > "${CLONE_PROJ}/.venv/bin/tapm"
#!/usr/bin/env bash
exec "$(dirname "$0")/python" -m tapm.cli "$@"
EOF
chmod +x "${CLONE_PROJ}/.venv/bin/tapm"

# Prefer cloned code over editable imports in the host dependency environment.
export PYTHONPATH="${CLONE_PROJ}/src${PYTHONPATH:+:$PYTHONPATH}"

# 3. Disconnect network and blank cloud credentials
echo "== Step 3: Configuring dead HTTP(S) proxies and blanking credentials"
export https_proxy="http://127.0.0.1:9"
export HTTPS_PROXY="http://127.0.0.1:9"
export http_proxy="http://127.0.0.1:9"
export HTTP_PROXY="http://127.0.0.1:9"
# The complete suite hosts ephemeral mock services on loopback. Allow only
# loopback to bypass the dead outbound proxy; discard inherited broad bypasses.
export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="$NO_PROXY"
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export AWS_CONFIG_FILE="/dev/null"
export AWS_SHARED_CREDENTIALS_FILE="/dev/null"

# Point repo clone directories to empty locations to prove ensure_repo bypass
export TAPM_TIER2_REPOS="${TMP_DIR}/empty_tier2_repos"
export TAPM_REALWORLD_REPOS="${TMP_DIR}/empty_realworld_repos"
mkdir -p "${TAPM_TIER2_REPOS}" "${TAPM_REALWORLD_REPOS}"

CLONE_TAPM="${CLONE_PROJ}/.venv/bin/tapm"
CLONE_PY="${CLONE_PROJ}/.venv/bin/python"

# 4. Phase 1: Offline CLI smoke tests
echo "== Phase 1: Offline CLI smoke checks"
"${CLONE_TAPM}" --help >/dev/null
echo "  [PASS] tapm --help"

PATHS_OUT=$("${CLONE_TAPM}" paths 006 2>&1)
if echo "${PATHS_OUT}" | grep -q "PATH-001"; then
  echo "  [PASS] tapm paths 006 (emitted PATH-001)"
else
  echo "  [FAIL] tapm paths 006 missing PATH-001" >&2
  exit 1
fi

CANARY_OUT=$("${CLONE_TAPM}" canary 2>&1)
if echo "${CANARY_OUT}" | grep -q "control failure rate (M15): 0/6"; then
  echo "  [PASS] tapm canary (0/6 control failures)"
else
  echo "  [FAIL] tapm canary control failure" >&2
  exit 1
fi

# 5. Phase 2: Tier-2 heldout offline evaluation replay
echo "== Phase 2: Tier-2 held-out offline evaluation replay"
T2_OUT=$("${CLONE_TAPM}" tier2 --heldout 2>&1)
if [ $VERBOSE -eq 1 ]; then
  echo "${T2_OUT}"
fi

# Validate heldout metrics
echo "${T2_OUT}" | grep -q '"tag": "heldout"'
echo "${T2_OUT}" | grep -q '"cases": 5'
echo "${T2_OUT}" | grep -q '"tp": 2'
echo "${T2_OUT}" | grep -q '"fn": 0'
echo "${T2_OUT}" | grep -q '"fp": 0'
echo "${T2_OUT}" | grep -q '"reachability_precision": 1.0'
echo "${T2_OUT}" | grep -q '"reachability_recall": 1.0'
echo "  [PASS] tapm tier2 --heldout: 5 cases, TP=2, FN=0, FP=0, precision=1.0, recall=1.0"

# 6. Phase 3: Real-world benign offline evaluation replay
echo "== Phase 3: Real-world benign offline evaluation replay"
RW_OUT=$("${CLONE_TAPM}" realworld 2>&1)
if [ $VERBOSE -eq 1 ]; then
  echo "${RW_OUT}"
fi

# Validate realworld metrics
echo "${RW_OUT}" | grep -q '"tag": "benign"'
echo "${RW_OUT}" | grep -q '"cases": 5'
echo "${RW_OUT}" | grep -q '"tp": 0'
echo "${RW_OUT}" | grep -q '"fn": 0'
echo "${RW_OUT}" | grep -q '"fp": 0'
echo "${RW_OUT}" | grep -q '"tn": 5'
echo "${RW_OUT}" | grep -q '"paths_emitted": 0'
echo "  [PASS] tapm realworld: 5 cases, TN=5, FP=0, paths_emitted=0"

# 7. Phase 4: exercise only source from the clone, using installed dependencies.
"${CLONE_PY}" - "${CLONE_PROJ}" <<'PY_SOURCE'
from pathlib import Path
import sys
from tapm.util import PROJECT_ROOT
assert PROJECT_ROOT.resolve() == Path(sys.argv[1]).resolve(), (PROJECT_ROOT, sys.argv[1])
print("  [PASS] imported tapm source is inside the fresh clone")
PY_SOURCE
if [ "$FULL_SUITE" -eq 1 ]; then
  # Node packages are declared in deck/package.json and installed before offline
  # validation. Reuse libraries only, never generated artifacts or source code.
  export NODE_PATH="${PROJECT_ROOT}/../deck/node_modules${NODE_PATH:+:$NODE_PATH}"
  HOST_NODE_MODULES=$(node - "${CLONE_PROJ}/../deck/package.json" <<'JS_DEPS'
const path = require("path");
const assert = require("assert");
const declared = require(process.argv[2]).dependencies.pptxgenjs;
assert.strictEqual(require("pptxgenjs/package.json").version, declared, "Deck dependency differs from pin; install deck/package-lock.json before offline validation");
process.stdout.write(path.dirname(path.dirname(require.resolve("pptxgenjs/package.json"))));
JS_DEPS
  )
  export NODE_PATH="${HOST_NODE_MODULES}${NODE_PATH:+:$NODE_PATH}"
  echo "== Phase 4: Running complete offline test suite inside fresh clone"
  (cd "${CLONE_PROJ}" && "${CLONE_PY}" -m pytest -rs)
  echo "  [PASS] complete offline test suite (see pytest summary above)"
else
  echo "== Phase 4: Running offline replay test suite inside fresh clone"
  (cd "${CLONE_PROJ}" && "${CLONE_PY}" -m pytest tests/test_offline_replay.py -q)
  echo "  [PASS] tests/test_offline_replay.py (3/3 passed offline)"
fi

echo
echo "======================================================================"
if [ $STANDALONE -eq 1 ]; then
  echo "✓ Task W6.2 Standalone Fresh Clone Offline Replay Test PASSED on Mac"
else
  echo "✓ Task A11 Fresh Clone Offline Replay Test PASSED on Mac"
fi
echo "  All 4 phases passed with dead outbound HTTP(S) proxies, loopback mocks allowed, and blank credentials."
echo "======================================================================"
exit 0
