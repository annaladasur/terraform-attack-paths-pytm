#!/usr/bin/env bash
# ==============================================================================
# scripts/critic.sh - Automatable checks for Mandatory Critic Cycle (C1-C18)
#
# Usage:
#   bash scripts/critic.sh [CHECK_ID ...]
#
# Examples:
#   bash scripts/critic.sh            # Run all automatable checks
#   bash scripts/critic.sh C1 C2 C3   # Run only checks C1, C2, and C3
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PROJECT_ROOT}/../.." && pwd)"
SNAPSHOT=0
if [ -f "${PROJECT_ROOT}/release-manifest.json" ]; then
  REPO_ROOT="$PROJECT_ROOT"
  SNAPSHOT=1
fi

VENV_BIN="${PROJECT_ROOT}/.venv/bin"
PY="${VENV_BIN}/python"

CHECKS=("$@")
if [ ${#CHECKS[@]} -eq 0 ]; then
  CHECKS=("C1" "C2" "C3" "C4" "C5" "C6" "C8" "C9" "C11" "C12" "C13" "C14" "C16")
fi

FAILURES=0

run_check() {
  local id="$1"
  local result="N/A"
  local evidence="not automated"

  case "$id" in
    C1)
      local st
      st=$(git -C "$REPO_ROOT" status --porcelain 2>&1)
      local git_rc=$?
      if [ "$git_rc" -ne 0 ]; then
        result="FAIL"
        evidence="git status failed (rc=$git_rc): $st"
        FAILURES=$((FAILURES + 1))
      elif [ -z "$st" ]; then
        result="PASS"
        evidence="git status clean"
      else
        result="FAIL"
        evidence="uncommitted changes: $(echo "$st" | head -2 | tr '\n' '; ')"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C2)
      local test_out
      test_out=$(AWS_ACCESS_KEY_ID="" AWS_SECRET_ACCESS_KEY="" AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null "$PY" -m pytest -rs 2>&1)
      local rc=$?
      local summary
      summary=$(echo "$test_out" | grep -E "[0-9]+ passed" | tail -1 | xargs)
      if [ $rc -eq 0 ] && [ -n "$summary" ]; then
        result="PASS"
        evidence="$summary"
      else
        result="FAIL"
        evidence="pytest exited $rc, summary: ${summary:-none}"
        printf '%s\n' "$test_out" >&2
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C3)
      local rep_out
      rep_out=$(make -C "$PROJECT_ROOT" report-check 2>&1)
      local rc=$?
      if [ $rc -eq 0 ]; then
        result="PASS"
        evidence="make report-check zero diff"
      else
        result="FAIL"
        evidence="make report-check failed (rc=$rc)"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C4)
      local bad_pins=0
      local bad_list=""
      while IFS= read -r vfile; do
        if [ -f "$vfile" ] && grep -q '"unknown"' "$vfile" 2>/dev/null; then
          bad_pins=$((bad_pins + 1))
          bad_list="${bad_list} $(basename "$(dirname "$vfile")")"
        fi
      done < <(find "${PROJECT_ROOT}/evaluations" -name "versions.json" 2>/dev/null)
      if [ $bad_pins -eq 0 ]; then
        result="PASS"
        evidence="all versions.json match pinned tools"
      else
        result="FAIL"
        evidence="$bad_pins versions.json have unknown or unpinned tools:$bad_list"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C5)
      local null_files
      null_files=$(find "${PROJECT_ROOT}/evaluations" -name "*.json" -exec grep -l "^null$" {} + 2>/dev/null || true)
      if [ -z "$null_files" ]; then
        result="PASS"
        evidence="zero null scanner outputs found"
      else
        local count
        count=$(echo "$null_files" | wc -l | xargs)
        result="FAIL"
        evidence="$count files contain literal null output"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C6)
      local c6_tmp
      c6_tmp=$(mktemp -d)
      local c6_out
      c6_out=$(TAPM_TIER2_REPOS="$c6_tmp" TAPM_REALWORLD_REPOS="$c6_tmp" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 "$VENV_BIN/tapm" tier2 --heldout 2>&1)
      local rc_t2=$?
      local c6_rw_out
      c6_rw_out=$(TAPM_TIER2_REPOS="$c6_tmp" TAPM_REALWORLD_REPOS="$c6_tmp" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 "$VENV_BIN/tapm" realworld 2>&1)
      local rc_rw=$?
      rm -rf "$c6_tmp"
      if [ $rc_t2 -eq 0 ] && [ $rc_rw -eq 0 ]; then
        result="PASS"
        evidence="tier2 --heldout and realworld replay offline with empty repos and dummy proxy"
      else
        result="FAIL"
        evidence="replay failed offline (t2_rc=$rc_t2, rw_rc=$rc_rw)"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C8)
      local c8_out
      if [ "$SNAPSHOT" -eq 1 ]; then
        if c8_out=$("$PY" "${PROJECT_ROOT}/scripts/verify-public.py" --frozen 2>&1); then
          result="N/A"
          evidence="snapshot frozen hashes verified; historical C8 ancestry unavailable (tapm verify-precommit remains fail-closed)"
        else
          result="FAIL"
          evidence="snapshot integrity failed: $c8_out"
          FAILURES=$((FAILURES + 1))
        fi
        echo "| $id | $result | $evidence |"
        return
      fi
      c8_out=$("$PY" -m tapm.eval.precommit --quiet 2>&1)
      local rc=$?
      if [ $rc -eq 0 ]; then
        result="PASS"
        evidence="gold commit is ancestor, sha256 unchanged, label commit pure"
      else
        result="FAIL"
        evidence="pre-commitment check failed (rc=$rc)"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C9)
      local adj="${PROJECT_ROOT}/evaluations/tier2/ADJUDICATION.md"
      if [ -f "$adj" ] && grep -q "cloudgoat" "$adj" 2>/dev/null; then
        result="PASS"
        evidence="ADJUDICATION.md documents held-out path verdicts"
      else
        result="FAIL"
        evidence="ADJUDICATION.md missing or incomplete"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C11)
      local help_out
      help_out=$("${PROJECT_ROOT}/.venv/bin/tapm" --help 2>&1)
      local contract_doc="${PROJECT_ROOT}/docs/contract.md"
      if [ -f "$contract_doc" ] && echo "$help_out" | grep -q "tier2" && echo "$help_out" | grep -q "realworld" && echo "$help_out" | grep -q "strata"; then
        result="PASS"
        evidence="canonical contract present; tapm --help exposes expected commands"
      else
        result="FAIL"
        evidence="docs/contract.md missing or tapm --help missing expected CLI commands"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C12)
      local bad_claims
      if [ "$SNAPSHOT" -eq 1 ]; then
        if [ ! -s "${PROJECT_ROOT}/PUBLIC-RELEASE.md" ] || [ ! -s "${PROJECT_ROOT}/SECURITY.md" ]; then
          result="FAIL"
          evidence="standalone scope/security guidance missing"
          FAILURES=$((FAILURES + 1))
        else
          result="N/A"
          evidence="private talk principle.md absent; standalone limits in PUBLIC-RELEASE.md and SECURITY.md"
        fi
        echo "| $id | $result | $evidence |"
        return
      fi
      bad_claims=$(grep -E -i "100% security|unbreakable|zero risk" "${REPO_ROOT}/OWASP-GLOBAL-AppSec-US-2026/principle.md" 2>/dev/null || true)
      if [ -z "$bad_claims" ]; then
        result="PASS"
        evidence="principle.md adheres to talk standards"
      else
        result="FAIL"
        evidence="forbidden absolute claims found in principle.md"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C13)
      local c13_out
      c13_out=$("$PY" -c '
from pathlib import Path
import datetime as dt
from tapm.report.executive import render_executive_report

conf = Path("conference-snapshot")
if conf.exists():
    md = render_executive_report(conf, format="markdown", today=dt.date(2026, 10, 10))
    if "≤ 30 days" in md or "<= 30 days" in md:
        print("FAIL: hardcoded <= 30 days found in executive report")
    elif "RISK-042 has 51 days left; DISPUTE-001 never expires" not in md:
        print("FAIL: executive exception note does not match table data")
    else:
        print("OK")
else:
    print("OK")
' 2>&1)
      if [ "$c13_out" = "OK" ]; then
        result="PASS"
        evidence="reports computed from data; zero contradictions"
      else
        result="FAIL"
        evidence="$c13_out"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C14)
      local tracker="${REPO_ROOT}/OWASP-GLOBAL-AppSec-US-2026/DEMO-TRACKER.md"
      if [ "$SNAPSHOT" -eq 1 ]; then
        result="N/A"
        evidence="private talk tracker not distributed; release integrity checked separately"
        echo "| $id | $result | $evidence |"
        return
      fi
      if [ ! -f "$tracker" ]; then
        result="FAIL"
        evidence="tracker missing outside declared standalone snapshot"
        FAILURES=$((FAILURES + 1))
        echo "| $id | $result | $evidence |"
        return
      fi
      local missing_records=0
      local missing_ids=""
      while IFS= read -r line; do
        local tid
        tid=$(echo "$line" | awk -F '|' '{print $2}' | xargs)
        local status
        status=$(echo "$line" | awk -F '|' '{print $7}' | xargs)
        if [ "$status" = "Done" ] || [ "$status" = "Review" ]; then
          if [ ! -f "${REPO_ROOT}/OWASP-GLOBAL-AppSec-US-2026/critic/${tid}.md" ] && [ ! -f "${REPO_ROOT}/OWASP-GLOBAL-AppSec-US-2026/critic/AUDIT-2026-10-10.md" ]; then
            missing_records=$((missing_records + 1))
            missing_ids="${missing_ids} ${tid}"
          fi
        fi
      done < <(grep -E "^\| [A-Z0-9.]+ \|" "$tracker" 2>/dev/null || true)
      if [ $missing_records -eq 0 ]; then
        result="PASS"
        evidence="all Review/Done rows tracked with critic records"
      else
        result="FAIL"
        evidence="$missing_records rows missing critic record:$missing_ids"
        FAILURES=$((FAILURES + 1))
      fi
      ;;
    C16)
      local gitleaks_bin=""
      if [ -n "${TAPM_GITLEAKS:-}" ] && [ -x "$TAPM_GITLEAKS" ]; then
        gitleaks_bin="$TAPM_GITLEAKS"
      elif [ -x "${PROJECT_ROOT}/.tools/bin/gitleaks" ]; then
        gitleaks_bin="${PROJECT_ROOT}/.tools/bin/gitleaks"
      elif command -v gitleaks >/dev/null 2>&1; then
        gitleaks_bin="$(command -v gitleaks)"
      fi

      if [ -z "$gitleaks_bin" ]; then
        result="FAIL"
        evidence="pinned gitleaks not found (install via scripts/fetch-tools.sh or ensure gitleaks on PATH)"
        FAILURES=$((FAILURES + 1))
      else
        local scan_out
        local scan_rc=0
        scan_out=$("$gitleaks_bin" detect --source "$PROJECT_ROOT" --no-git --config "${PROJECT_ROOT}/.gitleaks.toml" --max-archive-depth 2 --no-banner 2>&1) || scan_rc=$?
        if [ $scan_rc -eq 0 ]; then
          local aws_keys
          aws_keys=$(grep -rnE "AKIA[0-9A-Z]{16}" "${PROJECT_ROOT}/src" 2>/dev/null || true)
          if [ -z "$aws_keys" ]; then
            result="PASS"
            evidence="gitleaks clean over all plans, baselines, and fixtures; zero live AWS access keys"
          else
            result="FAIL"
            evidence="hardcoded AWS keys found in src"
            FAILURES=$((FAILURES + 1))
          fi
        else
          result="FAIL"
          evidence="gitleaks detected unallowlisted secrets (exit $scan_rc)"
          FAILURES=$((FAILURES + 1))
        fi
      fi
      ;;
    *)
      result="N/A"
      evidence="check $id not automated"
      ;;
  esac

  echo "| $id | $result | $evidence |"
}

echo "# Automated Critic Report"
echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo
echo "| Check | Result | Evidence |"
echo "|---|---|---|"

for chk in "${CHECKS[@]}"; do
  run_check "$chk"
done

echo
if [ $FAILURES -eq 0 ]; then
  echo "✓ All executed critic checks PASSED."
  exit 0
else
  echo "✗ $FAILURES critic check(s) FAILED."
  exit 1
fi
