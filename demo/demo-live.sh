#!/usr/bin/env bash
# ==============================================================================
# demo-live.sh - OWASP Global AppSec 2026 Live Demo Runbook Script (Task W5.1)
#
# Woven four-part conference presentation demo:
#   Part 1 (Slide 5,  02:15-05:30): PR #42 opens, 3 one-line diffs, 40 scanner findings
#   Part 2 (Slide 11,  13:40-17:25): Deterministic attack path, PyTM model, DFD, questions
#   Part 3 recorded on stage (Slide 14, 21:00-24:15): Bounded AI enrichment, evidence tampering, prompt injection
#   Part 4 (Slide 16, 26:15-29:00): Blocked CI gate (level: validate), proven fix, green check
#   Part 5 (Slide 17, optional):    Scalability on complex architecture (IAM-Vulnerable)
#
# Usage:
#   bash demo/demo-live.sh [OPTIONS]
#   make demo-live [AUTO=1] [RESET=1] [BEAT=N] [LLM=ollama|simulated]
#
# Options:
#   --auto, --non-interactive  Run all beats continuously without pausing for input
#   --reset                    Reset local Gitea demo repository and state before running
#   --beat N                   Jump directly to a specific beat (1..10)
#   --llm BACKEND              AI backend: 'ollama' (default; fails if unavailable) or 'simulated'
#   --model NAME               Model name for Ollama (default: qwen3-coder:30b)
#   --gitea-url URL            Gitea endpoint (default: http://localhost:3000)
#   --service-url URL          TAPM analysis service endpoint (default: http://localhost:8080)
#   --ollama-url URL           Ollama endpoint (default: http://localhost:11434)
#   -h, --help                 Show this help message
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_BIN="${PROJECT_ROOT}/.venv/bin"
TAPM="${VENV_BIN}/tapm"
LOCAL_STACK_DIR="${PROJECT_ROOT}/examples/local-stack"
FIXTURE="006"
INJECT_FIXTURE="019"
ART_DIR="${TAPM_DEMO_ART_DIR:-${PROJECT_ROOT}/artifacts/006-public-workload-iam-sensitive-bucket}"

# Defaults
INTERACTIVE=true
DO_RESET=false
START_BEAT=1
SINGLE_BEAT=0
LLM_BACKEND=""
MODEL_NAME="qwen3-coder:30b"
GITEA_URL="${GITEA_URL:-http://localhost:3000}"
SERVICE_URL="${SERVICE_URL:-http://localhost:8080}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
GITEA_ORG="demo-org"
GITEA_REPO="infra-demo"
GITEA_ADMIN_USER="tapm-admin"
GITEA_ADMIN_PASS="tapm-admin-pass123"

# Styling & Colors (disabled if NO_COLOR is set or non-tty)
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="\033[1m"
  DIM="\033[2m"
  CYAN="\033[36m"
  GREEN="\033[32m"
  YELLOW="\033[33m"
  RED="\033[31m"
  MAGENTA="\033[35m"
  BLUE="\033[34m"
  RESET="\033[0m"
else
  BOLD=""
  DIM=""
  CYAN=""
  GREEN=""
  YELLOW=""
  RED=""
  MAGENTA=""
  BLUE=""
  RESET=""
fi

usage() {
  cat << EOF
OWASP Global AppSec 2026 — Live Demo Runbook (make demo-live)

Usage:
  bash demo/demo-live.sh [OPTIONS]

Options:
  --auto, --non-interactive  Run without pausing between beats (for CI / automation)
  --reset                    Reset local Gitea demo repository and state before running
  --beat N                   Execute only beat N (1..10)
  --from-beat N              Start execution from beat N (1..10)
  --llm BACKEND              AI backend: 'ollama' (default; fails if unavailable) or 'simulated'
  --model NAME               Model name for Ollama (default: qwen3-coder:30b)
  --gitea-url URL            Gitea endpoint (default: http://localhost:3000)
  --service-url URL          TAPM analysis service endpoint (default: http://localhost:8080)
  --ollama-url URL           Ollama endpoint (default: http://localhost:11434)
  -h, --help                 Show this help message
EOF
  exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto|--non-interactive)
      INTERACTIVE=false
      shift
      ;;
    --reset)
      DO_RESET=true
      shift
      ;;
    --beat)
      SINGLE_BEAT="$2"
      START_BEAT="$2"
      shift 2
      ;;
    --from-beat)
      START_BEAT="$2"
      shift 2
      ;;
    --llm)
      LLM_BACKEND="$2"
      shift 2
      ;;
    --model)
      MODEL_NAME="$2"
      shift 2
      ;;
    --gitea-url)
      GITEA_URL="$2"
      shift 2
      ;;
    --service-url)
      SERVICE_URL="$2"
      shift 2
      ;;
    --ollama-url)
      OLLAMA_URL="$2"
      shift 2
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

# Pacing prompt helper
pause_for_cue() {
  local next_beat_desc="$1"
  if [ "$INTERACTIVE" = true ]; then
    echo
    echo -e "${DIM}--------------------------------------------------------------------------------${RESET}"
    echo -e "${YELLOW}>> Ready for next beat:${RESET} ${BOLD}${next_beat_desc}${RESET}"
    echo -e "${DIM}   [Press ENTER to continue, or 'q' to exit]${RESET} "
    read -r user_input || true
    if [ "$user_input" = "q" ] || [ "$user_input" = "Q" ]; then
      echo -e "${CYAN}Live demo runbook paused by speaker.${RESET}"
      exit 0
    fi
    echo
  else
    echo
    echo -e "${DIM}--------------------------------------------------------------------------------${RESET}"
  fi
}

# Header banner helper
print_beat_header() {
  local part_num="$1"
  local beat_num="$2"
  local slide_num="$3"
  local time_slot="$4"
  local title="$5"
  local what_it_proves="$6"

  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}${BOLD}║  LIVE ${part_num}/4 · BEAT ${beat_num}/10 · SLIDE ${slide_num} (${time_slot})                        ║${RESET}"
  echo -e "${CYAN}${BOLD}║  ${BOLD}${title}${RESET}"
  echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
  echo -e "${CYAN}${BOLD}║${RESET} ${DIM}What it proves:${RESET} ${what_it_proves}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
  echo
}

# Speaker cue display helper
print_speaker_cue() {
  local cue_text="$1"
  local direction="${2:-}"
  echo
  echo -e "${MAGENTA}${BOLD}┌── 🎙️  SPEAKER CUE (Slide delivery) ──────────────────────────────────────────┐${RESET}"
  if [ -n "$direction" ]; then
    echo -e "${MAGENTA}${BOLD}│${RESET} ${DIM}Stage direction:${RESET} ${YELLOW}${direction}${RESET}"
  fi
  echo -e "${MAGENTA}${BOLD}│${RESET} ${BOLD}\"${cue_text}\"${RESET}"
  echo -e "${MAGENTA}${BOLD}└───────────────────────────────────────────────────────────────────────────────┘${RESET}"
  echo
}

# Timing trackers (indexed arrays for bash 3.2 macOS compatibility)
declare -a BEAT_START_TIMES=()
declare -a BEAT_DURATIONS=()

start_beat_timer() {
  local b="$1"
  BEAT_START_TIMES["$b"]=$(date +%s)
}

stop_beat_timer() {
  local b="$1"
  local start="${BEAT_START_TIMES[$b]:-}"
  if [ -n "$start" ]; then
    local now
    now=$(date +%s)
    local dur=$((now - start))
    BEAT_DURATIONS["$b"]=$dur
  fi
}

# ------------------------------------------------------------------------------
# Pre-Flight State Verification & Diagnostics
# ------------------------------------------------------------------------------
echo -e "${BOLD}================================================================================${RESET}"
echo -e "${BOLD} OWASP Global AppSec 2026 — Live Demo Runbook (${CYAN}make demo-live${RESET}${BOLD})${RESET}"
echo -e "${BOLD} Target: Local Stack (Gitea + Runner + TAPM Service) + Local Model${RESET}"
echo -e "${BOLD}================================================================================${RESET}"
echo

echo -e "${BOLD}Checking environment and service connectivity...${RESET}"

GITEA_OK=false
if curl --connect-timeout 2 --max-time 10 -sf "${GITEA_URL}/api/v1/version" >/dev/null 2>&1; then
  GITEA_VERSION=$(curl --connect-timeout 2 --max-time 10 -sf "${GITEA_URL}/api/v1/version" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*' | cut -d'"' -f4 || echo "1.22.0")
  echo -e "  [✓] Gitea:        ${GREEN}Connected${RESET} at ${GITEA_URL} (v${GITEA_VERSION})"
  GITEA_OK=true
else
  echo -e "  [!] Gitea:        ${YELLOW}Not reachable${RESET} at ${GITEA_URL} (terminal fallback active)"
fi

SERVICE_OK=false
if curl --connect-timeout 2 --max-time 10 -sf "${SERVICE_URL}/health" >/dev/null 2>&1; then
  echo -e "  [✓] TAPM Service: ${GREEN}Connected${RESET} at ${SERVICE_URL} (/health ok)"
  SERVICE_OK=true
else
  echo -e "  [!] TAPM Service: ${YELLOW}Not reachable${RESET} at ${SERVICE_URL} (terminal fallback active)"
fi

LLM_BACKEND="${LLM_BACKEND:-ollama}"
case "$LLM_BACKEND" in
  ollama|simulated) ;;
  *) echo "Unsupported AI backend: $LLM_BACKEND" >&2; exit 2 ;;
esac
echo "  [i] AI backend: $LLM_BACKEND (no automatic substitution)"
# Only AI beats require a model. Non-AI beats remain usable offline.
if [ "$LLM_BACKEND" = ollama ] && { [ "$SINGLE_BEAT" = 5 ] || [ "$SINGLE_BEAT" = 7 ] || { [ "$SINGLE_BEAT" = 0 ] && [ "$START_BEAT" -le 7 ]; }; }; then
  TAGS=$(curl --connect-timeout 2 --max-time 10 -fsS "${OLLAMA_URL}/api/tags") || {
    echo "Local model unavailable. Start the pinned local model or play the recorded run." >&2
    exit 2
  }
  printf '%s' "$TAGS" | "${VENV_BIN}/python" -c 'import json,sys; names=[m["name"] for m in json.load(sys.stdin)["models"]]; sys.exit(0 if sys.argv[1] in names else 1)' "$MODEL_NAME" || {
    echo "Selected local model is not installed. Play the recorded run." >&2
    exit 2
  }
fi
export GITEA_URL GITEA_ADMIN_USER GITEA_ADMIN_PASS
export OLLAMA_HOST="$OLLAMA_URL"
gitea_state() { "${VENV_BIN}/python" "${SCRIPT_DIR}/gitea_state.py" "$@"; }

if command -v docker >/dev/null 2>&1 && [ -f "${LOCAL_STACK_DIR}/compose.yaml" ]; then
  RUNNER_STATUS=$(docker compose -f "${LOCAL_STACK_DIR}/compose.yaml" ps runner 2>/dev/null || echo "")
  if [[ "$RUNNER_STATUS" =~ "Up" ]]; then
    echo -e "  [✓] Actions Runner: ${GREEN}Active${RESET} (tapm-runner running)"
  else
    echo -e "  [!] Actions Runner: ${YELLOW}Not running in Compose${RESET}"
  fi
fi

echo

# ------------------------------------------------------------------------------
# Optional Demo State Reset
# ------------------------------------------------------------------------------
if [ "$DO_RESET" = true ]; then
  echo -e "${YELLOW}${BOLD}Resetting demo repository and stack state (--reset)...${RESET}"
  if [ "$GITEA_OK" = true ]; then
    AUTH_BASIC=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}" | base64)
    # 2. Re-seed demo branches from bundle
    if [ -f "${LOCAL_STACK_DIR}/seed-demo-repo.sh" ]; then
      GITEA_PUSH_URL=$("${VENV_BIN}/python" -c 'import os,urllib.parse; u=urllib.parse.urlsplit(os.environ["GITEA_URL"]); a=urllib.parse.quote(os.environ["GITEA_ADMIN_USER"],safe="")+":"+urllib.parse.quote(os.environ["GITEA_ADMIN_PASS"],safe=""); print(urllib.parse.urlunsplit((u.scheme,a+"@"+u.netloc,u.path.rstrip("/")+"/demo-org/infra-demo.git","","")))')
      echo "  -> Re-seeding canonical branches (main, pr-42, fix, injection)..."
      bash "${LOCAL_STACK_DIR}/seed-demo-repo.sh" --push "$GITEA_PUSH_URL" --quiet
    fi
    # Collect all pages before closing PRs; closing while paging skips entries.
    PR_NUMS=""
    page=1
    while :; do
      OPEN_PRS=$(curl --connect-timeout 2 --max-time 10 -fsS "${GITEA_URL}/api/v1/repos/${GITEA_ORG}/${GITEA_REPO}/pulls?state=open&limit=50&page=$page" \
        -H "Authorization: Basic ${AUTH_BASIC}")
      PAGE_NUMS=$("${VENV_BIN}/python" -c '
import sys,json
prs=json.load(sys.stdin)
if not isinstance(prs,list): sys.exit("Invalid Gitea PR list")
for p in prs:
    if p["head"]["ref"] in {"pr-42","fix","injection"} and p["head"].get("repo",{}).get("full_name")=="demo-org/infra-demo" and p["base"]["ref"]=="main":
        print(int(p["number"]))
' <<< "$OPEN_PRS")
      PR_NUMS="$PR_NUMS $PAGE_NUMS"
      count=$("${VENV_BIN}/python" -c 'import sys,json; print(len(json.load(sys.stdin)))' <<< "$OPEN_PRS")
      [ "$count" -lt 50 ] && break
      page=$((page+1))
    done
    for pr_num in $PR_NUMS; do
      echo "  -> Closing open PR #${pr_num}..."
      curl --connect-timeout 2 --max-time 10 -fsS -X PATCH "${GITEA_URL}/api/v1/repos/${GITEA_ORG}/${GITEA_REPO}/pulls/${pr_num}" \
        -H "Authorization: Basic ${AUTH_BASIC}" \
        -H "Content-Type: application/json" \
        -d '{"state": "closed"}' >/dev/null
    done


  fi
  # Clean artifacts directory
  rm -rf "$ART_DIR"
  mkdir -p "$ART_DIR"
  echo -e "${GREEN}State reset complete. Ready for clean presentation.${RESET}"
  echo
fi

# Ensure artifact directory exists
mkdir -p "$ART_DIR"

should_run() {
  local beat="$1"
  if [ "$SINGLE_BEAT" -gt 0 ]; then
    [ "$SINGLE_BEAT" -eq "$beat" ]
  else
    [ "$beat" -ge "$START_BEAT" ]
  fi
}

# ==============================================================================
# LIVE 1/4: THE FAILURE (Slide 5 · 02:15 → 05:30)
# ==============================================================================

# ------------------------------------------------------------------------------
# BEAT 1: The Pull Request
# ------------------------------------------------------------------------------
if should_run 1; then
  start_beat_timer 1
  print_beat_header "1" "1" "5" "02:15-05:30" \
    "Pull Request #42: Three one-line changes across network, compute, and IAM" \
    "A normal, plausible pull request in a normal CI pipeline."

  echo -e "${BOLD}Action:${RESET} Opening PR #42 in local Git server (or inspecting existing PR #42)..."
  if [ "$GITEA_OK" = true ]; then
    GITEA_URL="$GITEA_URL" bash "${LOCAL_STACK_DIR}/open-pr.sh" --branch pr-42
    gitea_state url pr-42
  else
    echo "Local Git server not reachable; inspecting committed PR #42 diff."
  fi

  echo
  echo -e "${BOLD}Terminal PR Diff:${RESET}"
  bash "${PROJECT_ROOT}/scripts/pr-diff.sh"

  print_speaker_cue \
    "Three one-line changes. A reviewer would approve each of these on its own." \
    "Click 1: Show the three lines. Gesture left to right: open ALB, relax IMDS, widen S3 read."

  stop_beat_timer 1
  pause_for_cue "Beat 2: Scanners Output (40 isolated findings)"
fi

# ------------------------------------------------------------------------------
# BEAT 2: What Current Scanners Say
# ------------------------------------------------------------------------------
if should_run 2; then
  start_beat_timer 2
  print_beat_header "1" "2" "5" "02:15-05:30" \
    "Saved scanner baselines: Checkov, tfsec and Trivy" \
    "The saved comparison contains 40 findings; this command replays those baselines."

  echo -e "${BOLD}Action:${RESET} Evaluating baseline static scanner outputs on PR #42..."
  "$TAPM" scan "$FIXTURE"

  print_speaker_cue \
    "Saved baselines from the pinned versions, so this is the real output. Which of these belong to the same attack story?" \
    "Click 2: The 40 findings, then the red 0 attack paths. Pause for two full seconds."

  stop_beat_timer 2
  pause_for_cue "Beat 3: Live 2/4 Control — The Attack Path & Developer PR Comment (Slide 11)"
fi

# ==============================================================================
# LIVE 2/4: THE CONTROL (Slide 11 · 13:40 → 17:25)
# ==============================================================================

# ------------------------------------------------------------------------------
# BEAT 3: The Attack Path & Developer PR Comment
# ------------------------------------------------------------------------------
if should_run 3; then
  start_beat_timer 3
  print_beat_header "2" "3" "11" "13:40-17:25" \
    "Deterministic Attack Path: From 40 isolated findings to 1 coherent path" \
    "Deterministic engine derives causal chain with file:line evidence on every hop."

  echo -e "${BOLD}Action:${RESET} Computing attack path for PR #42 (graph + IAM evaluator + path engine)..."
  "$TAPM" paths "$FIXTURE"

  # Display live Gitea PR comment excerpt if available
  if [ "$GITEA_OK" = true ]; then
    echo
    echo -e "${BOLD}Live Gitea PR Comment (First Screen):${RESET}"
    gitea_state comments pr-42
  fi

  print_speaker_cue \
    "Forty findings, one path. Every hop has a file and line. One hop is an assumption, and it's labeled. And these fixes aren't suggestions from a model: the engine re-ran itself with each change. IMDSv2 alone only downgrades the path. Scoping the policy breaks it." \
    "In the PR comment, point at the ASSUMPTION hop and say the word 'labeled'. Then show the single path on the slide."

  stop_beat_timer 3
  pause_for_cue "Beat 4: PyTM Model, IAM Graph, and Plain Words Story (Slide 11)"
fi

# ------------------------------------------------------------------------------
# BEAT 4: PyTM Model, IAM Inference & App Team Questions
# ------------------------------------------------------------------------------
if should_run 4; then
  start_beat_timer 4
  print_beat_header "2" "4" "11" "13:40-17:25" \
    "AppSec View: Executable PyTM model, inferred IAM dataflows, and DFD" \
    "PyTM model is compiled from plan evidence: 8 decided from plan evidence, 110 open questions, 12 ruled out."

  echo -e "${BOLD}Action 1:${RESET} PyTM Model and IAM policy evaluation..."
  "$TAPM" model "$FIXTURE"

  echo
  echo -e "${BOLD}Action 2:${RESET} The same path in plain words (for everyone on the team)..."
  "$TAPM" story "$FIXTURE" --audience everyone -n 1

  echo
  echo -e "${BOLD}Action 3:${RESET} Six questions for the application team..."
  "$TAPM" ask "$FIXTURE"

  if [ -f "${ART_DIR}/dfd.png" ]; then
    echo
    echo -e "  ${GREEN}[✓] Data Flow Diagram (DFD):${RESET} ${ART_DIR}/dfd.png"
  fi

  print_speaker_cue \
    "Twenty-nine edges come from Terraform references. These two come from evaluating the policy. The PyTM model it compiled to is fed with the plan: 8 threats are decided by evidence, one on every hop, and 110 are questions for the app team. And this is the model as a diagram. Nobody answers 110 questions. These six settle 34. The answers go next to the Terraform, reviewed like code, and they can't change a path." \
    "Switch to Screen 3 (Report + DFD) for 15 seconds. Trace the two arrows into the S3 bucket."

  stop_beat_timer 4
  pause_for_cue "Beat 5: Live 3/4 AI on a Leash — Bounded AI Enrichment (Slide 14)"
fi

# ==============================================================================
# REHEARSAL ONLY 3/4: AI ON A LEASH (Slide 14 · 21:00 → 24:15)
# ==============================================================================

# ------------------------------------------------------------------------------
# BEAT 5: Bounded AI Enrichment
# ------------------------------------------------------------------------------
if should_run 5; then
  start_beat_timer 5
  print_beat_header "3" "5" "14" "21:00-24:15" \
    "AI Enrichment: Jev picks the roles for this path; zero tools; a validator decides" \
    "Code computes the path; AI proposes annotations; independent checks enforce the output contract."

  echo -e "${BOLD}Action:${RESET} Running AI enrichment plane (backend: ${BOLD}${LLM_BACKEND}${RESET})..."
  if [ "$LLM_BACKEND" = "ollama" ]; then
    "$TAPM" explain "$FIXTURE" --llm ollama --model "$MODEL_NAME" --jev local
  else
    "$TAPM" explain "$FIXTURE" --llm simulated --jev local
  fi

  print_speaker_cue \
    "Jev decided how AI may participate. It didn't decide whether the path is real. Every annotation lists the evidence it rests on. Real AI tooling, bounded: no tools, evidence-cited, validated." \
    "Point at the Jev decision block. Point at the evidence line under each accepted annotation."

  stop_beat_timer 5
  pause_for_cue "Beat 6: Tamper Test (Removing Evidence Rejects Finding)"
fi

# ------------------------------------------------------------------------------
# BEAT 6: Tamper Test
# ------------------------------------------------------------------------------
if should_run 6; then
  start_beat_timer 6
  print_beat_header "3" "6" "14" "21:00-24:15" \
    "Tamper Resistance: Stripping evidence references causes validator rejection" \
    "The validator, not the model, determines what is permitted to be published."

  echo -e "${BOLD}Action:${RESET} Tampering with accepted annotation by stripping evidence citations..."
  "$TAPM" tamper --artifacts "$ART_DIR"

  print_speaker_cue \
    "Same sentence. Take away the evidence and it isn't a finding any more. The validator, not the model, decides what's published." \
    "Show the REJECTED status with 'evidence_present: annotation cites no evidence'."

  stop_beat_timer 6
  pause_for_cue "Beat 7: Prompt Injection Defense (Slide 14)"
fi

# ------------------------------------------------------------------------------
# BEAT 7: Prompt Injection Defense
# ------------------------------------------------------------------------------
if should_run 7; then
  start_beat_timer 7
  print_beat_header "3" "7" "14" "21:00-24:15" \
    "Prompt Injection Defense: Malicious Terraform comments cannot alter CI verdict" \
    "Comments are excluded from the default evidence bundle; the computed paths remain unchanged."

  echo -e "${BOLD}Action:${RESET} Testing prompt injection defense with adversarial comments (fixture ${INJECT_FIXTURE})..."
  if [ "$LLM_BACKEND" = "ollama" ]; then
    "$TAPM" inject "$INJECT_FIXTURE" --llm ollama --model "$MODEL_NAME" --jev local
  else
    "$TAPM" inject "$INJECT_FIXTURE" --llm simulated --jev local
  fi

  if [ "$LLM_BACKEND" = "ollama" ]; then
    print_speaker_cue \
      "Unsafe: raw Terraform, comments and all, straight to the model. Read its verdict: it calls this setup secure, on a plan with a path from the internet to customer data. It still mentions IAM, so it didn't simply obey the comments: the naive reviewer is the problem, comments or not. Safe: the comments never reach the model, and the validator still rejects what the evidence doesn't back. Stress test: hand it the comments as untrusted data; nothing it says changes the path. Last line: the path is identical with every comment stripped. The model was never responsible for deciding whether the path existed." \
      "Read the UNSAFE verdict aloud. Then point at the word 'identical' and pause two seconds. The 10-run numbers are on the slide."
  else
    print_speaker_cue \
      "Unsafe, with a stand-in model built to obey instructions: the comment wins. Safe: the model never sees it. Stress test: we hand it the comments, it obeys, and the validator rejects it. Last line: the path is byte-identical with every comment stripped. The model was never responsible for deciding whether the path existed." \
      "Say it is the simulated stand-in. Point at the word 'identical' on the slide, and pause two seconds."
  fi

  stop_beat_timer 7
  pause_for_cue "Beat 8: Live 4/4 CI/CD Output — The Blocked Gate (Slide 16)"
fi

# ==============================================================================
# LIVE 4/4: CI/CD OUTPUT (Slide 16 · 26:15 → 29:00)
# ==============================================================================

# ------------------------------------------------------------------------------
# BEAT 8: The Blocked Gate
# ------------------------------------------------------------------------------
if should_run 8; then
  start_beat_timer 8
  print_beat_header "4" "8" "16" "26:15-29:00" \
    "CI/CD Gate at Level 3 (Validate): Required check blocks PR merge" \
    "Check turns red; PR merge is blocked; developer provided two clear ways out."

  echo -e "${BOLD}Action 1:${RESET} Checking Gitea required commit status on PR #42..."
  if [ "$GITEA_OK" = true ]; then
    gitea_state status pr-42 --wait 120 --expect failure
  fi

  echo
  echo -e "${BOLD}Action 2:${RESET} Local CLI gate evaluation (level: validate)..."
  "$TAPM" gate "$ART_DIR" --level validate || echo "  exit $?: this is how CI blocks the merge"

  print_speaker_cue \
    "Level three, validate. One path at or above high, no decision. Blocked. Two ways out: fix it, or accept it with an owner, a reason and an expiry." \
    "Point at BLOCKED on the screen. Let the red color do the work."

  stop_beat_timer 8
  pause_for_cue "Beat 9: Least-Invasive Remediation & Proven Fix Pass (Slide 16)"
fi

# ------------------------------------------------------------------------------
# BEAT 9: Least-Invasive Remediation & Proven Fix
# ------------------------------------------------------------------------------
if should_run 9; then
  start_beat_timer 9
  print_beat_header "4" "9" "16" "26:15-29:00" \
    "Least-Invasive Remediation: AI proposes fix; pipeline proves it before merge" \
    "Resource scoping re-plans with 0 paths; PR fix check turns green."

  echo -e "${BOLD}Action 1:${RESET} Patch author proposes candidate fixes; the engine re-plans each one..."
  "$TAPM" remediate "$FIXTURE"

  echo
  echo -e "${BOLD}Action 2:${RESET} Opening / inspecting PR with the verified fix ('fix' branch)..."
  if [ "$GITEA_OK" = true ]; then
    GITEA_URL="$GITEA_URL" bash "${LOCAL_STACK_DIR}/open-pr.sh" --branch fix
    gitea_state url fix
    echo "Waiting for the required check on the newest open fix PR..."
    gitea_state status fix --wait 120 --expect success
  fi

  echo
  echo -e "${BOLD}Action 3:${RESET} Replaying fixed PR through the gate check..."
  TAPM="$TAPM" bash "${PROJECT_ROOT}/scripts/replay-fixed.sh"

  print_speaker_cue \
    "Two candidate patches. Each was applied to a copy, re-planned and run through everything again. In this re-plan, IMDSv2 downgrades the modeled path. Scoping the grant removes it, and pytm agrees: its grant threats are gone. Nothing was applied. That diff is for a human. Same PR, verified fix applied, same check: Zero paths. Pass. Same scenario, run twice: the second time the pipeline caught it, proved the fix and got out of the way." \
    "Point at PASS on the screen. Let the green color do the work."

  stop_beat_timer 9
  pause_for_cue "Beat 10 (Optional): Complex Architecture Scale Test (Slide 17)"
fi

# ------------------------------------------------------------------------------
# BEAT 10: Optional Scalability Test (Slide 17)
# ------------------------------------------------------------------------------
if should_run 10; then
  start_beat_timer 10
  print_beat_header "5" "10" "17" "29:00-31:30" \
    "Scalability: Complex architecture benchmark (IAM-Vulnerable)" \
    "Measures current deterministic engine output on a larger public example."

  echo -e "${BOLD}Action:${RESET} Evaluating complex fixture (IAM-Vulnerable)..."
  "$TAPM" tier2 iam-vulnerable --llm off

  print_speaker_cue \
    "This is the current measured run. Read the emitted path count and runtime above; the saved benchmark is a historical run." \
    "Do not substitute the saved run's count or runtime for this run."

  stop_beat_timer 10
fi

echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD} ✓ LIVE DEMO RUNBOOK COMPLETE${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════════${RESET}"

# Print execution timing summary if beats were executed
if [ ${#BEAT_DURATIONS[@]} -gt 0 ]; then
  S3_DUR=$(( ${BEAT_DURATIONS[1]:-0} + ${BEAT_DURATIONS[2]:-0} ))
  S8_DUR=$(( ${BEAT_DURATIONS[3]:-0} + ${BEAT_DURATIONS[4]:-0} ))
  S11_DUR=$(( ${BEAT_DURATIONS[5]:-0} + ${BEAT_DURATIONS[6]:-0} + ${BEAT_DURATIONS[7]:-0} ))
  S13_DUR=$(( ${BEAT_DURATIONS[8]:-0} + ${BEAT_DURATIONS[9]:-0} ))
  S14_DUR=$(( ${BEAT_DURATIONS[10]:-0} ))
  TOTAL_LIVE=$(( S3_DUR + S8_DUR + S11_DUR + S13_DUR + S14_DUR ))

  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}${BOLD}║  REHEARSAL EXECUTION TIMING SUMMARY (R2)                                     ║${RESET}"
  echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
  for b in 1 2 3 4 5 6 7 8 9 10; do
    if [ -n "${BEAT_DURATIONS[$b]:-}" ]; then
      printf "${CYAN}${BOLD}║${RESET}  Beat %2d: %3ds\n" "$b" "${BEAT_DURATIONS[$b]}"
    fi
  done
  echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
  echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}Terminal Live Time by Slide:${RESET}"
  printf "${CYAN}${BOLD}║${RESET}    Slide 5  (Live 1/4 · Failure):    %3ds (Beats 1 & 2)\n" "$S3_DUR"
  printf "${CYAN}${BOLD}║${RESET}    Slide 11  (Live 2/4 · Control):    %3ds (Beats 3 & 4)\n" "$S8_DUR"
  printf "${CYAN}${BOLD}║${RESET}    Slide 14 (Live 3/4 · AI Leash):   %3ds (Beats 5, 6, 7)\n" "$S11_DUR"
  printf "${CYAN}${BOLD}║${RESET}    Slide 16 (Live 4/4 · Gate/Fix):   %3ds (Beats 8 & 9)\n" "$S13_DUR"
  if [ -n "${BEAT_DURATIONS[10]:-}" ]; then
    printf "${CYAN}${BOLD}║${RESET}    Slide 17 (Optional Scale):        %3ds (Beat 10)\n" "$S14_DUR"
  fi
  printf "${CYAN}${BOLD}║${RESET}  ${BOLD}Total Terminal Execution Time:${RESET}      %3ds (%d:%02d)\n" "$TOTAL_LIVE" "$((TOTAL_LIVE / 60))" "$((TOTAL_LIVE % 60))"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
  echo

  # Write timing JSON artifact
  cat << JSON_EOF > "${ART_DIR}/rehearsal-timings.json"
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "measurement": "terminal_execution_only",
  "spoken_rehearsal": false,
  "beats": {
    "1": ${BEAT_DURATIONS[1]:-0},
    "2": ${BEAT_DURATIONS[2]:-0},
    "3": ${BEAT_DURATIONS[3]:-0},
    "4": ${BEAT_DURATIONS[4]:-0},
    "5": ${BEAT_DURATIONS[5]:-0},
    "6": ${BEAT_DURATIONS[6]:-0},
    "7": ${BEAT_DURATIONS[7]:-0},
    "8": ${BEAT_DURATIONS[8]:-0},
    "9": ${BEAT_DURATIONS[9]:-0},
    "10": ${BEAT_DURATIONS[10]:-0}
  },
  "slides": {
    "3": $S3_DUR,
    "8": $S8_DUR,
    "11": $S11_DUR,
    "13": $S13_DUR,
    "14": $S14_DUR
  },
  "total_terminal_seconds": $TOTAL_LIVE
}
JSON_EOF
fi

echo -e "Resources & Links for Conference Session:"
echo -e "  • Gitea Web UI:         ${CYAN}${GITEA_URL}/${GITEA_ORG}/${GITEA_REPO}${RESET}"
echo "  • Vulnerable PR: newest open PR from pr-42 (see Gitea)"
echo "  • Remediated PR: newest open PR from fix (see Gitea)"
echo -e "  • TAPM Service Health:  ${CYAN}${SERVICE_URL}/health${RESET}"
echo -e "  • Generated Artifacts:  ${CYAN}${ART_DIR}/report.md${RESET}"
echo -e "  • DFD Diagram:          ${CYAN}${ART_DIR}/dfd.png${RESET}"
echo
