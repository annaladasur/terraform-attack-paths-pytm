#!/usr/bin/env bash
# Audience lab driver (labs/README.md).
#
#   bash labs/lab.sh 1                 Level 1: run the pipeline on labs/workspace, check PASS
#   bash labs/lab.sh 2                 Level 2: re-plan your Terraform edit, compare with the what-if
#   bash labs/lab.sh 3                 Level 3: prompt injection through your comment
#   bash labs/lab.sh apply <edit>...   apply a named edit (no editor needed); no args lists them
#   bash labs/lab.sh variants          edits pre-computed in plan-cache/ (work without Terraform)
#   bash labs/lab.sh reset             start over from fixture 006
#
# No cloud account, no API key. LLM=recorded (default) replays cassettes and otherwise
# uses the labelled offline stand-in; LLM=anthropic|openai|ollama calls a live model.
set -euo pipefail
cd "$(dirname "$0")/.."

TAPM=${TAPM:-.venv/bin/tapm}
if [ ! -x "$TAPM" ]; then TAPM=$(command -v tapm || true); fi
if [ -z "$TAPM" ]; then echo "tapm not found: run 'make setup' first" >&2; exit 1; fi
LLM=${LLM:-recorded}
JEV=${JEV:-local}
WS=labs/workspace

step() { if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then printf "\n\033[1m== %s\033[0m\n" "$*"; else printf "\n== %s\n" "$*"; fi; }

case "${1:-help}" in
  reset)
    "$TAPM" lab reset ;;
  apply)
    shift; "$TAPM" lab apply "$@" ;;
  variants)
    "$TAPM" lab variants ;;
  1)
    [ -d "$WS" ] || "$TAPM" lab reset
    "$TAPM" lab sync
    step "Level 1.1  Terraform plan -> typed graph -> IAM -> PyTM"
    "$TAPM" model "$WS" --out artifacts/lab-1
    step "Level 1.2  Attack paths"
    "$TAPM" paths "$WS" --out artifacts/lab-1
    step "Level 1.3  AI enrichment, validated against the evidence"
    "$TAPM" explain "$WS" --out artifacts/lab-1 --llm "$LLM" --jev "$JEV"
    step "Level 1 checks"
    "$TAPM" lab check 1 ;;
  2)
    [ -d "$WS" ] || { echo "run level 1 first (bash labs/lab.sh 1)" >&2; exit 1; }
    step "Level 2.1  Re-plan the edited Terraform"
    "$TAPM" lab sync
    step "Level 2.2  Attack paths after your change"
    "$TAPM" paths "$WS" --out artifacts/lab-2
    step "Level 2 checks (compared with the unedited plan)"
    "$TAPM" lab check 2 ;;
  3)
    [ -d "$WS" ] || { echo "run level 1 first (bash labs/lab.sh 1)" >&2; exit 1; }
    "$TAPM" lab sync
    step "Level 3.1  Your comment vs. an unsafe and a safe AI pipeline"
    "$TAPM" inject "$WS" --out artifacts/lab-3 --llm "$LLM" --jev "$JEV"
    step "Level 3.2  The AI boundary's scripted negative tests on the demo fixture"
    "$TAPM" security-tests 006 --out artifacts/lab-3-security | tail -2
    step "Level 3 checks"
    "$TAPM" lab check 3 ;;
  *)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
