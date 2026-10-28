#!/usr/bin/env bash
# Demo beat 6b: apply the verified fix to a copy of the PR and run the same check again.
# The fix is the diff `tapm remediate` proved (remediation-PATH-001.diff); the plan for the patched copy comes from
# plan-cache/, so this runs offline. Nothing in fixtures/ is modified.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tapm="${TAPM:-$root/.venv/bin/tapm}"
fx="$root/fixtures/006-public-workload-iam-sensitive-bucket"
diff="${1:-$root/artifacts/006-public-workload-iam-sensitive-bucket/remediation-PATH-001.diff}"
[ -f "$diff" ] || diff="$root/conference-snapshot/remediation-PATH-001.diff"
work="$root/artifacts/pr-42-with-fix"
rm -rf "$work" && mkdir -p "$work"
cp "$fx"/*.tf "$work/" && cp -r "$fx/baselines" "$work/"
patch -s -p1 -d "$work" < "$diff"
echo "applied $(basename "$diff") to a copy of PR #42"
"$tapm" plan "$work" >/dev/null
"$tapm" run "$work" --out "$work/out" --no-dfd >/dev/null
"$tapm" gate "$work/out" --tf-dir "$work" --level validate
