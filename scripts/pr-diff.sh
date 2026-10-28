#!/usr/bin/env bash
# Show the demo pull request: the diff between the pre-PR state (demo/base) and fixture 006.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
base="$root/demo/base"
head="$root/fixtures/006-public-workload-iam-sensitive-bucket"
echo "PR #42  \"go-live: open orders ALB, relax IMDS for legacy agent, widen report export read\""
echo
cd "$root"
for f in network.tf app.tf iam.tf; do
  diff -u --label "a/$f" --label "b/$f" "$base/$f" "$head/$f" || true
done | { if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then sed -e 's/^+[^+].*/\x1b[32m&\x1b[0m/' -e 's/^-[^-].*/\x1b[31m&\x1b[0m/'; else cat; fi; }
