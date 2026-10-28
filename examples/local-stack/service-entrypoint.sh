#!/bin/sh
set -eu
if [ -z "${GITEA_TOKEN:-}" ]; then
  echo "TAPM startup error: GITEA_TOKEN is empty. Run make local-bootstrap from the checkout containing examples/local-stack/.env, then restart analysis-service." >&2
  exit 2
fi
exec tapm serve --host 0.0.0.0 --port 8080 \
  --token "${TAPM_SERVER_TOKEN:-demo-secret-token}" \
  --git-server gitea --git-base-url "${GITEA_BASE_URL:-http://gitea:3000}" \
  --git-token "$GITEA_TOKEN" --llm "${TAPM_LLM:-simulated}"
