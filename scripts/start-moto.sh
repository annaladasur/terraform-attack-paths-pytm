#!/usr/bin/env bash
# Local AWS API mock for planning real-world Terraform that uses AWS data sources.
# Only needed to regenerate Tier-2 plans; committed plans replay without it.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
venv="$root/.venv-moto"
[ -x "$venv/bin/moto_server" ] || { python3 -m venv "$venv"; "$venv/bin/pip" install -q "moto[server]==5.2.3"; }
amis="$root/.tools/moto-amis.json"
[ -f "$amis" ] || "$venv/bin/python" "$root/scripts/moto_amis.py" "$amis"
export MOTO_IAM_LOAD_MANAGED_POLICIES=true MOTO_AMIS_PATH="$amis"
exec "$venv/bin/moto_server" -H 127.0.0.1 -p "${MOTO_PORT:-5055}"
