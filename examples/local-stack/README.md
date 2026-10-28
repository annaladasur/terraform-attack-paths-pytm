# TAPM Local Stack Quick Start (W2.1)

Run the complete pull-request attack-path analysis pipeline on a local laptop using Docker Compose:
- **Local Git server**: Gitea 1.22 with Gitea Actions enabled
- **CI runner**: `act_runner` executing ephemeral CI jobs
- **Analysis service**: `tapm serve` with worker pool, plan deletion, and Gitea adapter
- **AI backend**: host-based model runtime (Ollama via `host.docker.internal:11434`) or simulated/recorded offline

```
 Developer laptop
 ┌────────────────────────────────────────────────────────────────────────┐
 │  Local Git server (Gitea:3000)      Runner (act_runner)                │
 │   demo-org/infra-demo           ──▶  checkout → terraform plan         │
 │   required check: attack-paths       → POST plan JSON ──────────┐      │
 │            ▲                                                    │      │
 │            │ PR comment, commit status                          ▼      │
 │            │                                                           │
 │  Analysis service (tapm-service:8080)                                  │
 │   queue → deterministic engine → gate verdict ──────────────────┤      │
 │        → async AI enrichment (roles, validator)                        │
 │   (raw plan deleted immediately after deterministic stage)             │
 │            │ minimal evidence bundle only                              │
 │            ▼                                                           │
 │  Host Model Runtime (Ollama on host GPU at :11434)                     │
 └────────────────────────────────────────────────────────────────────────┘
```

## Quick Start (Under 10 Minutes)

### 1. Prerequisites
- Docker Engine & Docker Compose (Docker Desktop, OrbStack, or Colima)
- Python 3.11+ (optional, for local CLI commands)
- Ollama running locally (optional; defaults to `simulated` if omitted)

### 2. Launch Stack
Run from the repository root:
```bash
make local-up
```
This automatically:
1. Starts Gitea and `tapm-service` containers.
2. Executes `examples/local-stack/bootstrap.sh`:
   - Creates admin user `tapm-admin` (`tapm-admin-pass123`)
   - Generates Gitea service API token for `tapm-service`
   - Creates organization `demo-org` and repository `infra-demo`
   - Seeds `.gitea/workflows/attack-paths.yml`
   - Enforces branch protection on `main` with required check `attack-paths`
   - Generates the Actions runner registration token
   - Starts `tapm-runner` connected to Gitea

`bootstrap.sh --no-compose` does the Gitea API steps without calling Docker; the tests use it. Without the flag, the
final restart of `tapm-service` and `tapm-runner` runs only when `ENV_FILE` is the `.env` next to `compose.yaml`,
because that is the file Compose reads.

### 3. Verify Components
- **Gitea UI**: [http://localhost:3000](http://localhost:3000) (Credentials: `tapm-admin` / `tapm-admin-pass123`)
- **Demo Repository**: [http://localhost:3000/demo-org/infra-demo](http://localhost:3000/demo-org/infra-demo)
- **Service Health**: `curl http://localhost:8080/health`
- **Metrics**: `curl http://localhost:8080/v1/metrics`
- **Platform Report**: `tapm report --persona platform --server http://localhost:8080`

### 4. Open a Demo Pull Request
The demo repository (`infra-demo`) is automatically seeded with four canonical branches:
- **`main`**: Pre-PR base infrastructure (0 paths, passes gate).
- **`pr-42`**: PR #42 go-live changes introducing PATH-001 (open ALB + IMDS optional + wildcard IAM; blocked by gate).
- **`fix`**: Verified remediation scoping IAM role back to reports bucket (breaks PATH-001, passes gate).
- **`injection`**: Prompt injection stress test hidden in Terraform comments (refused by AI boundary, blocked by gate).

#### Option A: One-command PR creation via API (recommended)
Open PR #42 instantly through the Gitea API:
```bash
# Open PR #42
./examples/local-stack/open-pr.sh
# Or using Makefile
make local-pr

# Open the fix or injection PRs:
./examples/local-stack/open-pr.sh --branch fix
./examples/local-stack/open-pr.sh --branch injection
```

#### Option B: Clone and explore locally
```bash
git clone http://localhost:3000/demo-org/infra-demo.git /tmp/infra-demo
cd /tmp/infra-demo
git checkout pr-42
```

When a pull request is opened into `main`:
1. `attack-paths` status check starts immediately (`pending`).
2. Gitea Actions runner triggers `tapm submit`.
3. Deterministic analysis evaluates the plan in under 1 second; raw plan is securely purged from disk.
4. Gate verdict updates commit status (`failure` if blocking paths found, `success` if clean).
5. Initial PR comment is posted with the path narrative and findings.
6. Async AI enrichment completes and edits the PR comment with structured annotations.
7. Merge button is blocked until paths are remediated or accepted with expiry.

### 5. Tear Down
To stop and remove containers and networks:
```bash
make local-down
```
To also purge persistent volumes (reset everything):
```bash
make local-clean
```

## Configuration Reference

Environment variables can be customized in `examples/local-stack/.env`:

| Variable | Description | Default |
|---|---|---|
| `GITEA_URL` | Public Gitea URL | `http://localhost:3000` |
| `GITEA_ADMIN_USER` | Admin username | `tapm-admin` |
| `GITEA_ADMIN_PASSWORD` | Admin password | `tapm-admin-pass123` |
| `GITEA_ORG` | Demo organization name | `demo-org` |
| `GITEA_REPO` | Demo repository name | `infra-demo` |
| `REQUIRED_CHECK` | Name of the mandatory status check | `attack-paths` |
| `TAPM_SERVER_TOKEN` | Bearer token for analysis service API | `demo-secret-token` |
| `TAPM_LLM` | AI backend for enrichment | `simulated` (or `ollama`) |
| `OLLAMA_HOST` | Host Ollama URL from within container | `http://host.docker.internal:11434` |
