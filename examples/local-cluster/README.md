# TAPM Enhanced Lab on a Local Cluster (W2.3a)

Run the complete pull-request attack-path analysis pipeline on a local Kubernetes cluster using **`k3d`** or **`kind`**:
- **Namespace `git`**: Gitea 1.22 server with Actions enabled, hosting repositories and PR reviews.
- **Namespace `ci`**: Gitea Actions `act_runner` executing CI jobs in isolated pod containers.
- **Namespace `tapm`**: TAPM analysis service (`tapm serve`) providing queue, plan parsing, deterministic graph engine, and bounded AI enrichment.
- **Host Model Runtime**: Host-based model runtime (Ollama via `host.k3d.internal:11434` or simulated/recorded offline).

```
 Local Kubernetes Cluster (k3d / kind)
 ┌────────────────────────────────────────────────────────────────────────┐
 │  Namespace: git (gitea:3000)        Namespace: ci (act_runner)         │
 │   demo-org/infra-demo           ──▶  checkout → plan.json              │
 │   required check: attack-paths       → POST plan JSON ──────────┐      │
 │            ▲                                                    │      │
 │            │ PR comment, commit status                          ▼      │
 │            │                                                           │
 │  Namespace: tapm (tapm-service:8080)                                   │
 │   queue → deterministic engine → gate verdict ──────────────────┤      │
 │        → async AI enrichment (roles, validator)                        │
 │   (raw plan deleted immediately after deterministic stage)             │
 │            │ minimal evidence bundle only                              │
 │            ▼                                                           │
 │  Host Model Runtime (Ollama on host GPU at :11434)                     │
 └────────────────────────────────────────────────────────────────────────┘
```

## Internal Cluster DNS Networking

| Component | Namespace | Internal Cluster URL | External Port |
|---|---|---|---|
| Gitea | `git` | `http://gitea.git.svc.cluster.local:3000` | `http://localhost:3000` |
| Gitea SSH | `git` | `gitea.git.svc.cluster.local:22` | `localhost:2222` |
| Analysis Service | `tapm` | `http://tapm-service.tapm.svc.cluster.local:8080` | `http://localhost:8080` |
| CI Runner | `ci` | N/A (worker connected to Gitea) | N/A |
| Host Model (GPU) | Host | `http://host.k3d.internal:11434` | `http://localhost:11434` |

---

## Quick Start

### 1. Prerequisites
- Docker Engine (Docker Desktop, OrbStack, or Colima)
- `kubectl`
- `kind` or `k3d` installed (`kind` is supported out-of-the-box)

### 2. Launch Cluster and Services
Run from the repository root:
```bash
make lab-cluster
```
Or directly via the cluster manager:
```bash
./examples/local-cluster/cluster.sh up
```

This automatically:
1. Detects `k3d` or `kind` and creates a local one-node Kubernetes cluster `tapm-lab` with port mappings (3000, 2222, 8080).
2. Pre-loads the `terraform-attack-paths-pytm:latest` container image into cluster nodes.
3. Applies the Kubernetes manifests across `git`, `ci`, and `tapm` namespaces via `manifests/kustomization.yaml`.
4. Waits for deployment rollouts in `git` and `tapm` namespaces.
5. Runs `bootstrap.sh`:
   - Configures admin user `tapm-admin` (`tapm-admin-pass123`).
   - Generates API token and synchronizes `secret/tapm-secret` in namespace `tapm`.
   - Creates organization `demo-org` and repository `infra-demo`.
   - Seeds the 4 canonical branches (`main`, `pr-42`, `fix`, `injection`) from `demo-repo.bundle`.
   - Seeds `.gitea/workflows/attack-paths.yml` configured for in-cluster service submission.
   - Enforces branch protection on `main` with required check `attack-paths`.
   - Generates runner registration token and synchronizes `secret/runner-secret` in namespace `ci`.

### 3. Check Cluster Status
```bash
make lab-cluster-status
# Or
./examples/local-cluster/cluster.sh status
```

### 4. Open a Demo Pull Request
Open PR #42 to trigger the attack-path evaluation pipeline in the cluster:
```bash
make lab-cluster-pr
# Or
./examples/local-cluster/cluster.sh pr
# Or with specific branch:
./examples/local-cluster/open-pr.sh --branch fix
```

When PR #42 is submitted:
1. The Gitea Actions runner in namespace `ci` picks up the job.
2. The runner submits the plan JSON to `http://tapm-service.tapm.svc.cluster.local:8080`.
3. Deterministic analysis evaluates the plan in under 1 second; raw plan is deleted from disk.
4. Gate verdict updates commit status to `failure` (`PATH-001` detected: open ALB + IMDS optional + wildcard IAM).
5. Initial PR comment is posted to Gitea with findings and path narrative.
6. Asynchronous bounded AI enrichment runs and updates the comment with structured recommendations.
7. Merge button in Gitea is blocked by branch protection until a clean or accepted commit is pushed.

### 5. Tear Down
To delete the cluster and purge all local resources:
```bash
make lab-cluster-down
# Or
./examples/local-cluster/cluster.sh down
```

---

## Manifest Organization

```
examples/local-cluster/manifests/
├── 00-namespaces.yaml         # Namespaces: git, ci, tapm
├── 01-git/
│   ├── configmap.yaml         # Gitea app.ini (actions enabled, sqlite3)
│   ├── secret.yaml            # Admin credentials & secret key
│   ├── pvc.yaml               # 2Gi persistent volume claim
│   ├── deployment.yaml        # Gitea 1.22 deployment with health probes
│   └── service.yaml           # NodePort service (:3000, :22)
├── 02-tapm/
│   ├── configmap.yaml         # TAPM server URLs & model settings
│   ├── secret.yaml            # Server token & Gitea API token
│   ├── deployment.yaml        # tapm serve deployment with health probes
│   └── service.yaml           # NodePort service (:8080)
├── 03-ci/
│   ├── configmap.yaml         # act_runner labels & Gitea URL
│   ├── secret.yaml            # Runner registration token
│   ├── rbac.yaml              # ServiceAccount, Role, RoleBinding
│   └── deployment.yaml        # act_runner deployment with Docker socket
└── kustomization.yaml         # Kustomize entrypoint for all manifests
```
