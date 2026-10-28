# Interface Contract: CLI, Service Endpoints, Gate Policy, and Demo Topology

This document specifies the canonical interface contract for `terraform-attack-paths-pytm`.
It documents the CLI commands, service REST endpoints, adoption ladder levels versus gate verdicts,
risk exception formats, and demo repository branch topology.

This specification serves as the authoritative truth against which documentation, briefs, decks,
and test suites are validated, resolving audit findings F14, F23, F24, F26, F27, and F39.

---

## 1. Command-Line Interface (`tapm`)

### 1.1 Command Overview

The CLI entrypoint is `tapm` (`src/tapm/cli.py`). Subcommands are organized around pipeline execution,
reporting personas, service interactions, and benchmarking.

| Subcommand | Purpose | Key Arguments |
|---|---|---|
| `plan` | Generate Terraform plan offline or from cache | `[fixture] [--out DIR] [--no-cache]` |
| `scan` | Run baseline security scanners (Checkov, tfsec, Trivy) | `[fixture] [--out DIR] [--live] [-v]` |
| `model` | Build graph, evaluate IAM, and generate PyTM model | `[fixture] [--out DIR]` |
| `paths` | Find attack paths traversing from entry to crown jewel | `[fixture] [--out DIR]` |
| `story` | Render plain-language narration for attack paths | `[fixture] [--audience {developer,everyone}] [-n N]` |
| `run` | Execute end-to-end deterministic analysis pipeline | `[fixture] [--out DIR] [--plan PLAN] [--baselines DIR] [--remediate]` |
| `explain` | Run pipeline with AI explanation stage enabled | `[fixture] [--llm {off,simulated,recorded,anthropic,openai,ollama}]` |
| `inject` | Run pipeline with adversarial prompt injection | `[fixture] [--include-comments]` |
| `gate` | Evaluate PR check at a configured adoption level | `<artifacts-dir> [--level {observe,recommend,validate,prevent}] [--fail-on {high,medium,low}]` |
| `measure` | Compute counts-only kit metrics from run directories | `<run-dirs...> [--json] [--per-run]` |
| `canary` | Run Level 5 regression suite proving blocking efficacy | `[--fail-on {high,medium,low}]` |
| `enrich` | Asynchronous AI enrichment from saved artifacts | `<artifacts-dir> [--llm ...] [--model MODEL] [--max-paths N]` |
| `serve` | Run the analysis service REST API and worker queue | `[--host HOST] [--port PORT] [--token TOKEN]` |
| `submit` | Runner client: post plan to service, poll, and exit | `<plan.json> [--server URL] [--level ...] [--timeout S]` |
| `git-status` | Post commit status check to Gitea or GitHub | `[--repo REPO] [--sha SHA] [--state STATE] [--target-url URL]` |
| `git-comment` | Post or edit PR comment on Gitea or GitHub | `[--repo REPO] [--pr PR] [--body TEXT | --body-file FILE] [--marker MARKER]` |
| `report` | Render persona reports (developer, appsec, platform, executive) | `<artifacts-dir> --persona ... [--format ...] [--file FILE]` |
| `matrix` | Affected-module CI matrix for multi-root monorepos | `[repo] [--roots ROOTS] [--changed FILES...] [--shards N]` |
| `tier2` | Benchmark on Tier-2 real-world corpus | `[--heldout] [--tag TAG] [--write-results]` |
| `realworld` | Benchmark on benign real-world modules | `[--write-results]` |
| `strata` | Re-cut evaluation results into strata taxonomy | `[--out FILE]` |
| `bench` | Benchmark all synthetic fixtures | `[--llm ...] [--decision {local,typesafe,recorded}]` |
| `terrara` | Benchmark against TerrARA corpus | `[--llm ...] [--decision {local,typesafe,recorded}]` |
| `verify-precommit` | Verify pre-commitment hash proofs and commit ancestry | `[--quiet]` |

### 1.2 Canonical Persona Reporting (`tapm report`)

Usage syntax:
```bash
tapm report [artifacts-dir] --persona {developer|appsec|platform|executive} [options]
```

#### Persona Argument Requirements (Finding F14 & F39)
1. **Developer, AppSec, Executive Personas:**
   - Require a positional `artifacts-dir` argument pointing to a valid pipeline run output directory (e.g. `tapm report conference-snapshot --persona developer`).
   - **There is NO `--fixture` flag for `tapm report`** (finding F14). Passing `--fixture` fails with an unrecognized argument error.
2. **Platform Persona:**
   - Generates the platform engineer report from `/v1/metrics` operational metrics.
   - Does not read from pipeline artifacts. Instead, it requires either:
     - `--file <path>` (or `-f <path>`): path to a saved metrics JSON file export (finding F39). For offline evaluation and reporting without a running daemon, pass a saved export such as `--file metrics-sample.json`.
     - `--server <url>`: URL of a live running `tapm serve` instance (default `http://127.0.0.1:8080` or `$TAPM_SERVER_URL`).
   - Examples of `--file` usage:
     ```bash
     # Render platform report from saved metrics JSON (offline)
     tapm report --persona platform --file metrics-sample.json

     # Render platform report as plain text or JSON
     tapm report --persona platform --file metrics-sample.json --format text
     tapm report --persona platform --file metrics-sample.json --format json
     ```
3. **Supported Output Formats:**
   - `--format markdown` (default)
   - `--format json`:
     - For `developer` persona: returns JSON containing `comment_markdown` (full rendered PR comment markdown ready for Git API posting), `first_screen_items` (structured JSON array of review items on the first screen: attack paths with proven or suggested fixes, yes/no questions, and data classification questions), and summary counts (`items_first_screen`, `m1_count`, `m2_count`, `paths_count`, `first_screen_max`, `comment_length_chars`, `under_git_limit`).
     - For `platform` persona: returns `/v1/metrics` operational metrics dictionary.
     - For `appsec` persona: returns structured AppSec posture and findings summary.
     - For `executive` persona: returns executive scorecard and trend metrics.
   - `--format text`
   - `--format sarif` (AppSec persona only)

---

## 2. Analysis Service REST API (`tapm serve`)

`tapm serve` exposes an HTTP service for CI/CD runners and local Compose deployments.

### 2.1 Registered Endpoints

Authentication is enforced only when a token is configured through `--token`, `TAPM_SERVER_TOKEN` or
`TAPM_TOKEN`. With no configured token, `TokenAuth` permits requests without authentication.
The CLI binds to loopback by default. Configure a token and network isolation before exposing the service
beyond a trusted local environment. The Auth column below describes token-configured operation.


| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` or `/v1/health` | None | Service liveness probe |
| `POST` | `/v1/jobs` | Bearer Token | Submit Terraform plan JSON + sources for deterministic analysis |
| `GET` | `/v1/jobs` | Bearer Token | List recent analysis jobs |
| `GET` | `/v1/jobs/{id}` | Bearer Token | Retrieve job status, completion state, and gate verdict |
| `GET` | `/v1/jobs/{id}/logs` | Bearer Token | Retrieve structured per-stage execution logs |
| `GET` | `/v1/jobs/{id}/artifacts/{name}` | Bearer Token | Download generated report or graph artifact |
| `POST` | `/v1/jobs/{id}/enrich` | Bearer Token | Trigger asynchronous AI enrichment using evidence bundles |
| `GET` | `/v1/metrics` | Bearer Token | Counts-only operational metrics in JSON format |

### 2.2 Protocol Rules & Non-Existent Surfaces (Finding F23)
- **Plan File Privacy:** Terraform plans uploaded to `POST /v1/jobs` are processed deterministically into the attack graph and **immediately deleted from disk**. Requesting any plan file via `/v1/jobs/{id}/artifacts/plan.json` returns HTTP `403 Forbidden`.
- **No `/v1/analyze`:** The job submission endpoint is strictly `POST /v1/jobs`.
- **No `/v1/tasks`:** Job state is queried exclusively via `GET /v1/jobs/{id}`.
- **No Server-Sent Events (SSE):** Clients track progress via polling `GET /v1/jobs/{id}`.
- **No Prometheus Format:** Operational telemetry is served exclusively as structured JSON via `GET /v1/metrics`.

---

## 3. Adoption Levels vs Gate Verdicts (`tapm gate`)

The pipeline distinguishes between **Adoption Levels** (policy configurations chosen by teams) and **Gate Verdicts** (the outcome of evaluating a specific pull request).

### 3.1 Four Adoption Levels (`LEVELS`)

Configured via `--level <name>` in `tapm gate` and `tapm submit`:

1. `observe`:
   - Records identified attack paths and computes metrics.
   - **Never fails CI** (always returns exit code 0).
2. `recommend`:
   - As `observe`, and additionally computes whether the pull request *would* block if the repository were operating at `validate`.
   - **Never fails CI** (always returns exit code 0).
3. `validate`:
   - Enforces merge gating: fails CI (exit code 3) if any attack path at or above `--fail-on` (default `high`) lacks a valid decision.
   - A valid decision is either:
     - The path is eliminated in Terraform (remediation patch applied).
     - An active accepted risk entry in `attack-path-exceptions.yaml` (expiry <= 90 days).
     - A disputed false path entry with `disposition: not_reachable`.
4. `prevent`:
   - Strictest governance: fails CI (exit code 3) if a path at or above the selected `--fail-on` threshold lacks a valid decision.
   - Accepted risks must specify a `compensating_control`, require a declared `approved_by` value distinct from `owner`, and have expiry <= 30 days. These are unsigned declared fields, not authenticated two-person approval; enforce identities, reviews and policy-file protection through your repository/CI controls.

### 3.2 Gate Evaluation Verdicts (Finding F24)

The evaluation of a plan against a policy produces one of three verdicts:
- `pass`: No unmitigated attack paths exist at or above the threshold, or all identified paths have valid exceptions.
- `fail`: One or more attack paths lack a valid decision. Blocks merge at `validate` and `prevent`.
- `would_block`: Advisory status emitted exclusively at the `recommend` level to inform developers that the changes would block under `validate`.

> [!IMPORTANT]
> `pass` is an evaluation verdict, **not** an adoption level. The adoption levels are strictly `observe`, `recommend`, `validate`, and `prevent`.

### 3.3 Pull Request Draft State Policy (Finding F25 & Decision D5)

- **No Draft-PR Exemption:** The pipeline does **not** inspect or exempt pull request draft states (neither Gitea nor GitHub draft PR states). The gate policy runs uniformly on any submitted plan. Claims of an automatic draft-PR exemption were deprecated per owner decision D5.
- **Meaning of `--draft` on `tapm gate`:** The CLI flag `--draft` on `tapm gate` does **not** inspect PR draft status; it instructs the CLI to generate boilerplate YAML exception entries (`draft_exceptions()`) for open attack paths lacking a decision, facilitating initial onboarding of legacy paths.

---

## 4. Risk Governance & Exception Format (Finding F26)

### 4.1 Canonical File Location
Risk acceptance and false-path disputes are stored in:
```
attack-path-exceptions.yaml
```
at the root of the repository. (The filename `.tapm-exception.yml` was an informal working title and is not recognized).

### 4.2 Security Properties
- **Declarative YAML:** Unsigned, committed directly to git under source control and `CODEOWNERS`.
- **Identity by Hop Semantics:** Exceptions specify paths by `entry` and `target` addresses (and optional intermediate hops), never by transient `PATH-###` IDs which re-order when unrelated resources change.

### 4.3 Supported Dispositions
```yaml
exceptions:
  # Option A: Accepted Risk
  - id: RISK-042
    entry: aws_lb.web
    target: aws_s3_bucket.customer_data
    owner: security-team@example.com
    reason: Legacy analytics ingestion requires cross-account read until Q1 migration
    expires: 2026-12-01
    compensating_control: WAF rate limiting and S3 Object Lock enabled
    approved_by: ciso@example.com

  # Option B: Disputed False Path (Finding F16 / W0.4)
  - id: DISPUTE-001
    entry: aws_lb.web
    target: aws_s3_bucket.customer_data
    disposition: not_reachable
    owner: dev-team@example.com
    reason: Application layer enforces strict mTLS authentication; ALB target group cannot proxy unauthenticated requests
```

---

## 5. Demo Repository Branch Topology (Finding F27)

The local stack and live demo environment utilize a pre-seeded git repository (`examples/local-stack/demo-repo/` packaged into `examples/local-stack/demo-repo.bundle`).

### 5.1 Canonical Branches

| Branch | State | Infrastructure Description | Expected Gate Result |
|---|---|---|---|
| `main` | Baseline | Pre-PR baseline infrastructure (orders ALB, internal app, scoped IAM) | `pass` (0 paths) |
| `pr-42` | Vulnerable PR | Opens ALB to `0.0.0.0/0`, relaxes IMDS tokens to `optional`, widens IAM to `arn:aws:s3:::*` | `fail` / Blocked (PATH-001 HIGH) |
| `fix` | Remediation | Applies verified remediation diff scoping S3 IAM actions back to `reports` bucket | `pass` (PATH-001 eliminated) |
| `injection` | Adversarial test | Reuses fixture 019: embeds adversarial comments into `app.tf` and `iam.tf` targeting AI reviewers | Scripted cases rejected; deterministic paths unchanged. No general injection-immunity claim. |

Non-canonical branch names (`pr-42-vulnerable`, `pr-42-fix`, `injection-test`) are deprecated.
