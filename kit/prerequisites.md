# Organizational prerequisites

| Area | You need | Minimum for Level 1 |
|---|---|---|
| **Data** | A plan per root module in CI; your scanners' JSON output (optional); data classification tags on the stores that matter | One root module that plans in CI, and its sensitive data tagged |
| **Permissions** | A read-only cloud role the CI job assumes through OIDC; permission to comment on PRs and upload SARIF; branch protection for a required check (Level 3) | The read-only role |
| **Infrastructure** | A CI runner with Terraform and Python 3.11+ (Graphviz optional, for diagrams) | Same |
| **Skills** | Reading Terraform and IAM policies; reviewing a path and saying "reachable or not" | One engineer who can run the job and one reviewer who knows the app |
| **Integrations** | Code host (comments, required checks, CODEOWNERS); ticketing IDs for accepted risks; code scanning for SARIF (optional) | Job summaries or artifacts |
| **Time and cost** | CI minutes for `terraform plan` (you may already pay for them) plus `tapm run`, a median of 0.6 s per lab fixture. AI is off unless you add a key | Same |

## Ownership

| Activity | Platform / DevOps | AppSec | Repo owners (app team) | Risk owner |
|---|---|---|---|---|
| CI job, plan role, runner | **Owns** | Consulted | Informed | |
| Threshold, level, canaries | Consulted | **Owns** | Consulted | |
| Answers (`threat-answers.yaml`) | | Reviews | **Owns** | |
| Accepted risks (`attack-path-exceptions.yaml`) | | Approves at Level 4 | Requests | **Owns** (with expiry) |
| Weekly false-path sample (M8) | | **Owns** | Consulted | |
| Local worksheet and evidence review | Consulted | **Owns** | | |

## Regulated environments

- The evidence ledger (`evidence.json`) and the accepted-risk file give change-management evidence. They show which
  plan produced which path, who accepted it, until when, and why.
- Keep `gate.json` with your change records. It is small and holds no plan values.
- A plan is sensitive. Nothing in this kit needs one to leave the runner.

## Adoption concerns

The objections you'll hear, and what the kit does about each. Rows marked *recommendation* are judgment, not lab
results.

| Concern | What goes wrong | What to do | Where |
|---|---|---|---|
| **Legacy systems** | Old Terraform, or root modules nobody can plan in CI | `terraform show -json` exists since 0.12. Modules that can't plan per PR run on a schedule at Level 1 until they can | `30-60-90.md`, day 1 |
| **Heterogeneous environments** | Several clouds, several repos, several CI systems | Scope by root module. AWS modules get paths; others keep their scanners. The check is one CLI call in any CI | `architecture.md` |
| **Regulated environments** | Auditors ask who accepted a risk, when, and why | Accepted risks are files with an owner, approver and expiry, reviewed like code | Above |
| **Developer resistance** | Another bot, more comments | Level 2 posts one comment that replaces the finding list with the paths and a few questions (M2 vs M1). Verified fixes arrive as a diff | `adoption-ladder.md` |
| **Security-team workload** | AppSec becomes the bottleneck for every path | Authors answer questions and fix their own paths. AppSec owns the threshold and, at Level 4, the approvals | Ownership table |
| **False positives** | Paths nobody believes, then overrides | Sample weekly (M8). Hold blocking until M8 < 10%. Every path shows its evidence, file and line, so a wrong path is quick to spot and report | `metrics.md` |
| **Exceptions** | Temporary acceptances become permanent | Expiry at most 90 days (30 at prevent). Expired entries stop counting. Nightly runs report them | `decision-matrix.md` §6 |
| **Ownership** | Nobody owns the check after the pilot | Assign the table above before Level 2 | Above |
| **Change management** | A level change surprises teams | Announce each level change with its exit criteria. Record a rollback like a policy change | `adoption-ladder.md` |
| **Integration complexity** | The rollout stalls on wiring | Level 1 is one job and one role. The PR comment waits until Level 2 | `../examples/` |
| **Cost** | CI time and people time | Measure M14 and M9. AI adds cost only if you turn it on | `metrics.md` |
| **Latency** | Slower PR checks | `tapm run` is small next to `terraform plan`; measure p95 (M14) | `metrics.md` |
| **Reliability** | The check breaks and nobody notices | Nightly canaries (M15). *Recommendation:* a crash turns the job red at every level; merging past it needs a recorded reason | `adoption-ladder.md` |
