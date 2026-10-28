# Architecture: one page

```
 pull request touches *.tf, *.tfvars, lock file, exceptions or answers
        │
        ▼
 CI job  (read-only plan role via OIDC; nothing long-lived)
  1  terraform plan → terraform show -json → plan.json      secret: never uploaded, never sent to a model
     (skipped when only exceptions or answers change: gate evaluates from cached attack paths)
  2  the scanners you already run → baselines/               optional: findings get joined to paths
  3  tapm run --remediate  plan → typed graph → IAM + network → attack paths → evidence ledger
                   → pytm model fed with plan evidence → threats sorted: confirmed / ruled out / ask the app team
                   → a few yes/no questions → verified remediation diffs → report.md, SARIF
                   (optional) AI explains validated evidence; it cannot add, drop or re-rank a path
  4  tapm gate     your adoption level decides: observe / recommend never fail; validate / prevent exit 3
                   while a path at or above the threshold has no fix and no valid accepted risk
  5  PR comment    gate.md + report.md: the paths in plain words, the questions, the verified fix if any
  6  tapm measure  counts only → your worksheet
        │
        ▼
 files in the repository, reviewed like code (CODEOWNERS)
   threat-answers.yaml            the author's yes/no answers; they become evidence for pytm
   attack-path-exceptions.yaml    accepted risks: owner, reason, compensating control, expiry

 nightly (Level 5)
   tapm canary                    known-bad plans must block, known-good must pass
   tapm run + tapm gate on main   open paths; accepted risks that expired
```

**Where each decision is made.**
- Paths, priorities and the gate are deterministic code: the same plan gives the same bytes.
- People decide the answers and the accepted risks, in files that are reviewed like code.
- A model, if you turn one on, only writes explanations. Each explanation must cite evidence IDs, and a validator
  rejects it otherwise. It never blocks or unblocks a merge.

## Trigger matrix

CI workflows (`examples/github-actions/pr-security.yml`, `examples/gitlab/.gitlab-ci.yml`) enforce this trigger matrix:

| Event | Runs | Can block? |
|---|---|---|
| PR changes `*.tf`, `*.tfvars`, `*.tfvars.json`, `.terraform.lock.hcl` or a consumed module | plan, scanners, deterministic engine, AI explanations, verified remediation (`--remediate`), gate | At `validate` and above |
| PR changes only `attack-path-exceptions.yaml` or `threat-answers.yaml` | gate re-evaluation from cached artifacts (no new plan needed) | At `validate` and above |
| Re-push with no change to any evidence bundle | cache hit | No |
| Paths exist | asynchronous AI enrichment | Never |
| Nightly on the default branch | sharded sweep, canaries, expiries (`examples/github-actions/nightly-canary.yml`) | Opens an issue |
| Model, prompt, engine, pytm, scanner or provider version changes | replay, negative tests, canaries, AI regression subset | Blocks the upgrade, not PRs |
| Weekly | false-path sample (M8) | No |

For repositories with multiple root modules, `tapm matrix` maps changes across shared modules to affected root modules, emits CI matrices, and shards the nightly sweep across parallel runners (`examples/github-actions/nightly-canary.yml`).

False paths can be disputed in `attack-path-exceptions.yaml` using `disposition: not_reachable` (reviewed via CODEOWNERS, counted automatically into M8 by `tapm measure`, and treated as decided by `tapm gate`).

## If you already have X, use Y

The method doesn't depend on this tool. Keep what you have and add the missing piece.

| You already have | Keep it for | Add |
|---|---|---|
| An IaC scanner (Checkov, tfsec, Trivy, KICS) | Per-resource rules: encryption, logging, tagging | The path check. `tapm` joins Checkov, tfsec and Trivy findings to the hops they sit on. Other scanners' findings aren't joined, but paths still work |
| A policy engine (OPA/conftest, Sentinel) | Rules about single resources | Read `gate.json` from your policy if you'd rather make the merge decision there. It's plain JSON |
| A threat-modeling tool or practice (pytm, Threat Dragon, a design-review process) | Application design reviews | The generated `threat-model.py` is plain pytm. Send the questions to the same people who own the design review |
| A risk register or ticketing system | Owners, due dates, audit trail | Use the ticket ID as the accepted risk's `id` |
| A cloud security platform with runtime attack-path analysis | What is deployed now, including drift and console changes | This check sees the change before it is applied. The two answer different questions; use both |
| Code-scanning UI (GitHub code scanning, GitLab security reports) | Triage in one place | `attack-paths.sarif`, one result per path with a location per hop |
| Another CI (Jenkins, Atlantis, Terraform Cloud run tasks) | Your pipeline | Any job that can run `terraform show -json` and a Python 3.11 CLI. The examples are GitHub Actions and GitLab |

## What it needs from your Terraform

- **A plan.** It reads `terraform show -json`, so modules, `count`, `for_each` and unknown values are resolved the way
  Terraform resolves them.
- **AWS resources.** Other providers' resources are carried in the graph but not analyzed.
- **Data classification tags.** Paths end at data you care about. Tag it, for example `data_classification =
  "confidential"` (also accepted: `DataClassification`, `classification`, `sensitivity`). Without tags,
  `--heuristic-sensitivity` classifies by name, and every such path is marked `review`.
