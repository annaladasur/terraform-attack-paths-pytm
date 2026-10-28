# Tier 2: real-world Terraform at frozen commits

| Repository | Commit | License | Cases |
|---|---|---|---|
| [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) | `729f8da` (2023-04-27, unmaintained) | Apache-2.0 | `terraform/aws` |
| [BishopFox/iam-vulnerable](https://github.com/BishopFox/iam-vulnerable) | `0f29866` (2025-09-11) | MIT | default configuration (free modules) |
| [RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) | `abf1ba8` (v2.5.0) | BSD-3-Clause | 8 AWS scenarios |

- `manifest.yaml` pins repositories, variables and toolchains.
- `gold/` holds reachability labels written from each project's own documentation before the engine ran.
- `ADJUDICATION.md` records every disagreement.
- `plans/` holds the gzip-compressed `terraform show -json` output.
- `baselines/` holds Checkov, tfsec and Trivy output.

## How the plans were produced (no AWS account, no credentials)

Real-world code uses data sources such as `aws_caller_identity`, `aws_ami` and `aws_iam_policy` that call AWS during `plan`. We answer those calls with [moto](https://github.com/getmoto/moto), a local AWS API mock:

```bash
make tools                       # pinned Terraform 1.16.4 + provider mirror (checksums verified)
bash scripts/start-moto.sh       # moto_server on 127.0.0.1:5055 with AWS managed policies + stand-in AMIs
TAPM_TERRAFORM_LEGACY=... TAPM_PROVIDER_MIRROR_LEGACY=... tapm tier2 --tag rerun
```

The repositories are cloned at their pinned commits into `.tools/tier2-repos/` (override with `TAPM_TIER2_REPOS`).

The planner writes a provider override (`skip_*` flags, static fake keys, `endpoints { ... = "http://127.0.0.1:5055" }`), swaps any remote backend for an empty local one, and removes real `AWS_*` credentials from the child environment. The committed plans make the benchmark replayable without any of this.

What moto changes: account ID `123456789012`, AMI IDs from a stand-in catalogue, and AWS-managed policy documents from moto's bundled copies. None of these affects the relationships being scored.

## Findings about the corpus itself

- **TerraGoat does not parse on Terraform >= 0.15** (quoted type constraints, removed in 0.15). Scanners read it; a plan-based pipeline cannot, without an old toolchain. We used Terraform 0.14.11 and hashicorp/aws 4.67.0 (the newest provider that accepts its S3 inline blocks and `aws_rds_cluster.allocated_storage`). This is a real cost of plan-based analysis: it needs code that current Terraform can plan.
- TerraGoat documents misconfigurations, not attack paths, so it is unlabeled and only used for robustness and scanner comparison. Even with name-based sensitivity heuristics, the engine finds no internet-to-data path. That is expected: TerraGoat's resources are mostly independent misconfigurations, not chains.
- Four CloudGoat scenarios needed harness work to plan: Ubuntu AMIs for moto, a throwaway SSH public key (the CloudGoat CLI normally generates it), and `../assets` outside the Terraform directory.

## Results

See `../RESULTS.md` (generated) and `../DEVELOPMENT-LOG.md` for what changed between the blind first run and the second run.
