# Tier-2 label adjudication log

Gold labels were written by reviewer 1 (author draft) from each project's documentation before the engine ran. Where the engine and the labels disagree after the second run, the disagreement is recorded here **without changing the gold file**. Reviewer 2 decides; until then the headline numbers use the labels as written.

## Disputed: engine says "not reachable from this user", gold says VALID

| Entry | Gold | Engine | Evidence from source (commit `0f29866`) | Proposed resolution |
|---|---|---|---|---|
| `module.privesc-paths.aws_iam_user.privesc9-AttachRolePolicy-user` | VALID | no path | The user's only permission is `iam:AttachRolePolicy` on `*`. It has no `sts:AssumeRole`, and no role in the plan trusts it. It can attach a policy to a role but cannot then use that role. The matching **role** (`privesc9-AttachRolePolicy-role`) is self-escalating and the engine reports it. | Re-label the *user* entry OUT_OF_SCOPE ("requires a second principal"); keep the role as VALID. |
| `module.privesc-paths.aws_iam_user.privesc12-PutRolePolicy-user` | VALID | no path | Same shape: `iam:PutRolePolicy` on `*`, no way to use a role. | Same as above. |
| `module.privesc-paths.aws_iam_user.privesc-AssumeRole-start-user` | VALID | no path | The start user has **no policy attached**. The chain's first role trusts `var.aws_assume_role_arn` (the operator running Terraform), not this user. The path exists for the operator's principal, which is outside the plan. | Re-label OUT_OF_SCOPE ("entry is the lab operator's principal, not in the plan"). |

The labelling mistake is instructive: the README table lists *techniques*, and I mapped each technique to the *user* named after it. IAM-Vulnerable creates a user **and** a role per technique and expects the tester to use whichever principal works.

## Accepted as a known limitation

| Entry | Gold | Engine | Why |
|---|---|---|---|
| `module.tool-testing.aws_iam_user.fp5-nonExploitableConditionConstraint-user` | INVALID | path, status `review`, precondition `condition_satisfied` | The grant's Condition cannot be met in practice, but the engine does not evaluate Condition values (runtime context is not in a plan). It reports the path as needing review rather than asserting it. Strict scoring counts it as FP. |

## Unlabeled paths found (not scored)

| Case | Path | Assessment |
|---|---|---|
| cloudgoat-iam_privesc_by_key_rotation | `aws_iam_user.admin -> primary_secret` | The admin user is the documented pivot; its credentials are what the attacker takes over. Correct relationship. |
| cloudgoat-ec2_ssrf | `aws_iam_user.wrex -> secret_bucket` | Wrex's keys are found in Lambda environment variables in the documented route. Correct relationship. |
| cloudgoat-data_secrets | `aws_iam_user.lambda_user -> final_flag` | lambda_user's keys are found in Lambda environment variables in the documented route. Correct relationship. |

These are real IAM relationships starting from identities whose credentials leak mid-route. The engine cannot know that a credential is stored in data (that is a secrets-scanning problem), but once a stolen identity is an entry, it finds the rest.

## Held-out blind evaluation (E4: 5 CloudGoat scenarios)

Ground-truth labels were committed to git prior to running the engine on this suite (commit `2a199ec`).

| Case | Result | Assessment |
|---|---|---|
| `cloudgoat-beanstalk_secrets` | 0 FP, 0 FN (1 OUT_OF_SCOPE) | Documented route extracts secondary credentials from Elastic Beanstalk environment configuration (credentials stored in data). 4 unlabeled paths connect `admin_user` and `secondary_user` directly to targets. |
| `cloudgoat-secrets_in_the_cloud` | 0 FP, 0 FN (1 OUT_OF_SCOPE found) | Route relies on secrets stored in S3/Lambda/Vault/IMDS/DynamoDB data. 2 unlabeled paths + 1 out-of-scope path found (`low_priv_user`, `secrets_manager_user`, `internet` to secret). |
| `cloudgoat-vpc_peering_overexposed` | 0 FP, 0 FN (2 OUT_OF_SCOPE) | Route requires lateral movement over SSH and stealing credentials from host web server configuration on prod EC2. No false path reported (0 paths emitted). |
| `cloudgoat-rds_snapshot` | 1 TP, 0 FP, 0 FN (1 OUT_OF_SCOPE) | Correctly identifies `cg-david` reachability to `cg-rds-db_instance` via RDS snapshot restore and modify grants. |
| `cloudgoat-codebuild_secrets` | 1 TP, 0 FP, 0 FN (1 OUT_OF_SCOPE) | Correctly identifies `cg-calrissian` reachability to `cg-psql-rds` via RDS snapshot restore and modify grants. |

Across all 5 held-out scenarios: 9 paths emitted, 2 scored (2 TP, 0 FP, 0 FN; Precision = 1.0 (2/2), Recall = 1.0 (2/2), False paths = 0 among labeled). 7 paths unscored (6 unlabeled + 1 out-of-scope found).

### Adjudication of all 7 unscored E4 paths (Task A4)

Every emitted path in `tier2-heldout.json` not covered by the 2 scored true positives is adjudicated below with source evidence and a verdict:

| # | Case | Emitted Path | Type | Source Evidence | Assessment & Mechanism | Verdict |
|---|---|---|---|---|---|---|
| 1 | `cloudgoat-beanstalk_secrets` | `aws_iam_user.admin_user -> aws:account-admin` | Unlabeled | `iam.tf:38-51` | `admin_user` has `AdministratorAccess` policy attached, granting direct account administrator privileges. | Correct relationship |
| 2 | `cloudgoat-beanstalk_secrets` | `aws_iam_user.admin_user -> aws_secretsmanager_secret.final_flag` | Unlabeled | `iam.tf:38-51` | `admin_user` has full administrator privileges and can read any secret in the account, including `final_flag`. | Correct relationship |
| 3 | `cloudgoat-beanstalk_secrets` | `aws_iam_user.secondary_user -> aws:account-admin` | Unlabeled | `iam.tf:58-75` | `secondary_user` policy `cg-secondary-user-policy` grants `iam:CreateAccessKey` on `admin_user.arn`, escalating privileges to `admin_user` and full account admin. | Correct relationship |
| 4 | `cloudgoat-beanstalk_secrets` | `aws_iam_user.secondary_user -> aws_secretsmanager_secret.final_flag` | Unlabeled | `iam.tf:58-75` | `secondary_user` creates access keys for `admin_user` (`iam:CreateAccessKey`), who then accesses `final_flag`. Documented multi-hop route in CloudGoat cheat sheet. | Correct relationship |
| 5 | `cloudgoat-secrets_in_the_cloud` | `aws_iam_user.secrets_manager_user -> aws_secretsmanager_secret.this` | Unlabeled | `iam.tf:192-205` | `secrets_manager_user` policy `cg-secrets-manager-user-policy` explicitly grants `secretsmanager:DescribeSecret`, `secretsmanager:GetSecretValue`, `secretsmanager:ListSecrets` on `this.arn`. Documented final identity in CloudGoat cheat sheet. | Correct relationship |
| 6 | `cloudgoat-secrets_in_the_cloud` | `aws_iam_user.low_priv_user -> aws_secretsmanager_secret.this` | Out-of-scope found | `secrets_manager.tf:22-35` | Gold label (`OUT_OF_SCOPE`) assumed `low_priv_user` could only reach the secret via the documented 8-step data chain (S3 -> Lambda -> Vault -> EC2 -> DynamoDB -> `secrets_manager_user`). However, `secrets_manager.tf` attaches `aws_secretsmanager_secret_policy.this` with `Principal = "*"`. In AWS IAM, resource-based policies grant read access to all in-account principals without requiring identity grants. `low_priv_user` therefore has direct read access in IAM. | Correct relationship (agent adjudication; no second person has confirmed it: gold label remains OUT_OF_SCOPE as intended scenario route; IAM wildcard shortcut documented as authentic architectural finding; gold files preserved to protect C8 pre-commitment) |
| 7 | `cloudgoat-secrets_in_the_cloud` | `internet -> aws_secretsmanager_secret.this` | Unlabeled | `secrets_manager.tf:22-35` | Detailed root-cause analysis below. Edge `GRAPH-023` (`INTERNET -> principal:any`) and `GRAPH-008` (`principal:any -> aws_secretsmanager_secret.this`) triggered by `aws_secretsmanager_secret_policy.this` (`Principal = "*"` on `secretsmanager:GetSecretValue`). | Correct relationship (agent adjudication; no second person has confirmed it: authentic cross-account exposure in scenario code; 0 engine false positives; recorded as adjudicated unlabeled path) |

### Root-cause analysis: `internet -> aws_secretsmanager_secret.this`

- **Case:** `cloudgoat-secrets_in_the_cloud`
- **Emitted Path:** `PATH-001`: `internet -> principal:any -> aws_secretsmanager_secret.this` (status: `direct`, priority: `high`, score: 4).
- **Exact Resource Policy in Code:** `secrets_manager.tf` lines 22-35:
  ```terraform
  resource "aws_secretsmanager_secret_policy" "this" {
    secret_arn = aws_secretsmanager_secret.this.arn
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action    = "secretsmanager:GetSecretValue"
          Effect    = "Allow"
          Resource  = aws_secretsmanager_secret.this.arn
          Principal = "*"
        }
      ]
    })
  }
  ```
  Recorded in evidence as `IAM-006` (statement Allow `secretsmanager:GetSecretValue` on `aws_secretsmanager_secret.this.arn` for `Principal: "*"`) and `TF-031` (`aws_secretsmanager_secret.this`).
- **Exact Engine Edges and Graph Mechanics:**
  1. `GRAPH-023`: `INTERNET -> principal:any` (`EXPOSES`, label: `"any AWS principal / anonymous"`, generated in `src/tapm/graph/build.py:100-103`).
  2. `GRAPH-008`: `principal:any -> aws_secretsmanager_secret.this` (`ALLOWS`, label: `"read"`, actions: `["secretsmanager:GetSecretValue"]`, generated in `src/tapm/iam/evaluator.py:462`).
- **AWS Security Mechanics & Reachability Analysis:**
  - AWS Secrets Manager endpoints (`secretsmanager.<region>.amazonaws.com`) are public, internet-accessible cloud API endpoints.
  - Unlike S3 buckets, AWS Secrets Manager requires request authentication via AWS Signature Version 4 (SigV4). It does not accept unauthenticated (anonymous) requests.
  - However, an IAM resource-based policy specifying `Principal: "*"` without restrictive conditions (`aws:PrincipalArn`, `aws:PrincipalAccount`, or `aws:PrincipalOrgID`) allows cross-account requests from *any* valid AWS principal globally.
  - In `tapm`'s threat model, `principal:any` represents external actors wielding arbitrary AWS credentials or anonymous access, exposed from `internet`.
  - An adversary on the internet holding an arbitrary AWS account (e.g. standard developer or free-tier credentials) can invoke `aws secretsmanager get-secret-value --secret-id <arn>` directly over the internet without compromising any identity or credential within the victim's account.
  - **Prerequisite / Constraint:** The caller must know or discover the secret ARN or name (`cg-secret-${local.cgid_suffix}`), because `secretsmanager:ListSecrets` is an account-level API that cannot be granted cross-account via secret resource policy.
- **Why CloudGoat Contains This Configuration:**
  - In CloudGoat's scenario design, the intended route involves multiple pivot steps ending with credentials for `secrets_manager_user`. To ensure that user could read the secret without managing explicit principal ARNs in the resource policy, the scenario author attached `Principal = "*"` to `aws_secretsmanager_secret_policy.this`.
  - This authoring shortcut unintentionally made the secret accessible to any external AWS principal worldwide who acquires or guesses the secret ARN.
- **Verdict & Headline Status:**
  - **Verdict:** Correct relationship (unintended cross-account exposure in benchmark scenario code).
  - This is an authentic architectural vulnerability arising directly from the scenario's Terraform definition. The engine did not hallucinate the policy or edges.
  - It is **not a false positive** of the engine. No engine fix task is required.
  - Because it was not part of the labeled expected paths in `gold/cloudgoat-secrets_in_the_cloud.yaml` (which only labeled `low_priv_user`), it is recorded as an adjudicated unlabeled path.

### Tool-pin verification update (Task A3)
Re-run after tool-pin fix (Terraform 1.16.4, Checkov 3.3.20, tfsec v1.28.14, Trivy 0.74.0), gold unchanged. Emitted path counts and evaluation metrics remain identical across all 5 held-out scenarios (2 TP, 0 FP, 0 FN; Precision = 1.0, Recall = 1.0).

### Retracted: "Reviewer 2 disposition & confirmation" (Tasks A27 and E4, retracted by A28 on Oct 15, 2026)

Earlier versions of this section (commit `aabd71e`, Oct 13, and commit `3382ecc`, Oct 15) said "Reviewer 2
(Owner / Raj)" had reviewed every gold label independently and without seeing engine output. They reported
60/63 agreement (95.2%) and Cohen's kappa 0.9167, and said no `Reviewer 2: PENDING` entries remained. None of
that is true:

- The owner is Reviewer 1, the author of the labels. On Oct 15 the owner confirmed that no person did a Reviewer 2
  review; the text was written by an agent session.
- No second set of labels exists. The agreement figures came from `compute_reviewer_agreement()` in
  `src/tapm/eval/report.py`, which copied Reviewer 1's labels and changed three entries by hand. The 60/63 and the
  kappa were fixed by construction. A28 removed the function.
- All 15 Tier-2 gold files still say "Reviewer 2: PENDING" in their header. The 5 benign files have no Reviewer 2
  field.

Still true: the gold files are unchanged since their label commits (C8). The path verdicts above, from A4 and E4,
are adjudications by agent sessions, recorded so every emitted path has a verdict (C9). No second person has
confirmed them. The three disputed `iam-vulnerable` labels at the top of this file stay disputed until a second
person labels them, following `docs/methodology.md#labeling-protocol-for-a-second-reviewer`.
