# Orders Service Demo Infrastructure (`infra-demo`)

This repository contains the Terraform infrastructure for the orders service demo used in the OWASP Global AppSec 2026 talk.

## Branches

This demo repository includes four canonical branches representing the evolution of PR #42:

1. **`main` (Base infrastructure)**:
   - The pre-PR state (from `demo/base/`).
   - ALB admits only private corporate traffic (`10.0.0.0/8`).
   - EC2 instance requires IMDSv2 (`http_tokens = "required"`).
   - IAM role policy scoped to reports bucket only (`[aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]`).
   - Security findings: 36 scanner findings, **0 attack paths**.
   - Gate verdict: **PASS**.

2. **`pr-42` (PR #42: go-live changes)**:
   - The orders service goes live (from fixture 006).
   - `network.tf`: ALB ingress opened to internet (`0.0.0.0/0`).
   - `app.tf`: IMDS relaxed to `"optional"` for legacy monitoring agent.
   - `iam.tf`: export policy widened to `arn:aws:s3:::*`.
   - Security findings: 40 scanner findings (4 new, 0 from the IAM change).
   - Attack path: **PATH-001** (HIGH) Internet -> ALB -> EC2 -> IAM role -> `aws_s3_bucket.customer_data` (confidential).
   - Gate verdict: **BLOCKED** at Level 3 (validate) and Level 4 (prevent).

3. **`fix` (Verified remediation)**:
   - Fixes the attack path by scoping the IAM policy back down to the reports bucket (`remediation-PATH-001.diff`).
   - Attacks paths: **0 paths reach sensitive targets**.
   - Gate verdict: **PASS**.

4. **`injection` (Prompt injection stress test)**:
   - Includes adversarial prompt injection comments in `app.tf` and `iam.tf` (from fixture 019).
   - Tests that the pipeline's deterministic AI boundary refuses prompt injection attempts without altering security truth.
   - Gate verdict: **BLOCKED** identically to PR #42.

## CI Workflow

The repository includes `.gitea/workflows/attack-paths.yml` which executes on every pull request and push to `main`, submitting the plan to `tapm serve` and blocking unapproved attack paths.
