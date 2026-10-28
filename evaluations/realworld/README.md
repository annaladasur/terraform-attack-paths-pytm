# Benign real-world modules evaluation (E6)

Evaluation of the engine against benign, production-grade public Terraform modules (`terraform-aws-modules/*`) to verify that the pipeline remains quiet (zero false paths) on real-world architectures with declared sensitive targets.

## Hypothesis & Acceptance Criteria

* **Question (DEMO-BUILD-PLAN §6 E4/E6):** Does the engine stay quiet on benign real-world modules?
* **Hypothesis:** On well-architected public modules with declared sensitive targets (database subnets, private databases, secure buckets, segmented security groups, least-privilege IAM roles), the reachability engine reports **0 false attack paths** (0 FP).
* **Mode:** Deterministic (`RunConfig`).
* **Evidence:** `evaluations/results/realworld-benign.json`, feeding talk slide 14 ("0 false paths on benign real-world modules").

## Dataset

Five public modules from the canonical `terraform-aws-modules` collection at frozen commits:

1. `realworld-vpc-complete`: `terraform-aws-modules/terraform-aws-vpc` (`examples/complete`) at `b3abd6d` (v5.19.0). Complete multi-tier VPC with public, private, and database subnets. Declared target: database subnet group.
2. `realworld-security-group-complete`: `terraform-aws-modules/terraform-aws-security-group` (`examples/complete`) at `b3c1b2e` (v5.3.0). Complete segmented security groups for web, database, and bastion tiers. Declared target: database security group.
3. `realworld-s3-bucket-complete`: `terraform-aws-modules/terraform-aws-s3-bucket` (`examples/complete`) at `8a0b697` (v4.1.2). Complete S3 bucket with public access block, TLS-only policy, SSE-KMS encryption. Declared target: secure S3 bucket.
4. `realworld-rds-complete`: `terraform-aws-modules/terraform-aws-rds` (`examples/complete-postgres`) at `7c83995` (v6.3.0). Production PostgreSQL database in private subnet group, `publicly_accessible = false`. Declared target: RDS instance.
5. `realworld-iam-role`: `terraform-aws-modules/terraform-aws-iam` (`examples/iam-role`) at `da8e6a8` (v5.52.2). Scoped IAM roles with MFA conditions and explicit trusted principal ARNs. Declared target: admin role.

## Order of Execution

Ground-truth reachability labels (`evaluations/realworld/gold/`) and manifest are committed to git **before** the engine run.
