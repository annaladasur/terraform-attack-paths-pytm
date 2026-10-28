# Automated blind mapping: 2026-10-19

Three fresh-context reviewers covered AWS IAM, CloudGoat attack paths, and network/data controls. Inputs withheld original verdicts, routes, engine outputs and adjudications. Mapping outputs were sealed before comparison. This is an automated review; the second-person requirement in A27 remains unmet.

Coverage: 63/63 supplied pairs across 20 cases. TerraGoat has no supplied pairs; its separate inventory is explicitly non-exhaustive.

Labels: {'INVALID': 12, 'OUT_OF_SCOPE': 2, 'PARTIALLY_VALID': 18, 'VALID': 31}. 28 labels differ from the original labels. Every differing pair has a separate independent automated adjudication; no agreement rate or kappa is asserted because reviewer definitions include conditional reachability and differing scope judgments.

## Reviewers and evidence

- `iam-review.json`: AWS IAM authorization and privilege escalation; raw IAM plan only.
- `cloudgoat-review.json`: AWS attack paths; raw plans plus matching Terraform for unresolved expressions.
- `benign-review.json`: network/data controls; raw plans only.
- `inputs.json`: candidate pairs and compressed-plan hashes, with original verdicts/routes removed.
- `comparison.json`: exact coverage and post-seal comparison.
- `path-drift.json`: separate later forensic replay; reviewers had already sealed labels before accessing engine output.

## Next steps

1. Owner reviews the eight proposed gold corrections in `adjudication-summary.json`; all 28 initial classification differences now have independent automated dispositions in `adjudication-iam.json` and `adjudication-cloud-network.json`. Original gold and pre-commitment are preserved.
2. A person performs the separate blind review, or the owner explicitly accepts the single-human-labeler limitation.
3. Do not change frozen benchmark results from this review.

| Case | Entry | Target | Original | Automated blind |
|---|---|---|---|---|
| cloudgoat-beanstalk_secrets | aws_iam_user.low_priv_user | aws_secretsmanager_secret.final_flag | OUT_OF_SCOPE | VALID |
| cloudgoat-cloud_breach_s3 | internet | aws_s3_bucket.cg-cardholder-data-bucket | VALID | PARTIALLY_VALID |
| cloudgoat-codebuild_secrets | aws_iam_user.cg-solo | aws_db_instance.cg-psql-rds | OUT_OF_SCOPE | VALID |
| cloudgoat-data_secrets | aws_iam_user.start_user | aws_secretsmanager_secret.final_flag | OUT_OF_SCOPE | PARTIALLY_VALID |
| cloudgoat-ec2_ssrf | internet | aws_s3_bucket.secret_bucket | VALID | PARTIALLY_VALID |
| cloudgoat-ec2_ssrf | aws_iam_user.solus | aws_lambda_function.lambda_function | OUT_OF_SCOPE | VALID |
| cloudgoat-iam_privesc_by_ec2 | aws_iam_user.dev_user | aws:account-admin | VALID | PARTIALLY_VALID |
| cloudgoat-iam_privesc_by_rollback | aws_iam_user.raynor | aws:account-admin | VALID | PARTIALLY_VALID |
| cloudgoat-rds_snapshot | internet | aws_db_instance.cg-rds-db_instance | OUT_OF_SCOPE | INVALID |
| cloudgoat-secrets_in_the_cloud | aws_iam_user.low_priv_user | aws_secretsmanager_secret.this | OUT_OF_SCOPE | VALID |
| cloudgoat-vpc_peering_overexposed | internet | aws_db_instance.customer_db | OUT_OF_SCOPE | INVALID |
| cloudgoat-vpc_peering_overexposed | aws_iam_user.initial_user | aws_db_instance.customer_db | OUT_OF_SCOPE | INVALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc2-SetExistingDefaultPolicyVersion-user | aws:account-admin | VALID | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc6-UpdateLoginProfile-user | aws:account-admin | VALID | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc9-AttachRolePolicy-user | aws:account-admin | VALID | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc12-PutRolePolicy-user | aws:account-admin | VALID | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc16-PassRoleToNewLambdaThenTriggerWithNewDynamo-user | aws:account-admin | VALID | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc21-PassExistingRoleToNewDataPipeline-user | aws:account-admin | VALID | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc-AssumeRole-start-user | aws:account-admin | VALID | INVALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc-CloudFormationUpdateStack-user | aws:account-admin | OUT_OF_SCOPE | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc-ec2InstanceConnect-user | aws:account-admin | OUT_OF_SCOPE | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc-sageMakerCreatePresignedNotebookURL-user | aws:account-admin | OUT_OF_SCOPE | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc-ssmSendCommand-user | aws:account-admin | OUT_OF_SCOPE | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc-ssmStartSession-user | aws:account-admin | OUT_OF_SCOPE | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc17-EditExistingLambdaFunctionWithRole-user | aws:account-admin | OUT_OF_SCOPE | PARTIALLY_VALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc19-UpdateExistingGlueDevEndpoint-user | aws:account-admin | OUT_OF_SCOPE | PARTIALLY_VALID |
| realworld-security-group-complete | internet | module.postgresql.module.security_group.aws_security_group.this[0] | INVALID | OUT_OF_SCOPE |
| realworld-vpc-complete | internet | module.vpc.aws_db_subnet_group.database[0] | INVALID | OUT_OF_SCOPE |

## Independent adjudication complete

All 28 differing classifications were assessed by a different reviewer from the blind mapper. Eight corrections are proposed under the original labeling protocol; some confirm already logged disputes. They require owner acceptance before any revised benchmark. The other 20 preserve the original label with explicit scope/precondition qualifications. This is automated adjudication, not a second human review.

| Case | Entry | Target | Original | Proposed |
|---|---|---|---|---|
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc2-SetExistingDefaultPolicyVersion-user | aws:account-admin | VALID | OUT_OF_SCOPE |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc6-UpdateLoginProfile-user | aws:account-admin | VALID | OUT_OF_SCOPE |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc9-AttachRolePolicy-user | aws:account-admin | VALID | INVALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc12-PutRolePolicy-user | aws:account-admin | VALID | INVALID |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc16-PassRoleToNewLambdaThenTriggerWithNewDynamo-user | aws:account-admin | VALID | OUT_OF_SCOPE |
| iam-vulnerable | module.privesc-paths.aws_iam_user.privesc-AssumeRole-start-user | aws:account-admin | VALID | INVALID |
| cloudgoat-ec2_ssrf | aws_iam_user.solus | aws_lambda_function.lambda_function | OUT_OF_SCOPE | VALID |
| cloudgoat-secrets_in_the_cloud | aws_iam_user.low_priv_user | aws_secretsmanager_secret.this | OUT_OF_SCOPE | VALID |
