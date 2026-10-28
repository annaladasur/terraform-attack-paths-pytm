# Scanner findings

64 findings from Checkov, tfsec and Trivy on this plan.

| Tool | Rule | Severity | Resource | Location | Finding |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_6 | unrated | aws_s3_bucket.exports | main.tf:1 | Ensure that S3 bucket has a Public Access block |
| checkov | CKV2_AWS_61 | unrated | aws_s3_bucket.exports | main.tf:1 | Ensure that an S3 bucket has a lifecycle configuration |
| checkov | CKV2_AWS_62 | unrated | aws_s3_bucket.exports | main.tf:1 | Ensure S3 buckets should have event notifications enabled |
| checkov | CKV_AWS_144 | unrated | aws_s3_bucket.exports | main.tf:1 | Ensure that S3 bucket has cross-region replication enabled |
| checkov | CKV_AWS_145 | unrated | aws_s3_bucket.exports | main.tf:1 | Ensure that S3 buckets are encrypted with KMS by default |
| checkov | CKV_AWS_18 | unrated | aws_s3_bucket.exports | main.tf:1 | Ensure the S3 bucket has access logging enabled |
| checkov | CKV_AWS_21 | unrated | aws_s3_bucket.exports | main.tf:1 | Ensure all data stored in the S3 bucket have versioning enabled |
| checkov | CKV_AWS_70 | unrated | aws_s3_bucket_policy.exports | main.tf:9 | Ensure S3 bucket does not allow an action with any Principal |
| checkov | CKV2_AWS_6 | unrated | aws_s3_bucket.site | main.tf:26 | Ensure that S3 bucket has a Public Access block |
| checkov | CKV2_AWS_61 | unrated | aws_s3_bucket.site | main.tf:26 | Ensure that an S3 bucket has a lifecycle configuration |
| checkov | CKV2_AWS_62 | unrated | aws_s3_bucket.site | main.tf:26 | Ensure S3 buckets should have event notifications enabled |
| checkov | CKV_AWS_144 | unrated | aws_s3_bucket.site | main.tf:26 | Ensure that S3 bucket has cross-region replication enabled |
| checkov | CKV_AWS_145 | unrated | aws_s3_bucket.site | main.tf:26 | Ensure that S3 buckets are encrypted with KMS by default |
| checkov | CKV_AWS_18 | unrated | aws_s3_bucket.site | main.tf:26 | Ensure the S3 bucket has access logging enabled |
| checkov | CKV_AWS_21 | unrated | aws_s3_bucket.site | main.tf:26 | Ensure all data stored in the S3 bucket have versioning enabled |
| checkov | CKV_AWS_70 | unrated | aws_s3_bucket_policy.site | main.tf:34 | Ensure S3 bucket does not allow an action with any Principal |
| checkov | CKV2_AWS_61 | unrated | aws_s3_bucket.backups | main.tf:51 | Ensure that an S3 bucket has a lifecycle configuration |
| checkov | CKV2_AWS_62 | unrated | aws_s3_bucket.backups | main.tf:51 | Ensure S3 buckets should have event notifications enabled |
| checkov | CKV_AWS_144 | unrated | aws_s3_bucket.backups | main.tf:51 | Ensure that S3 bucket has cross-region replication enabled |
| checkov | CKV_AWS_145 | unrated | aws_s3_bucket.backups | main.tf:51 | Ensure that S3 buckets are encrypted with KMS by default |
| checkov | CKV_AWS_18 | unrated | aws_s3_bucket.backups | main.tf:51 | Ensure the S3 bucket has access logging enabled |
| checkov | CKV_AWS_21 | unrated | aws_s3_bucket.backups | main.tf:51 | Ensure all data stored in the S3 bucket have versioning enabled |
| checkov | CKV_AWS_70 | unrated | aws_s3_bucket_policy.backups | main.tf:59 | Ensure S3 bucket does not allow an action with any Principal |
| tfsec | aws-s3-block-public-acls | high | aws_s3_bucket.exports | main.tf:1 | No public access block so not blocking public acls |
| tfsec | aws-s3-block-public-policy | high | aws_s3_bucket.exports | main.tf:1 | No public access block so not blocking public policies |
| tfsec | aws-s3-enable-bucket-encryption | high | aws_s3_bucket.exports | main.tf:1 | Bucket does not have encryption enabled |
| tfsec | aws-s3-encryption-customer-key | high | aws_s3_bucket.exports | main.tf:1 | Bucket does not encrypt data with a customer managed key. |
| tfsec | aws-s3-ignore-public-acls | high | aws_s3_bucket.exports | main.tf:1 | No public access block so not ignoring public acls |
| tfsec | aws-s3-no-public-buckets | high | aws_s3_bucket.exports | main.tf:1 | No public access block so not restricting public buckets |
| tfsec | aws-s3-block-public-acls | high | aws_s3_bucket.site | main.tf:26 | No public access block so not blocking public acls |
| tfsec | aws-s3-block-public-policy | high | aws_s3_bucket.site | main.tf:26 | No public access block so not blocking public policies |
| tfsec | aws-s3-enable-bucket-encryption | high | aws_s3_bucket.site | main.tf:26 | Bucket does not have encryption enabled |
| tfsec | aws-s3-encryption-customer-key | high | aws_s3_bucket.site | main.tf:26 | Bucket does not encrypt data with a customer managed key. |
| tfsec | aws-s3-ignore-public-acls | high | aws_s3_bucket.site | main.tf:26 | No public access block so not ignoring public acls |
| tfsec | aws-s3-no-public-buckets | high | aws_s3_bucket.site | main.tf:26 | No public access block so not restricting public buckets |
| tfsec | aws-s3-enable-bucket-encryption | high | aws_s3_bucket.backups | main.tf:51 | Bucket does not have encryption enabled |
| tfsec | aws-s3-encryption-customer-key | high | aws_s3_bucket.backups | main.tf:51 | Bucket does not encrypt data with a customer managed key. |
| tfsec | aws-s3-enable-bucket-logging | medium | aws_s3_bucket.exports | main.tf:1 | Bucket does not have logging enabled |
| tfsec | aws-s3-enable-versioning | medium | aws_s3_bucket.exports | main.tf:1 | Bucket does not have versioning enabled |
| tfsec | aws-s3-enable-bucket-logging | medium | aws_s3_bucket.site | main.tf:26 | Bucket does not have logging enabled |
| tfsec | aws-s3-enable-versioning | medium | aws_s3_bucket.site | main.tf:26 | Bucket does not have versioning enabled |
| tfsec | aws-s3-enable-bucket-logging | medium | aws_s3_bucket.backups | main.tf:51 | Bucket does not have logging enabled |
| tfsec | aws-s3-enable-versioning | medium | aws_s3_bucket.backups | main.tf:51 | Bucket does not have versioning enabled |
| tfsec | aws-s3-specify-public-access-block | low | aws_s3_bucket.exports | main.tf:1 | Bucket does not have a corresponding public access block. |
| tfsec | aws-s3-specify-public-access-block | low | aws_s3_bucket.site | main.tf:26 | Bucket does not have a corresponding public access block. |
| trivy | AWS-0086 | high | aws_s3_bucket.exports | main.tf:1 | S3 Access block should block public ACL |
| trivy | AWS-0087 | high | aws_s3_bucket.exports | main.tf:1 | S3 Access block should block public policy |
| trivy | AWS-0091 | high | aws_s3_bucket.exports | main.tf:1 | S3 Access Block should Ignore Public ACL |
| trivy | AWS-0093 | high | aws_s3_bucket.exports | main.tf:1 | S3 Access block should restrict public bucket to limit access |
| trivy | AWS-0132 | high | aws_s3_bucket.exports | main.tf:1 | S3 encryption should use Customer Managed Keys |
| trivy | AWS-0086 | high | aws_s3_bucket.site | main.tf:26 | S3 Access block should block public ACL |
| trivy | AWS-0087 | high | aws_s3_bucket.site | main.tf:26 | S3 Access block should block public policy |
| trivy | AWS-0091 | high | aws_s3_bucket.site | main.tf:26 | S3 Access Block should Ignore Public ACL |
| trivy | AWS-0093 | high | aws_s3_bucket.site | main.tf:26 | S3 Access block should restrict public bucket to limit access |
| trivy | AWS-0132 | high | aws_s3_bucket.site | main.tf:26 | S3 encryption should use Customer Managed Keys |
| trivy | AWS-0132 | high | aws_s3_bucket.backups | main.tf:51 | S3 encryption should use Customer Managed Keys |
| trivy | AWS-0090 | medium | aws_s3_bucket.exports | main.tf:1 | S3 Data should be versioned |
| trivy | AWS-0090 | medium | aws_s3_bucket.site | main.tf:26 | S3 Data should be versioned |
| trivy | AWS-0090 | medium | aws_s3_bucket.backups | main.tf:51 | S3 Data should be versioned |
| trivy | AWS-0089 | low | aws_s3_bucket.exports | main.tf:1 | S3 Bucket Logging |
| trivy | AWS-0094 | low | aws_s3_bucket.exports | main.tf:1 | S3 buckets should each define an aws_s3_bucket_public_access_block |
| trivy | AWS-0089 | low | aws_s3_bucket.site | main.tf:26 | S3 Bucket Logging |
| trivy | AWS-0094 | low | aws_s3_bucket.site | main.tf:26 | S3 buckets should each define an aws_s3_bucket_public_access_block |
| trivy | AWS-0089 | low | aws_s3_bucket.backups | main.tf:51 | S3 Bucket Logging |
