# Scanner findings

40 findings from Checkov, tfsec and Trivy on this plan.

| Tool | Rule | Severity | Resource | Location | Finding |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_28 | unrated | aws_lb.web | alb.tf:1 | Ensure public facing ALB are protected by WAF |
| checkov | CKV_AWS_150 | unrated | aws_lb.web | alb.tf:1 | Ensure that Load Balancer has deletion protection enabled |
| checkov | CKV_AWS_91 | unrated | aws_lb.web | alb.tf:1 | Ensure the ELBv2 (Application/Network) has access logging enabled |
| checkov | CKV_AWS_79 | unrated | aws_instance.app | app.tf:1 | Ensure Instance Metadata Service Version 1 is not enabled |
| checkov | CKV2_AWS_11 | unrated | aws_vpc.main | network.tf:1 | Ensure VPC flow logging is enabled in all VPCs |
| checkov | CKV2_AWS_12 | unrated | aws_vpc.main | network.tf:1 | Ensure the default security group of every VPC restricts all traffic |
| checkov | CKV2_AWS_61 | unrated | aws_s3_bucket.customer_data | storage.tf:1 | Ensure that an S3 bucket has a lifecycle configuration |
| checkov | CKV2_AWS_62 | unrated | aws_s3_bucket.customer_data | storage.tf:1 | Ensure S3 buckets should have event notifications enabled |
| checkov | CKV_AWS_144 | unrated | aws_s3_bucket.customer_data | storage.tf:1 | Ensure that S3 bucket has cross-region replication enabled |
| checkov | CKV_AWS_18 | unrated | aws_s3_bucket.customer_data | storage.tf:1 | Ensure the S3 bucket has access logging enabled |
| checkov | CKV_AWS_21 | unrated | aws_s3_bucket.customer_data | storage.tf:1 | Ensure all data stored in the S3 bucket have versioning enabled |
| checkov | CKV2_AWS_61 | unrated | aws_s3_bucket.reports | storage.tf:28 | Ensure that an S3 bucket has a lifecycle configuration |
| checkov | CKV2_AWS_62 | unrated | aws_s3_bucket.reports | storage.tf:28 | Ensure S3 buckets should have event notifications enabled |
| checkov | CKV_AWS_144 | unrated | aws_s3_bucket.reports | storage.tf:28 | Ensure that S3 bucket has cross-region replication enabled |
| checkov | CKV_AWS_145 | unrated | aws_s3_bucket.reports | storage.tf:28 | Ensure that S3 buckets are encrypted with KMS by default |
| checkov | CKV_AWS_18 | unrated | aws_s3_bucket.reports | storage.tf:28 | Ensure the S3 bucket has access logging enabled |
| checkov | CKV_AWS_21 | unrated | aws_s3_bucket.reports | storage.tf:28 | Ensure all data stored in the S3 bucket have versioning enabled |
| tfsec | aws-ec2-no-public-ingress-sgr | critical | aws_security_group.alb | network.tf:77 | Security group rule allows ingress from public internet. |
| tfsec | aws-ec2-no-public-egress-sgr | critical | aws_security_group.app | network.tf:107 | Security group rule allows egress to multiple public internet addresses. |
| tfsec | aws-elb-alb-not-public | high | aws_lb.web | alb.tf:3 | Load balancer is exposed publicly. |
| tfsec | aws-ec2-enforce-http-token-imds | high | aws_instance.app | app.tf:12 | Instance does not require IMDS access to require a token |
| tfsec | aws-iam-no-policy-wildcards | high | aws_iam_role_policy.app_s3 | iam.tf:26 | IAM policy document uses sensitive action 's3:GetObject' on wildcarded resource 'arn:aws:s3:::*' |
| tfsec | aws-s3-encryption-customer-key | high | aws_s3_bucket_server_side_encryption_configuration.customer_data | storage.tf:18 | Bucket does not encrypt data with a customer managed key. |
| tfsec | aws-s3-enable-bucket-encryption | high | aws_s3_bucket.reports | storage.tf:28 | Bucket does not have encryption enabled |
| tfsec | aws-s3-encryption-customer-key | high | aws_s3_bucket.reports | storage.tf:28 | Bucket does not encrypt data with a customer managed key. |
| tfsec | aws-ec2-require-vpc-flow-logs-for-all-vpcs | medium | aws_vpc.main | network.tf:1 | VPC Flow Logs is not enabled for VPC  |
| tfsec | aws-s3-enable-bucket-logging | medium | aws_s3_bucket.customer_data | storage.tf:1 | Bucket does not have logging enabled |
| tfsec | aws-s3-enable-versioning | medium | aws_s3_bucket.customer_data | storage.tf:1 | Bucket does not have versioning enabled |
| tfsec | aws-s3-enable-bucket-logging | medium | aws_s3_bucket.reports | storage.tf:28 | Bucket does not have logging enabled |
| tfsec | aws-s3-enable-versioning | medium | aws_s3_bucket.reports | storage.tf:28 | Bucket does not have versioning enabled |
| trivy | AWS-0104 | critical | aws_security_group.app | network.tf:107 | A security group rule should not allow unrestricted egress to any IP address. |
| trivy | AWS-0053 | high | aws_lb.web | alb.tf:3 | Load balancer is exposed to the internet. |
| trivy | AWS-0028 | high | aws_instance.app | app.tf:12 | aws_instance should activate session tokens for Instance Metadata Service. |
| trivy | AWS-0132 | high | aws_s3_bucket_server_side_encryption_configuration.customer_data | storage.tf:18 | S3 encryption should use Customer Managed Keys |
| trivy | AWS-0132 | high | aws_s3_bucket.reports | storage.tf:28 | S3 encryption should use Customer Managed Keys |
| trivy | AWS-0178 | medium | aws_vpc.main | network.tf:1 | VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet "Rejects" for VPCs. |
| trivy | AWS-0090 | medium | aws_s3_bucket.customer_data | storage.tf:1 | S3 Data should be versioned |
| trivy | AWS-0090 | medium | aws_s3_bucket.reports | storage.tf:28 | S3 Data should be versioned |
| trivy | AWS-0089 | low | aws_s3_bucket.customer_data | storage.tf:1 | S3 Bucket Logging |
| trivy | AWS-0089 | low | aws_s3_bucket.reports | storage.tf:28 | S3 Bucket Logging |
