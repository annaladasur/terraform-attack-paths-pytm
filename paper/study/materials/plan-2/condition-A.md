# Scanner findings

32 findings from Checkov, tfsec and Trivy on this plan.

| Tool | Rule | Severity | Resource | Location | Finding |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_11 | unrated | aws_vpc.main | main.tf:1 | Ensure VPC flow logging is enabled in all VPCs |
| checkov | CKV2_AWS_12 | unrated | aws_vpc.main | main.tf:1 | Ensure the default security group of every VPC restricts all traffic |
| checkov | CKV_AWS_130 | unrated | aws_subnet.public | main.tf:9 | Ensure VPC subnets do not assign public IP by default |
| checkov | CKV_AWS_23 | unrated | aws_security_group.api | main.tf:30 | Ensure every security group and rule has a description |
| checkov | CKV_AWS_126 | unrated | aws_instance.api | main.tf:62 | Ensure that detailed monitoring is enabled for EC2 instances |
| checkov | CKV_AWS_135 | unrated | aws_instance.api | main.tf:62 | Ensure that EC2 is EBS optimized |
| checkov | CKV_AWS_8 | unrated | aws_instance.api | main.tf:62 | Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted |
| checkov | CKV_AWS_88 | unrated | aws_instance.api | main.tf:62 | EC2 instance should not have public IP. |
| checkov | CKV2_AWS_61 | unrated | aws_s3_bucket.ledger | main.tf:76 | Ensure that an S3 bucket has a lifecycle configuration |
| checkov | CKV2_AWS_62 | unrated | aws_s3_bucket.ledger | main.tf:76 | Ensure S3 buckets should have event notifications enabled |
| checkov | CKV_AWS_144 | unrated | aws_s3_bucket.ledger | main.tf:76 | Ensure that S3 bucket has cross-region replication enabled |
| checkov | CKV_AWS_145 | unrated | aws_s3_bucket.ledger | main.tf:76 | Ensure that S3 buckets are encrypted with KMS by default |
| checkov | CKV_AWS_18 | unrated | aws_s3_bucket.ledger | main.tf:76 | Ensure the S3 bucket has access logging enabled |
| checkov | CKV_AWS_21 | unrated | aws_s3_bucket.ledger | main.tf:76 | Ensure all data stored in the S3 bucket have versioning enabled |
| tfsec | aws-ec2-no-public-ingress-sgr | critical | aws_security_group.api | main.tf:38 | Security group rule allows ingress from public internet. |
| tfsec | aws-ec2-no-public-ip-subnet | high | aws_subnet.public | main.tf:13 | Subnet associates public IP address. |
| tfsec | aws-ec2-enable-at-rest-encryption | high | aws_instance.api | main.tf:62 | Root block device is not encrypted. |
| tfsec | aws-s3-enable-bucket-encryption | high | aws_s3_bucket.ledger | main.tf:76 | Bucket does not have encryption enabled |
| tfsec | aws-s3-encryption-customer-key | high | aws_s3_bucket.ledger | main.tf:76 | Bucket does not encrypt data with a customer managed key. |
| tfsec | aws-ec2-require-vpc-flow-logs-for-all-vpcs | medium | aws_vpc.main | main.tf:1 | VPC Flow Logs is not enabled for VPC  |
| tfsec | aws-s3-enable-bucket-logging | medium | aws_s3_bucket.ledger | main.tf:76 | Bucket does not have logging enabled |
| tfsec | aws-s3-enable-versioning | medium | aws_s3_bucket.ledger | main.tf:76 | Bucket does not have versioning enabled |
| tfsec | aws-ec2-add-description-to-security-group | low | aws_security_group.api | main.tf:30 | Security group explicitly uses the default description. |
| tfsec | aws-ec2-add-description-to-security-group-rule | low | aws_security_group.api | main.tf:34 | Security group rule does not have a description. |
| trivy | AWS-0164 | high | aws_subnet.public | main.tf:13 | Instances in a subnet should not receive a public IP address by default. |
| trivy | AWS-0131 | high | aws_instance.api | main.tf:62 | Instance with unencrypted block device. |
| trivy | AWS-0132 | high | aws_s3_bucket.ledger | main.tf:76 | S3 encryption should use Customer Managed Keys |
| trivy | AWS-0178 | medium | aws_vpc.main | main.tf:1 | VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet "Rejects" for VPCs. |
| trivy | AWS-0090 | medium | aws_s3_bucket.ledger | main.tf:76 | S3 Data should be versioned |
| trivy | AWS-0099 | low | aws_security_group.api | main.tf:30 | Missing description for security group. |
| trivy | AWS-0124 | low | aws_security_group.api | main.tf:34 | Missing description for security group rule. |
| trivy | AWS-0089 | low | aws_s3_bucket.ledger | main.tf:76 | S3 Bucket Logging |
