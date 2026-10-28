# Scanner findings

32 findings from Checkov, tfsec and Trivy on this plan.

| Tool | Rule | Severity | Resource | Location | Finding |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_11 | unrated | aws_vpc.main | main.tf:1 | Ensure VPC flow logging is enabled in all VPCs |
| checkov | CKV2_AWS_12 | unrated | aws_vpc.main | main.tf:1 | Ensure the default security group of every VPC restricts all traffic |
| checkov | CKV_AWS_130 | unrated | aws_subnet.public | main.tf:9 | Ensure VPC subnets do not assign public IP by default |
| checkov | CKV_AWS_23 | unrated | aws_security_group.api | main.tf:35 | Ensure every security group and rule has a description |
| checkov | CKV_AWS_355 | unrated | aws_iam_role_policy.app | main.tf:71 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| checkov | CKV_AWS_126 | unrated | aws_instance.api | main.tf:87 | Ensure that detailed monitoring is enabled for EC2 instances |
| checkov | CKV_AWS_135 | unrated | aws_instance.api | main.tf:87 | Ensure that EC2 is EBS optimized |
| checkov | CKV_AWS_79 | unrated | aws_instance.api | main.tf:87 | Ensure Instance Metadata Service Version 1 is not enabled |
| checkov | CKV_AWS_8 | unrated | aws_instance.api | main.tf:87 | Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted |
| checkov | CKV_AWS_88 | unrated | aws_instance.api | main.tf:87 | EC2 instance should not have public IP. |
| checkov | CKV_AWS_119 | unrated | aws_dynamodb_table.customers | main.tf:101 | Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK |
| checkov | CKV_AWS_28 | unrated | aws_dynamodb_table.customers | main.tf:101 | Ensure DynamoDB point in time recovery (backup) is enabled |
| tfsec | aws-ec2-no-public-ingress-sgr | critical | aws_security_group.api | main.tf:46 | Security group rule allows ingress from public internet. |
| tfsec | aws-ec2-no-public-ingress-sgr | critical | aws_security_group.api | main.tf:46 | Security group rule allows ingress from public internet. |
| tfsec | aws-ec2-no-public-ingress-sgr | critical | aws_security_group.api | main.tf:46 | Security group rule allows ingress from public internet. |
| tfsec | aws-ec2-no-public-ingress-sgr | critical | aws_security_group.api | main.tf:46 | Security group rule allows ingress from public internet. |
| tfsec | aws-ec2-no-public-ip-subnet | high | aws_subnet.public | main.tf:13 | Subnet associates public IP address. |
| tfsec | aws-iam-no-policy-wildcards | high | aws_iam_role_policy.app | main.tf:76 | IAM policy document uses sensitive action 'dynamodb:GetItem' on wildcarded resource '*' |
| tfsec | aws-ec2-enable-at-rest-encryption | high | aws_instance.api | main.tf:87 | Root block device is not encrypted. |
| tfsec | aws-ec2-enforce-http-token-imds | high | aws_instance.api | main.tf:97 | Instance does not require IMDS access to require a token |
| tfsec | aws-dynamodb-enable-at-rest-encryption | high | aws_dynamodb_table.customers | main.tf:101 | Table encryption is not enabled. |
| tfsec | aws-ec2-require-vpc-flow-logs-for-all-vpcs | medium | aws_vpc.main | main.tf:1 | VPC Flow Logs is not enabled for VPC  |
| tfsec | aws-dynamodb-enable-recovery | medium | aws_dynamodb_table.customers | main.tf:101 | Point-in-time recovery is not enabled. |
| tfsec | aws-ec2-add-description-to-security-group | low | aws_security_group.api | main.tf:35 | Security group explicitly uses the default description. |
| tfsec | aws-dynamodb-table-customer-key | low | aws_dynamodb_table.customers | main.tf:101 | Table encryption does not use a customer-managed KMS key. |
| trivy | AWS-0164 | high | aws_subnet.public | main.tf:13 | Instances in a subnet should not receive a public IP address by default. |
| trivy | AWS-0131 | high | aws_instance.api | main.tf:87 | Instance with unencrypted block device. |
| trivy | AWS-0028 | high | aws_instance.api | main.tf:97 | aws_instance should activate session tokens for Instance Metadata Service. |
| trivy | AWS-0178 | medium | aws_vpc.main | main.tf:1 | VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet "Rejects" for VPCs. |
| trivy | AWS-0024 | medium | aws_dynamodb_table.customers | main.tf:101 | Point in time recovery should be enabled to protect DynamoDB table |
| trivy | AWS-0099 | low | aws_security_group.api | main.tf:35 | Missing description for security group. |
| trivy | AWS-0025 | low | aws_dynamodb_table.customers | main.tf:101 | DynamoDB tables should use at rest encryption with a Customer Managed Key |
