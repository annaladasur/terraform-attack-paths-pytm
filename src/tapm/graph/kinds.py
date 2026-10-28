"""Terraform resource type -> security-graph kind.

Only types listed here are *modeled*. Every other resource still becomes a node
(so reference edges and coverage metrics stay honest) but is marked
``modeled: false``.
"""

from __future__ import annotations

# type: (aws_type, category, attribute allowlist carried into the graph)
KINDS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    # network
    "aws_vpc": ("AWS::EC2::VPC", "network", ("cidr_block",)),
    "aws_subnet": ("AWS::EC2::Subnet", "network", ("cidr_block", "availability_zone", "map_public_ip_on_launch")),
    "aws_internet_gateway": ("AWS::EC2::InternetGateway", "network", ()),
    "aws_route_table": ("AWS::EC2::RouteTable", "network", ()),
    "aws_route_table_association": ("AWS::EC2::SubnetRouteTableAssociation", "network", ()),
    "aws_security_group": ("AWS::EC2::SecurityGroup", "network", ("name",)),
    "aws_security_group_rule": ("AWS::EC2::SecurityGroupRule", "network", ("type", "from_port", "to_port", "protocol", "cidr_blocks")),
    "aws_vpc_security_group_ingress_rule": ("AWS::EC2::SecurityGroupIngress", "network", ("from_port", "to_port", "ip_protocol", "cidr_ipv4", "cidr_ipv6")),
    "aws_vpc_security_group_egress_rule": ("AWS::EC2::SecurityGroupEgress", "network", ()),
    "aws_lb": ("AWS::ElasticLoadBalancingV2::LoadBalancer", "network", ("name", "internal", "load_balancer_type")),
    "aws_alb": ("AWS::ElasticLoadBalancingV2::LoadBalancer", "network", ("name", "internal", "load_balancer_type")),
    "aws_lb_listener": ("AWS::ElasticLoadBalancingV2::Listener", "network", ("port", "protocol")),
    "aws_lb_target_group": ("AWS::ElasticLoadBalancingV2::TargetGroup", "network", ("port", "protocol", "target_type")),
    "aws_lb_target_group_attachment": ("AWS::ElasticLoadBalancingV2::TargetGroupAttachment", "network", ("port",)),
    "aws_lambda_function_url": ("AWS::Lambda::Url", "network", ("authorization_type",)),
    "aws_route53_record": ("AWS::Route53::RecordSet", "network", ("name", "type")),
    "aws_api_gateway_rest_api": ("AWS::ApiGateway::RestApi", "network", ("name",)),
    "aws_api_gateway_method": ("AWS::ApiGateway::Method", "network", ("http_method", "authorization")),
    "aws_api_gateway_integration": ("AWS::ApiGateway::Integration", "network", ("type", "integration_http_method")),
    "aws_apigatewayv2_api": ("AWS::ApiGatewayV2::Api", "network", ("name", "protocol_type")),
    "aws_apigatewayv2_route": ("AWS::ApiGatewayV2::Route", "network", ("route_key", "authorization_type")),
    "aws_apigatewayv2_integration": ("AWS::ApiGatewayV2::Integration", "network", ("integration_type",)),
    "aws_lambda_permission": ("AWS::Lambda::Permission", "network", ("principal", "action")),
    # compute
    "aws_instance": ("AWS::EC2::Instance", "compute", ("instance_type", "associate_public_ip_address")),
    "aws_lambda_function": ("AWS::Lambda::Function", "compute", ("function_name", "runtime")),
    "aws_ecs_service": ("AWS::ECS::Service", "compute", ("name", "launch_type")),
    "aws_ecs_task_definition": ("AWS::ECS::TaskDefinition", "other", ("family", "network_mode", "pid_mode")),
    "aws_ecs_cluster": ("AWS::ECS::Cluster", "other", ("name",)),
    "aws_launch_template": ("AWS::EC2::LaunchTemplate", "other", ("name", "name_prefix")),
    # identity
    "aws_iam_role": ("AWS::IAM::Role", "identity", ("name", "path")),
    "aws_iam_user": ("AWS::IAM::User", "identity", ("name", "path")),
    "aws_iam_group": ("AWS::IAM::Group", "identity", ("name",)),
    "aws_iam_instance_profile": ("AWS::IAM::InstanceProfile", "identity", ("name",)),
    "aws_iam_policy": ("AWS::IAM::ManagedPolicy", "identity", ("name",)),
    "aws_iam_role_policy": ("AWS::IAM::RolePolicy", "identity", ("name",)),
    "aws_iam_user_policy": ("AWS::IAM::UserPolicy", "identity", ("name",)),
    "aws_iam_group_policy": ("AWS::IAM::GroupPolicy", "identity", ("name",)),
    "aws_iam_role_policy_attachment": ("AWS::IAM::RolePolicyAttachment", "identity", ("policy_arn",)),
    "aws_iam_user_policy_attachment": ("AWS::IAM::UserPolicyAttachment", "identity", ("policy_arn",)),
    "aws_iam_group_policy_attachment": ("AWS::IAM::GroupPolicyAttachment", "identity", ("policy_arn",)),
    "aws_iam_policy_attachment": ("AWS::IAM::PolicyAttachment", "identity", ("policy_arn",)),
    "aws_iam_group_membership": ("AWS::IAM::UserToGroupAddition", "identity", ()),
    "aws_iam_user_group_membership": ("AWS::IAM::UserToGroupAddition", "identity", ()),
    "aws_iam_access_key": ("AWS::IAM::AccessKey", "identity", ()),
    # data
    "aws_s3_bucket": ("AWS::S3::Bucket", "data", ("bucket",)),
    "aws_s3_bucket_policy": ("AWS::S3::BucketPolicy", "data", ()),
    "aws_s3_bucket_public_access_block": ("AWS::S3::PublicAccessBlock", "data",
                                          ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")),
    "aws_s3_bucket_acl": ("AWS::S3::BucketAcl", "data", ("acl",)),
    "aws_s3_bucket_server_side_encryption_configuration": ("AWS::S3::BucketEncryption", "data", ()),
    "aws_db_instance": ("AWS::RDS::DBInstance", "data", ("identifier", "engine", "publicly_accessible", "storage_encrypted", "port")),
    "aws_dynamodb_table": ("AWS::DynamoDB::Table", "data", ("name",)),
    "aws_secretsmanager_secret": ("AWS::SecretsManager::Secret", "data", ("name",)),
    "aws_ssm_parameter": ("AWS::SSM::Parameter", "data", ("name", "type")),
    "aws_kms_key": ("AWS::KMS::Key", "data", ("description",)),
}

# Resource kinds that can be the *target* (asset) of an attack path.
ASSET_TYPES = (
    "aws_s3_bucket",
    "aws_db_instance",
    "aws_dynamodb_table",
    "aws_secretsmanager_secret",
    "aws_ssm_parameter",
    "aws_kms_key",
)

WORKLOAD_TYPES = ("aws_instance", "aws_lambda_function", "aws_ecs_service")
PRINCIPAL_TYPES = ("aws_iam_role", "aws_iam_user")


def kind_of(tf_type: str) -> tuple[str, str, tuple[str, ...], bool]:
    if tf_type in KINDS:
        aws_type, category, attrs = KINDS[tf_type]
        return aws_type, category, attrs, True
    return f"terraform::{tf_type}", "other", (), False
