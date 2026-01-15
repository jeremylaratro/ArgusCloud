"""AWS resource collectors."""

from .iam import collect_iam_roles, collect_iam_users, collect_iam_policies, collect_iam_summary
from .sts import collect_sts_identity
from .org import collect_organizations
from .s3 import collect_s3
from .ec2 import collect_ec2_instances, collect_ec2_snapshots_images, collect_vpc
from .security import (
    collect_cloudtrail,
    collect_guardduty,
    collect_securityhub,
    collect_detective,
    collect_config,
    collect_waf,
    collect_shield,
    collect_firewall_manager,
)
from .compute import collect_lambda, collect_eks, collect_ecr
from .storage import collect_kms, collect_secretsmanager, collect_ssm_parameters, collect_rds
from .messaging import collect_sns, collect_sqs
from .devops import collect_codebuild, collect_codepipeline, collect_cloudformation, collect_cloudwatch
from .identity import collect_sso

__all__ = [
    # IAM
    "collect_iam_roles",
    "collect_iam_users",
    "collect_iam_policies",
    "collect_iam_summary",
    # STS
    "collect_sts_identity",
    # Organizations
    "collect_organizations",
    # S3
    "collect_s3",
    # EC2/VPC
    "collect_ec2_instances",
    "collect_ec2_snapshots_images",
    "collect_vpc",
    # Security
    "collect_cloudtrail",
    "collect_guardduty",
    "collect_securityhub",
    "collect_detective",
    "collect_config",
    "collect_waf",
    "collect_shield",
    "collect_firewall_manager",
    # Compute
    "collect_lambda",
    "collect_eks",
    "collect_ecr",
    # Storage/Secrets
    "collect_kms",
    "collect_secretsmanager",
    "collect_ssm_parameters",
    "collect_rds",
    # Messaging
    "collect_sns",
    "collect_sqs",
    # DevOps
    "collect_codebuild",
    "collect_codepipeline",
    "collect_cloudformation",
    "collect_cloudwatch",
    # Identity
    "collect_sso",
]
