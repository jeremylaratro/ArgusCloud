"""AWS EC2 and VPC security rules."""

from __future__ import annotations

from typing import List

from arguscloud.core.graph import AttackPath, Severity
from arguscloud.core.base import RuleContext, RuleResult
from arguscloud.core.registry import rules


@rules.rule(
    rule_id="aws-ec2-open-security-group",
    provider="aws",
    description="Security group allows ingress from 0.0.0.0/0",
    severity="medium",
    tags=["ec2", "networking"],
)
def rule_open_security_group(ctx: RuleContext) -> RuleResult:
    """Detect security groups with open ingress rules."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "SecurityGroup":
            continue

        if node.properties.get("has_open_ingress"):
            findings.append(AttackPath(
                src=node.id,
                dst="internet",
                rule_id="aws-ec2-open-security-group",
                severity=Severity.MEDIUM,
                description=f"Security group {node.properties.get('name')} allows ingress from 0.0.0.0/0",
                remediation="Restrict inbound rules to specific IP ranges or security groups",
            ))

    return RuleResult(
        rule_id="aws-ec2-open-security-group",
        description="Security group open to internet",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-ec2-imds-exposure",
    provider="aws",
    description="Public EC2 instance with IAM role (IMDS credential theft risk)",
    severity="medium",
    tags=["ec2", "credential-theft"],
)
def rule_imds_exposure(ctx: RuleContext) -> RuleResult:
    """Detect public EC2 instances with attached IAM roles."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "EC2Instance":
            continue

        has_public_ip = bool(node.properties.get("public_ip"))
        has_role = bool(node.properties.get("iam_instance_profile"))
        imds_v2_required = node.properties.get("imds_v2_required", False)

        if has_public_ip and has_role:
            severity = Severity.MEDIUM if imds_v2_required else Severity.HIGH

            findings.append(AttackPath(
                src=node.id,
                dst="imds:credential-theft",
                rule_id="aws-ec2-imds-exposure",
                severity=severity,
                description=f"Public instance with IAM role attached (IMDSv2: {imds_v2_required})",
                remediation="Require IMDSv2, restrict security groups, or remove public IP",
            ))

    return RuleResult(
        rule_id="aws-ec2-imds-exposure",
        description="IMDS credential exposure risk",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-ec2-public-snapshot",
    provider="aws",
    description="EC2 snapshot is publicly shared",
    severity="high",
    tags=["ec2", "data-exposure"],
)
def rule_public_snapshot(ctx: RuleContext) -> RuleResult:
    """Detect publicly shared EC2 snapshots."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "Snapshot":
            continue

        if node.properties.get("is_public"):
            findings.append(AttackPath(
                src=node.id,
                dst="internet",
                rule_id="aws-ec2-public-snapshot",
                severity=Severity.HIGH,
                description="EC2 snapshot is publicly accessible",
                remediation="Remove public sharing permissions from the snapshot",
            ))

    return RuleResult(
        rule_id="aws-ec2-public-snapshot",
        description="Public EC2 snapshot",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-ec2-public-ami",
    provider="aws",
    description="AMI is publicly shared",
    severity="medium",
    tags=["ec2", "data-exposure"],
)
def rule_public_ami(ctx: RuleContext) -> RuleResult:
    """Detect publicly shared AMIs."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "AMI":
            continue

        if node.properties.get("public"):
            findings.append(AttackPath(
                src=node.id,
                dst="internet",
                rule_id="aws-ec2-public-ami",
                severity=Severity.MEDIUM,
                description=f"AMI {node.properties.get('name')} is publicly launchable",
                remediation="Remove public launch permissions from the AMI",
            ))

    return RuleResult(
        rule_id="aws-ec2-public-ami",
        description="Public AMI",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-ec2-unencrypted-snapshot",
    provider="aws",
    description="EC2 snapshot is not encrypted",
    severity="medium",
    tags=["ec2", "encryption"],
)
def rule_unencrypted_snapshot(ctx: RuleContext) -> RuleResult:
    """Detect unencrypted EC2 snapshots."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "Snapshot":
            continue

        if node.properties.get("encrypted") is False:
            findings.append(AttackPath(
                src=node.id,
                dst="ec2:unencrypted",
                rule_id="aws-ec2-unencrypted-snapshot",
                severity=Severity.MEDIUM,
                description="EC2 snapshot is not encrypted",
                remediation="Create an encrypted copy of the snapshot and delete the unencrypted version",
            ))

    return RuleResult(
        rule_id="aws-ec2-unencrypted-snapshot",
        description="Unencrypted snapshot",
        attack_paths=findings,
        passed=len(findings) == 0,
    )
