"""AWS S3 security rules."""

from __future__ import annotations

from typing import List

from arguscloud.core.graph import AttackPath, Severity
from arguscloud.core.base import RuleContext, RuleResult, extract_principals
from arguscloud.core.registry import rules


@rules.rule(
    rule_id="aws-s3-public-bucket",
    provider="aws",
    description="S3 bucket is publicly accessible",
    severity="high",
    tags=["s3", "data-exposure"],
)
def rule_public_s3(ctx: RuleContext) -> RuleResult:
    """Detect S3 buckets with public access."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "S3Bucket":
            continue

        is_public = node.properties.get("is_public", False)
        block_public = node.properties.get("public_access_blocked", False)

        if is_public and not block_public:
            findings.append(AttackPath(
                src=node.id,
                dst="internet",
                rule_id="aws-s3-public-bucket",
                severity=Severity.HIGH,
                description=f"S3 bucket {node.properties.get('name')} is publicly accessible",
                remediation="Enable S3 Block Public Access settings or review and restrict bucket policy",
            ))

    return RuleResult(
        rule_id="aws-s3-public-bucket",
        description="Public S3 bucket",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-s3-policy-allows-all",
    provider="aws",
    description="S3 bucket policy allows any principal",
    severity="high",
    tags=["s3", "data-exposure"],
)
def rule_s3_policy_allows_all(ctx: RuleContext) -> RuleResult:
    """Detect S3 bucket policies that allow any principal."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "ResourcePolicy":
            continue
        if "s3:::" not in node.id:
            continue

        doc = node.properties.get("document") or {}
        principals = extract_principals(doc)

        if "*" in principals:
            # Get the bucket name from the policy ID
            bucket_id = node.id.replace(":policy", "")
            findings.append(AttackPath(
                src=bucket_id,
                dst="internet",
                rule_id="aws-s3-policy-allows-all",
                severity=Severity.HIGH,
                description="S3 bucket policy allows any principal (*)",
                remediation="Restrict the Principal element in the bucket policy",
            ))

    return RuleResult(
        rule_id="aws-s3-policy-allows-all",
        description="S3 policy allows everyone",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-s3-no-encryption",
    provider="aws",
    description="S3 bucket does not have encryption enabled",
    severity="medium",
    tags=["s3", "encryption"],
)
def rule_s3_no_encryption(ctx: RuleContext) -> RuleResult:
    """Detect S3 buckets without server-side encryption."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "S3Bucket":
            continue

        encrypted = node.properties.get("encrypted", False)
        if not encrypted:
            findings.append(AttackPath(
                src=node.id,
                dst="s3:no-encryption",
                rule_id="aws-s3-no-encryption",
                severity=Severity.MEDIUM,
                description=f"S3 bucket {node.properties.get('name')} has no default encryption",
                remediation="Enable default server-side encryption (SSE-S3 or SSE-KMS)",
            ))

    return RuleResult(
        rule_id="aws-s3-no-encryption",
        description="S3 bucket without encryption",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-s3-no-versioning",
    provider="aws",
    description="S3 bucket does not have versioning enabled",
    severity="low",
    tags=["s3", "data-protection"],
)
def rule_s3_no_versioning(ctx: RuleContext) -> RuleResult:
    """Detect S3 buckets without versioning enabled."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "S3Bucket":
            continue

        versioning = node.properties.get("versioning_enabled", False)
        if not versioning:
            findings.append(AttackPath(
                src=node.id,
                dst="s3:no-versioning",
                rule_id="aws-s3-no-versioning",
                severity=Severity.LOW,
                description=f"S3 bucket {node.properties.get('name')} has versioning disabled",
                remediation="Enable versioning to protect against accidental deletions",
            ))

    return RuleResult(
        rule_id="aws-s3-no-versioning",
        description="S3 bucket without versioning",
        attack_paths=findings,
        passed=len(findings) == 0,
    )
