"""AWS Data and Secrets security rules (KMS, RDS, Secrets Manager)."""

from __future__ import annotations

from typing import List

from arguscloud.core.graph import AttackPath, Severity
from arguscloud.core.base import RuleContext, RuleResult, extract_principals
from arguscloud.core.registry import rules


@rules.rule(
    rule_id="aws-kms-key-public-access",
    provider="aws",
    description="KMS key policy allows broad access",
    severity="high",
    tags=["kms", "encryption"],
)
def rule_kms_public_access(ctx: RuleContext) -> RuleResult:
    """Detect KMS keys with overly permissive policies."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "ResourcePolicy":
            continue
        if "kms" not in node.id.lower() and ":key/" not in node.id:
            continue

        doc = node.properties.get("document") or {}
        principals = extract_principals(doc)

        if "*" in principals:
            key_id = node.id.replace(":policy", "")
            findings.append(AttackPath(
                src=key_id,
                dst="internet",
                rule_id="aws-kms-key-public-access",
                severity=Severity.HIGH,
                description="KMS key policy allows any principal",
                remediation="Restrict the Principal element in the key policy",
            ))

    return RuleResult(
        rule_id="aws-kms-key-public-access",
        description="KMS key with public access",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-kms-key-no-rotation",
    provider="aws",
    description="KMS key does not have automatic rotation enabled",
    severity="low",
    tags=["kms", "encryption", "compliance"],
)
def rule_kms_no_rotation(ctx: RuleContext) -> RuleResult:
    """Detect KMS keys without automatic rotation."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "KMSKey":
            continue

        rotation_enabled = node.properties.get("rotation_enabled", False)
        key_state = node.properties.get("key_state", "")

        # Only check enabled keys
        if key_state == "Enabled" and not rotation_enabled:
            findings.append(AttackPath(
                src=node.id,
                dst="kms:no-rotation",
                rule_id="aws-kms-key-no-rotation",
                severity=Severity.LOW,
                description="KMS key does not have automatic rotation enabled",
                remediation="Enable automatic key rotation for the KMS key",
            ))

    return RuleResult(
        rule_id="aws-kms-key-no-rotation",
        description="KMS key without rotation",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-rds-public-snapshot",
    provider="aws",
    description="RDS snapshot is publicly shared",
    severity="high",
    tags=["rds", "data-exposure"],
)
def rule_rds_public_snapshot(ctx: RuleContext) -> RuleResult:
    """Detect publicly shared RDS snapshots."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "RDSSnapshot":
            continue

        if node.properties.get("public"):
            findings.append(AttackPath(
                src=node.id,
                dst="internet",
                rule_id="aws-rds-public-snapshot",
                severity=Severity.HIGH,
                description=f"RDS snapshot {node.id} is publicly accessible",
                remediation="Remove public access by modifying snapshot attributes",
            ))

    return RuleResult(
        rule_id="aws-rds-public-snapshot",
        description="Public RDS snapshot",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-rds-unencrypted-snapshot",
    provider="aws",
    description="RDS snapshot is not encrypted",
    severity="medium",
    tags=["rds", "encryption"],
)
def rule_rds_unencrypted_snapshot(ctx: RuleContext) -> RuleResult:
    """Detect unencrypted RDS snapshots."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "RDSSnapshot":
            continue

        if node.properties.get("encrypted") is False:
            findings.append(AttackPath(
                src=node.id,
                dst="rds:unencrypted",
                rule_id="aws-rds-unencrypted-snapshot",
                severity=Severity.MEDIUM,
                description="RDS snapshot is not encrypted",
                remediation="Create an encrypted copy of the snapshot",
            ))

    return RuleResult(
        rule_id="aws-rds-unencrypted-snapshot",
        description="Unencrypted RDS snapshot",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-secrets-no-rotation",
    provider="aws",
    description="Secrets Manager secret does not have rotation enabled",
    severity="medium",
    tags=["secrets", "credential-management"],
)
def rule_secrets_no_rotation(ctx: RuleContext) -> RuleResult:
    """Detect Secrets Manager secrets without rotation."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "Secret":
            continue

        rotation_enabled = node.properties.get("rotation_enabled", False)
        if not rotation_enabled:
            findings.append(AttackPath(
                src=node.id,
                dst="secrets:no-rotation",
                rule_id="aws-secrets-no-rotation",
                severity=Severity.MEDIUM,
                description=f"Secret {node.properties.get('name')} has no rotation",
                remediation="Enable automatic rotation for the secret",
            ))

    return RuleResult(
        rule_id="aws-secrets-no-rotation",
        description="Secret without rotation",
        attack_paths=findings,
        passed=len(findings) == 0,
    )
