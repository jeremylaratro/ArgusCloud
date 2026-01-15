"""AWS Logging and Monitoring security rules."""

from __future__ import annotations

from typing import List

from arguscloud.core.graph import AttackPath, Severity
from arguscloud.core.base import RuleContext, RuleResult
from arguscloud.core.registry import rules


@rules.rule(
    rule_id="aws-logging-no-cloudtrail",
    provider="aws",
    description="CloudTrail is not enabled or not logging",
    severity="high",
    tags=["logging", "compliance"],
)
def rule_missing_cloudtrail(ctx: RuleContext) -> RuleResult:
    """Detect accounts without active CloudTrail logging."""
    findings: List[AttackPath] = []

    trails = [n for n in ctx.nodes if n.type == "CloudTrailTrail"]
    active_trail = any(
        t.properties.get("is_logging") is True
        for t in trails
    )

    if not active_trail:
        for acct in ctx.get_nodes_by_type("Account"):
            findings.append(AttackPath(
                src=acct.id,
                dst="cloudtrail:absent",
                rule_id="aws-logging-no-cloudtrail",
                severity=Severity.HIGH,
                description="CloudTrail is not enabled or not logging",
                remediation="Enable CloudTrail logging with multi-region trails",
            ))

    return RuleResult(
        rule_id="aws-logging-no-cloudtrail",
        description="Missing CloudTrail",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-logging-cloudtrail-not-logging",
    provider="aws",
    description="CloudTrail trail exists but is not actively logging",
    severity="high",
    tags=["logging", "compliance"],
)
def rule_cloudtrail_not_logging(ctx: RuleContext) -> RuleResult:
    """Detect CloudTrail trails that are disabled."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "CloudTrailTrail":
            continue

        if node.properties.get("is_logging") is False:
            findings.append(AttackPath(
                src=node.id,
                dst="cloudtrail:disabled",
                rule_id="aws-logging-cloudtrail-not-logging",
                severity=Severity.HIGH,
                description=f"CloudTrail trail {node.properties.get('name')} is not logging",
                remediation="Enable logging on the CloudTrail trail",
            ))

    return RuleResult(
        rule_id="aws-logging-cloudtrail-not-logging",
        description="CloudTrail not logging",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-logging-no-guardduty",
    provider="aws",
    description="GuardDuty is not enabled in the account",
    severity="medium",
    tags=["logging", "threat-detection"],
)
def rule_missing_guardduty(ctx: RuleContext) -> RuleResult:
    """Detect accounts without GuardDuty enabled."""
    findings: List[AttackPath] = []

    detectors = [n for n in ctx.nodes if n.type == "GuardDutyDetector"]
    has_guardduty = len(detectors) > 0

    if not has_guardduty:
        for acct in ctx.get_nodes_by_type("Account"):
            findings.append(AttackPath(
                src=acct.id,
                dst="guardduty:absent",
                rule_id="aws-logging-no-guardduty",
                severity=Severity.MEDIUM,
                description="GuardDuty detector not found",
                remediation="Enable GuardDuty for threat detection",
            ))

    return RuleResult(
        rule_id="aws-logging-no-guardduty",
        description="Missing GuardDuty",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-logging-no-config",
    provider="aws",
    description="AWS Config is not enabled",
    severity="low",
    tags=["logging", "compliance"],
)
def rule_missing_config(ctx: RuleContext) -> RuleResult:
    """Detect accounts without AWS Config enabled."""
    findings: List[AttackPath] = []

    recorders = [
        n for n in ctx.nodes
        if n.type == "ConfigRecorder" and n.properties.get("recording")
    ]

    if not recorders:
        for acct in ctx.get_nodes_by_type("Account"):
            findings.append(AttackPath(
                src=acct.id,
                dst="config:absent",
                rule_id="aws-logging-no-config",
                severity=Severity.LOW,
                description="AWS Config recorder not found or not recording",
                remediation="Enable AWS Config for configuration change tracking",
            ))

    return RuleResult(
        rule_id="aws-logging-no-config",
        description="Missing AWS Config",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-logging-cloudwatch-no-retention",
    provider="aws",
    description="CloudWatch Log Group has no retention policy",
    severity="low",
    tags=["logging", "cost-optimization"],
)
def rule_cloudwatch_no_retention(ctx: RuleContext) -> RuleResult:
    """Detect CloudWatch Log Groups without retention policies."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "LogGroup":
            continue

        if not node.properties.get("retention"):
            findings.append(AttackPath(
                src=node.id,
                dst="cloudwatch:infinite-retention",
                rule_id="aws-logging-cloudwatch-no-retention",
                severity=Severity.LOW,
                description="Log group has no retention policy (logs kept forever)",
                remediation="Set a retention policy to manage storage costs",
            ))

    return RuleResult(
        rule_id="aws-logging-cloudwatch-no-retention",
        description="Log group without retention",
        attack_paths=findings,
        passed=len(findings) == 0,
    )
