"""AWS Compute security rules (Lambda, EKS, CodeBuild)."""

from __future__ import annotations

from typing import List

from arguscloud.core.graph import AttackPath, Severity
from arguscloud.core.base import RuleContext, RuleResult, extract_principals
from arguscloud.core.registry import rules


@rules.rule(
    rule_id="aws-lambda-public-url",
    provider="aws",
    description="Lambda function has a public URL with no authentication",
    severity="high",
    tags=["lambda", "public-exposure"],
)
def rule_lambda_public_url(ctx: RuleContext) -> RuleResult:
    """Detect Lambda functions with unauthenticated public URLs."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "LambdaFunction":
            continue

        has_public_url = node.properties.get("has_public_url", False)
        auth_type = node.properties.get("url_auth_type", "")

        if has_public_url and auth_type == "NONE":
            findings.append(AttackPath(
                src=node.id,
                dst="internet",
                rule_id="aws-lambda-public-url",
                severity=Severity.HIGH,
                description=f"Lambda {node.properties.get('name')} has public URL with no auth",
                remediation="Enable IAM authentication on the function URL or remove it",
            ))

    return RuleResult(
        rule_id="aws-lambda-public-url",
        description="Public Lambda URL without auth",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-eks-public-endpoint",
    provider="aws",
    description="EKS cluster has public endpoint access enabled",
    severity="medium",
    tags=["eks", "kubernetes", "public-exposure"],
)
def rule_eks_public_endpoint(ctx: RuleContext) -> RuleResult:
    """Detect EKS clusters with public API endpoints."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "EKSCluster":
            continue

        public_access = node.properties.get("public_access", False)
        private_access = node.properties.get("private_access", False)

        if public_access and not private_access:
            findings.append(AttackPath(
                src=node.id,
                dst="internet",
                rule_id="aws-eks-public-endpoint",
                severity=Severity.MEDIUM,
                description=f"EKS cluster {node.properties.get('name')} has public-only endpoint",
                remediation="Enable private endpoint access and restrict public access CIDRs",
            ))

    return RuleResult(
        rule_id="aws-eks-public-endpoint",
        description="EKS public endpoint",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-codebuild-privileged-mode",
    provider="aws",
    description="CodeBuild project uses privileged mode",
    severity="medium",
    tags=["codebuild", "container-security"],
)
def rule_codebuild_privileged(ctx: RuleContext) -> RuleResult:
    """Detect CodeBuild projects running in privileged mode."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "CodeBuildProject":
            continue

        privileged = node.properties.get("environment_privileged", False)
        if privileged:
            findings.append(AttackPath(
                src=node.id,
                dst="codebuild:privileged",
                rule_id="aws-codebuild-privileged-mode",
                severity=Severity.MEDIUM,
                description=f"CodeBuild project {node.properties.get('name')} uses privileged mode",
                remediation="Disable privileged mode unless building Docker images",
            ))

    return RuleResult(
        rule_id="aws-codebuild-privileged-mode",
        description="CodeBuild privileged mode",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-codebuild-env-secrets",
    provider="aws",
    description="CodeBuild project has environment variables that may contain secrets",
    severity="medium",
    tags=["codebuild", "secrets"],
)
def rule_codebuild_env_secrets(ctx: RuleContext) -> RuleResult:
    """Detect CodeBuild projects with potentially sensitive environment variables."""
    findings: List[AttackPath] = []

    sensitive_keywords = ["SECRET", "PASSWORD", "KEY", "TOKEN", "CREDENTIAL", "API_KEY"]

    for node in ctx.nodes:
        if node.type != "CodeBuildProject":
            continue

        env_vars = node.properties.get("environment_vars", [])
        suspicious = [
            v for v in env_vars
            if any(kw in v.get("name", "").upper() for kw in sensitive_keywords)
        ]

        if suspicious:
            findings.append(AttackPath(
                src=node.id,
                dst="codebuild:exposed-secrets",
                rule_id="aws-codebuild-env-secrets",
                severity=Severity.MEDIUM,
                description=f"CodeBuild has {len(suspicious)} potentially sensitive env vars",
                remediation="Use Secrets Manager or SSM Parameter Store for secrets",
            ))

    return RuleResult(
        rule_id="aws-codebuild-env-secrets",
        description="CodeBuild env secrets",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-ecr-cross-account-access",
    provider="aws",
    description="ECR repository policy allows cross-account access",
    severity="medium",
    tags=["ecr", "container-security"],
)
def rule_ecr_cross_account(ctx: RuleContext) -> RuleResult:
    """Detect ECR repositories with cross-account access policies."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "ResourcePolicy":
            continue
        if ":repository/" not in node.id:
            continue

        doc = node.properties.get("document") or {}
        principals = extract_principals(doc)

        for principal in principals:
            if principal == "*":
                findings.append(AttackPath(
                    src=node.id.replace(":policy", ""),
                    dst="internet",
                    rule_id="aws-ecr-cross-account-access",
                    severity=Severity.HIGH,
                    description="ECR repository allows any principal",
                    remediation="Restrict repository policy to specific accounts",
                ))
                break
            elif isinstance(principal, str) and ":iam::" in principal:
                findings.append(AttackPath(
                    src=node.id.replace(":policy", ""),
                    dst=principal,
                    rule_id="aws-ecr-cross-account-access",
                    severity=Severity.MEDIUM,
                    description="ECR repository allows cross-account access",
                    remediation="Review cross-account access permissions",
                ))

    return RuleResult(
        rule_id="aws-ecr-cross-account-access",
        description="ECR cross-account access",
        attack_paths=findings,
        passed=len(findings) == 0,
    )
