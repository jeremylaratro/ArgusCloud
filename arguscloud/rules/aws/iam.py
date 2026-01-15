"""AWS IAM security rules."""

from __future__ import annotations

from collections import deque
from typing import List, Set

from arguscloud.core.graph import AttackPath, Severity
from arguscloud.core.base import RuleContext, RuleResult
from arguscloud.core.registry import rules


@rules.rule(
    rule_id="aws-iam-open-trust",
    provider="aws",
    description="Role trust policy allows any principal (*)",
    severity="high",
    tags=["iam", "privilege-escalation"],
)
def rule_open_trust(ctx: RuleContext) -> RuleResult:
    """Detect roles with trust policies allowing any principal."""
    findings: List[AttackPath] = []

    for edge in ctx.edges:
        if edge.type == "Trusts" and edge.dst == "*":
            findings.append(AttackPath(
                src=edge.src,
                dst="internet",
                rule_id="aws-iam-open-trust",
                severity=Severity.HIGH,
                description="Role trust policy allows any principal to assume",
                remediation="Restrict the Principal in the trust policy to specific AWS accounts or roles",
            ))

    return RuleResult(
        rule_id="aws-iam-open-trust",
        description="Role trust allows any principal",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-iam-assume-role-chain",
    provider="aws",
    description="Principal can reach admin role via trust chain",
    severity="high",
    tags=["iam", "privilege-escalation"],
)
def rule_assume_role_chain(ctx: RuleContext) -> RuleResult:
    """Detect trust chains that lead to admin roles."""
    findings: List[AttackPath] = []

    # Build trust graph
    trust_graph: dict = {}
    for edge in ctx.edges:
        if edge.type == "Trusts" and edge.dst != "*":
            trust_graph.setdefault(edge.dst, []).append(edge.src)

    # Find admin roles
    admin_roles: Set[str] = {
        n.id for n in ctx.nodes
        if n.type == "Role" and n.properties.get("is_admin")
    }

    # BFS to find paths to admin
    def find_path(start: str, target: str, max_depth: int = 3):
        queue = deque([(start, [start])])
        visited = set()

        while queue:
            current, path = queue.popleft()
            if len(path) - 1 > max_depth:
                continue
            if current == target and len(path) > 1:
                return path
            visited.add(current)
            for neighbor in trust_graph.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))
        return None

    for principal in trust_graph:
        for admin_role in admin_roles:
            path = find_path(principal, admin_role)
            if path:
                findings.append(AttackPath(
                    src=principal,
                    dst=admin_role,
                    rule_id="aws-iam-assume-role-chain",
                    severity=Severity.HIGH,
                    description=f"Trust chain to admin: {' -> '.join(path)}",
                    properties={"path": path},
                    remediation="Review and restrict trust relationships in the chain",
                ))

    return RuleResult(
        rule_id="aws-iam-assume-role-chain",
        description="Assume role chain to admin",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-iam-user-no-mfa",
    provider="aws",
    description="IAM user with console access has no MFA",
    severity="high",
    tags=["iam", "authentication"],
)
def rule_user_no_mfa(ctx: RuleContext) -> RuleResult:
    """Detect IAM users with console access but no MFA configured."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "User":
            continue

        has_console = node.properties.get("has_console_access", False)
        has_mfa = node.properties.get("has_mfa", False)

        if has_console and not has_mfa:
            findings.append(AttackPath(
                src=node.id,
                dst="console:no-mfa",
                rule_id="aws-iam-user-no-mfa",
                severity=Severity.HIGH,
                description=f"User {node.properties.get('name')} has console access without MFA",
                remediation="Enable MFA for all IAM users with console access",
            ))

    return RuleResult(
        rule_id="aws-iam-user-no-mfa",
        description="IAM user without MFA",
        attack_paths=findings,
        passed=len(findings) == 0,
    )


@rules.rule(
    rule_id="aws-iam-user-multiple-keys",
    provider="aws",
    description="IAM user has multiple active access keys",
    severity="medium",
    tags=["iam", "credential-management"],
)
def rule_user_multiple_keys(ctx: RuleContext) -> RuleResult:
    """Detect IAM users with multiple active access keys."""
    findings: List[AttackPath] = []

    for node in ctx.nodes:
        if node.type != "User":
            continue

        active_keys = node.properties.get("active_access_keys", 0)
        if active_keys > 1:
            findings.append(AttackPath(
                src=node.id,
                dst="iam:multiple-keys",
                rule_id="aws-iam-user-multiple-keys",
                severity=Severity.MEDIUM,
                description=f"User has {active_keys} active access keys (best practice is 1)",
                remediation="Rotate access keys and maintain only one active key per user",
            ))

    return RuleResult(
        rule_id="aws-iam-user-multiple-keys",
        description="User with multiple access keys",
        attack_paths=findings,
        passed=len(findings) == 0,
    )
