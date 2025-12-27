from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Callable, List

from .graph import Edge, Node


@dataclass
class RuleContext:
    nodes: List[Node]
    edges: List[Edge]


@dataclass
class RuleResult:
    rule_id: str
    description: str
    edges: List[Edge]


RuleFn = Callable[[RuleContext], RuleResult]


def rule_open_trust(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for edge in ctx.edges:
        if edge.type == "Trusts" and edge.dst == "*":
            attack_edges.append(
                Edge(
                    src=edge.src,
                    dst=edge.dst,
                    type="AttackPath",
                    properties={
                        "rule": "open-trust",
                        "description": "Role trust policy allows any principal",
                        "severity": "high",
                    },
                )
            )
    return RuleResult(rule_id="open-trust", description="Role trust allows any principal", edges=attack_edges)


def rule_missing_guardduty(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    has_guardduty = any(n.type == "GuardDutyDetector" for n in ctx.nodes)
    if not has_guardduty:
        for acct in (n for n in ctx.nodes if n.type == "Account"):
            attack_edges.append(
                Edge(
                    src=acct.id,
                    dst="guardduty:absent",
                    type="AttackPath",
                    properties={
                        "rule": "guardduty-missing",
                        "description": "GuardDuty detector not found in account",
                        "severity": "medium",
                    },
                )
            )
    return RuleResult(rule_id="guardduty-missing", description="GuardDuty not present", edges=attack_edges)


def rule_public_s3(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type != "ResourcePolicy":
            continue
        doc = node.properties.get("document") or {}
        stmts = doc.get("Statement") or []
        if not isinstance(stmts, list):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            princ = stmt.get("Principal")
            if princ == "*" or (isinstance(princ, dict) and any(v == "*" or v == ["*"] for v in princ.values())):
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst="internet",
                        type="AttackPath",
                        properties={"rule": "public-s3", "description": "S3/KMS resource policy allows everyone", "severity": "high"},
                    )
                )
                break
    return RuleResult(rule_id="public-s3", description="Resource policy allows everyone", edges=attack_edges)


def rule_open_sg(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type != "SecurityGroup":
            continue
        ingress = node.properties.get("ingress") or []
        for perm in ingress:
            cidrs = []
            for rng in perm.get("IpRanges", []):
                cidrs.append(rng.get("CidrIp"))
            if "0.0.0.0/0" in cidrs:
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst="internet",
                        type="AttackPath",
                        properties={"rule": "open-sg", "description": "Security group allows ingress from 0.0.0.0/0", "severity": "medium"},
                    )
                )
                break
    return RuleResult(rule_id="open-sg", description="Security group open to internet", edges=attack_edges)


def rule_missing_cloudtrail(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    has_trail = any(n.type == "CloudTrailTrail" and n.properties.get("is_logging") is not False for n in ctx.nodes)
    if not has_trail:
        for acct in (n for n in ctx.nodes if n.type == "Account"):
            attack_edges.append(
                Edge(
                    src=acct.id,
                    dst="cloudtrail:absent",
                    type="AttackPath",
                    properties={"rule": "cloudtrail-missing", "description": "CloudTrail trail not found or not logging", "severity": "medium"},
                )
            )
    return RuleResult(rule_id="cloudtrail-missing", description="CloudTrail missing", edges=attack_edges)


def rule_missing_config(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    has_recorder = any(n.type == "ConfigRecorder" and n.properties.get("recording") for n in ctx.nodes)
    if not has_recorder:
        for acct in (n for n in ctx.nodes if n.type == "Account"):
            attack_edges.append(
                Edge(
                    src=acct.id,
                    dst="config:absent",
                    type="AttackPath",
                    properties={"rule": "config-missing", "description": "AWS Config recorder not found", "severity": "low"},
                )
            )
    return RuleResult(rule_id="config-missing", description="Config missing", edges=attack_edges)


def rule_kms_external_access(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type != "ResourcePolicy":
            continue
        if "kms" not in node.id and ":key/" not in node.id:
            continue
        doc = node.properties.get("document") or {}
        stmts = doc.get("Statement") or []
        if not isinstance(stmts, list):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and any(v == "*" or v == ["*"] for v in principal.values())):
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst="internet",
                        type="AttackPath",
                        properties={"rule": "kms-external-access", "description": "KMS key policy allows broad principals", "severity": "high"},
                    )
                )
                break
            if isinstance(principal, dict):
                for val in principal.values():
                    if isinstance(val, list):
                        principals = val
                    else:
                        principals = [val]
                    for p in principals:
                        if ":iam::" in str(p):
                            attack_edges.append(
                                Edge(
                                    src=node.id,
                                    dst=str(p),
                                    type="AttackPath",
                                    properties={"rule": "kms-cross-account", "description": "KMS key policy trusts external account principal", "severity": "medium"},
                                )
                            )
    return RuleResult(rule_id="kms-external-access", description="KMS key policy exposes access", edges=attack_edges)


def _build_trust_graph(edges: List[Edge]) -> dict:
    adj: dict = {}
    for e in edges:
        if e.type != "Trusts":
            continue
        principal = e.dst
        role = e.src
        if principal == "*":
            continue
        adj.setdefault(principal, []).append(role)
    return adj


def _admin_roles(nodes: List[Node]) -> set:
    return {n.id for n in nodes if n.type == "Role" and n.properties.get("is_admin")}


def _bfs_path(adj: dict, start: str, target: str, max_depth: int = 3):
    queue = deque()
    queue.append((start, [start]))
    visited = set()
    while queue:
        current, path = queue.popleft()
        if len(path) - 1 > max_depth:
            continue
        if current == target and len(path) > 1:
            return path
        visited.add(current)
        for neighbor in adj.get(current, []):
            if neighbor not in visited:
                queue.append((neighbor, path + [neighbor]))
    return None


def rule_assume_role_chain(ctx: RuleContext) -> RuleResult:
    adj = _build_trust_graph(ctx.edges)
    admin_roles = _admin_roles(ctx.nodes)
    attack_edges: List[Edge] = []
    for principal in adj:
        for target in admin_roles:
            path = _bfs_path(adj, principal, target, max_depth=3)
            if path:
                attack_edges.append(
                    Edge(
                        src=principal,
                        dst=target,
                        type="AttackPath",
                        properties={
                            "rule": "assume-role-chain",
                            "description": f"Principal can reach admin role via trust chain: {' -> '.join(path)}",
                            "path": path,
                            "severity": "high",
                        },
                    )
                )
    return RuleResult(rule_id="assume-role-chain", description="Assume role chain to admin", edges=attack_edges)


def rule_codebuild_secret_exfil(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type != "CodeBuildProject":
            continue
        env_vars = node.properties.get("environment_vars") or []
        privileged = node.properties.get("environment_privileged")
        if env_vars:
            attack_edges.append(
                Edge(
                    src=node.id,
                    dst="codebuild:envvars",
                    type="AttackPath",
                    properties={"rule": "codebuild-env-secrets", "description": "CodeBuild project has environment variables (potential secrets)", "severity": "medium"},
                )
            )
        if privileged:
            attack_edges.append(
                Edge(
                    src=node.id,
                    dst="codebuild:privileged",
                    type="AttackPath",
                    properties={"rule": "codebuild-privileged", "description": "CodeBuild project uses privilegedMode (container breakout risk)", "severity": "medium"},
                )
            )
    return RuleResult(rule_id="codebuild-risk", description="CodeBuild project risks", edges=attack_edges)


def rule_public_snapshots_amis(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type == "Snapshot" and node.properties.get("state") == "completed":
            if node.properties.get("encrypted") is False:
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst="internet",
                        type="AttackPath",
                        properties={"rule": "snapshot-exfil", "description": "Unencrypted snapshot may be shareable/clonable", "severity": "medium"},
                    )
                )
        if node.type == "AMI":
            if node.properties.get("public"):
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst="internet",
                        type="AttackPath",
                        properties={"rule": "ami-public", "description": "Public AMI allows anyone to launch", "severity": "medium"},
                    )
                )
    return RuleResult(rule_id="public-snapshot-ami", description="Snapshot/AMI exposure", edges=attack_edges)


def rule_rds_public_snapshots(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type == "RDSSnapshot" and node.properties.get("public"):
            attack_edges.append(
                Edge(
                    src=node.id,
                    dst="internet",
                    type="AttackPath",
                    properties={"rule": "rds-public-snapshot", "description": "RDS snapshot is public (restore=all)", "severity": "high"},
                )
            )
    return RuleResult(rule_id="rds-public-snapshot", description="RDS snapshot public", edges=attack_edges)


def rule_imds_exposure(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type == "EC2Instance":
            has_public = bool(node.properties.get("public_ip"))
            has_profile = bool(node.properties.get("iam_instance_profile"))
            if has_public and has_profile:
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst="imds:cred-theft",
                        type="AttackPath",
                        properties={"rule": "imds-exposure", "description": "Public instance with role attached (IMDS credential theft risk)", "severity": "medium"},
                    )
                )
    return RuleResult(rule_id="imds-exposure", description="Instance exposes role via IMDS", edges=attack_edges)


def rule_cloudtrail_not_logging(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    trails = [n for n in ctx.nodes if n.type == "CloudTrailTrail"]
    for tr in trails:
        if tr.properties.get("is_logging") is False:
            attack_edges.append(
                Edge(
                    src=tr.id,
                    dst="cloudtrail:not-logging",
                    type="AttackPath",
                    properties={"rule": "cloudtrail-not-logging", "description": "CloudTrail trail present but not logging", "severity": "high"},
                )
            )
    return RuleResult(rule_id="cloudtrail-not-logging", description="CloudTrail not logging", edges=attack_edges)


def rule_codepipeline_risk(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type == "CodePipeline":
            if node.properties.get("role_arn"):
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst=node.properties.get("role_arn"),
                        type="AttackPath",
                        properties={"rule": "codepipeline-role", "description": "Pipeline uses IAM role (review permissions for artifact access/exfil)", "severity": "medium"},
                    )
                )
    return RuleResult(rule_id="codepipeline-risk", description="CodePipeline role risk", edges=attack_edges)


def _principal_list(doc: dict) -> list:
    principals = []
    stmts = doc.get("Statement") or []
    if not isinstance(stmts, list):
        stmts = [stmts]
    for stmt in stmts:
        principal = stmt.get("Principal")
        if principal == "*":
            principals.append("*")
        elif isinstance(principal, dict):
            for val in principal.values():
                if isinstance(val, list):
                    principals.extend(val)
                else:
                    principals.append(val)
        elif principal:
            principals.append(principal)
    return principals


def rule_ecr_cross_account(ctx: RuleContext) -> RuleResult:
    attack_edges: List[Edge] = []
    for node in ctx.nodes:
        if node.type != "ResourcePolicy":
            continue
        if ":repository/" not in node.id:
            continue
        doc = node.properties.get("document") or {}
        for principal in _principal_list(doc):
            if principal == "*" or (isinstance(principal, str) and ":iam::" in principal):
                attack_edges.append(
                    Edge(
                        src=node.id,
                        dst=principal if principal != "*" else "internet",
                        type="AttackPath",
                        properties={"rule": "ecr-cross-account", "description": "ECR repository policy allows external access", "severity": "medium"},
                    )
                )
    return RuleResult(rule_id="ecr-cross-account", description="ECR policy exposes repository", edges=attack_edges)


RULES: List[RuleFn] = [
    rule_open_trust,
    rule_missing_guardduty,
    rule_public_s3,
    rule_open_sg,
    rule_missing_cloudtrail,
    rule_missing_config,
    rule_kms_external_access,
    rule_assume_role_chain,
    rule_codebuild_secret_exfil,
    rule_public_snapshots_amis,
    rule_ecr_cross_account,
    rule_rds_public_snapshots,
    rule_imds_exposure,
    rule_cloudtrail_not_logging,
    rule_codepipeline_risk,
]


def evaluate_rules(nodes: List[Node], edges: List[Edge]) -> List[Edge]:
    ctx = RuleContext(nodes=nodes, edges=edges)
    attack_edges: List[Edge] = []
    for rule in RULES:
        result = rule(ctx)
        attack_edges.extend(result.edges)
    return attack_edges
