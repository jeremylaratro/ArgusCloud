"""AWS Compute service normalizers (Lambda, EKS, ECR)."""

from __future__ import annotations

from typing import Any, Dict, Iterable

from arguscloud.core.graph import CloudProvider, Edge, GraphData, Node
from arguscloud.core.base import extract_principals
from arguscloud.core.registry import normalizers


@normalizers.normalizer(
    name="lambda",
    provider="aws",
    description="Normalize Lambda functions to graph",
    input_type="lambda",
)
def normalize_lambda(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert Lambda functions to nodes and edges."""
    graph = GraphData()

    for rec in records:
        fn = rec.get("Function") or {}
        arn = fn.get("FunctionArn")
        if not arn:
            continue

        # Check for function URL (public access)
        url_config = rec.get("FunctionUrlConfig", {})
        has_public_url = bool(url_config.get("FunctionUrl"))
        auth_type = url_config.get("AuthType", "")

        graph.add_node(Node(
            id=arn,
            type="LambdaFunction",
            properties={
                "name": fn.get("FunctionName"),
                "runtime": fn.get("Runtime"),
                "role": fn.get("Role"),
                "handler": fn.get("Handler"),
                "memory_size": fn.get("MemorySize"),
                "timeout": fn.get("Timeout"),
                "has_public_url": has_public_url,
                "url_auth_type": auth_type,
            },
            provider=CloudProvider.AWS,
        ))

        # Execution role relationship
        if fn.get("Role"):
            graph.add_edge(Edge(
                src=arn,
                dst=fn["Role"],
                type="AssumesRole",
                properties={"source": "lambda-execution-role"},
                provider=CloudProvider.AWS,
            ))

        # Resource policy
        policy = rec.get("Policy")
        if policy:
            policy_id = f"{arn}:policy"
            graph.add_node(Node(
                id=policy_id,
                type="ResourcePolicy",
                properties={"document": policy},
                provider=CloudProvider.AWS,
            ))
            graph.add_edge(Edge(
                src=arn,
                dst=policy_id,
                type="ResourcePolicy",
                properties={},
                provider=CloudProvider.AWS,
            ))
            for principal in extract_principals(policy):
                graph.add_edge(Edge(
                    src=policy_id,
                    dst=principal,
                    type="PolicyPrincipal",
                    properties={},
                    provider=CloudProvider.AWS,
                ))

    return graph


@normalizers.normalizer(
    name="eks",
    provider="aws",
    description="Normalize EKS clusters to graph",
    input_type="eks",
)
def normalize_eks(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert EKS clusters to nodes and edges."""
    graph = GraphData()

    for rec in records:
        cluster = rec.get("Cluster") or {}
        arn = cluster.get("arn")
        if not arn:
            continue

        # Check endpoint access
        vpc_config = cluster.get("resourcesVpcConfig", {})
        public_access = vpc_config.get("endpointPublicAccess", False)
        private_access = vpc_config.get("endpointPrivateAccess", False)

        graph.add_node(Node(
            id=arn,
            type="EKSCluster",
            properties={
                "name": cluster.get("name"),
                "version": cluster.get("version"),
                "status": cluster.get("status"),
                "endpoint": cluster.get("endpoint"),
                "role_arn": cluster.get("roleArn"),
                "public_access": public_access,
                "private_access": private_access,
                "security_groups": vpc_config.get("securityGroupIds", []),
                "subnet_ids": vpc_config.get("subnetIds", []),
            },
            provider=CloudProvider.AWS,
        ))

        # Cluster service role
        role_arn = cluster.get("roleArn")
        if role_arn:
            graph.add_edge(Edge(
                src=arn,
                dst=role_arn,
                type="AssumesRole",
                properties={"source": "eks-cluster-service-role"},
                provider=CloudProvider.AWS,
            ))

        # Node groups
        for ng in rec.get("NodeGroups", []):
            graph.add_node(Node(
                id=f"{arn}:nodegroup:{ng}",
                type="EKSNodeGroup",
                properties={"name": ng, "cluster": arn},
                provider=CloudProvider.AWS,
            ))

    return graph


@normalizers.normalizer(
    name="ecr",
    provider="aws",
    description="Normalize ECR repositories to graph",
    input_type="ecr",
)
def normalize_ecr(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert ECR repositories to nodes and edges."""
    graph = GraphData()

    for rec in records:
        repo = rec.get("Repository") or {}
        arn = repo.get("repositoryArn")
        if not arn:
            continue

        scan_config = repo.get("imageScanningConfiguration", {})

        graph.add_node(Node(
            id=arn,
            type="ECRRepository",
            properties={
                "name": repo.get("repositoryName"),
                "uri": repo.get("repositoryUri"),
                "scan_on_push": scan_config.get("scanOnPush", False),
                "encryption_type": repo.get("encryptionConfiguration", {}).get("encryptionType"),
            },
            provider=CloudProvider.AWS,
        ))

        # Repository policy
        policy = rec.get("Policy")
        if policy:
            policy_id = f"{arn}:policy"
            graph.add_node(Node(
                id=policy_id,
                type="ResourcePolicy",
                properties={"document": policy},
                provider=CloudProvider.AWS,
            ))
            graph.add_edge(Edge(
                src=arn,
                dst=policy_id,
                type="ResourcePolicy",
                properties={},
                provider=CloudProvider.AWS,
            ))
            for principal in extract_principals(policy):
                graph.add_edge(Edge(
                    src=policy_id,
                    dst=principal,
                    type="PolicyPrincipal",
                    properties={},
                    provider=CloudProvider.AWS,
                ))

    return graph
