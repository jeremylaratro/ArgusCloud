"""AWS Compute service collectors (Lambda, EKS, ECR)."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="lambda",
    provider="aws",
    description="Collect Lambda functions and policies",
    services=["lambda"],
)
def collect_lambda(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect Lambda functions with their resource policies and configurations."""
    lam = session.client("lambda")
    data: List[Dict[str, Any]] = []

    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                record: Dict[str, Any] = {"Function": fn}
                fn_name = fn["FunctionName"]

                # Resource-based policy
                try:
                    pol = lam.get_policy(FunctionName=fn_name)
                    record["Policy"] = json.loads(pol.get("Policy", "{}"))
                except botocore.exceptions.ClientError:
                    pass

                # Function URL config (public access)
                try:
                    url_config = lam.get_function_url_config(FunctionName=fn_name)
                    record["FunctionUrlConfig"] = url_config
                except botocore.exceptions.ClientError:
                    pass

                # Event source mappings
                try:
                    mappings = lam.list_event_source_mappings(FunctionName=fn_name)
                    record["EventSourceMappings"] = mappings.get("EventSourceMappings", [])
                except botocore.exceptions.ClientError:
                    pass

                data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"Lambda collection failed: {exc}")

    return "lambda", data


@collectors.collector(
    name="eks",
    provider="aws",
    description="Collect EKS clusters",
    services=["eks"],
)
def collect_eks(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect EKS clusters with their configuration."""
    eks = session.client("eks")
    data: List[Dict[str, Any]] = []

    try:
        clusters = eks.list_clusters().get("clusters", [])
        for name in clusters:
            try:
                desc = eks.describe_cluster(name=name).get("cluster", {})
                record: Dict[str, Any] = {"Cluster": desc}

                # Get node groups
                try:
                    node_groups = eks.list_nodegroups(clusterName=name)
                    record["NodeGroups"] = node_groups.get("nodegroups", [])
                except botocore.exceptions.ClientError:
                    pass

                # Get Fargate profiles
                try:
                    fargate = eks.list_fargate_profiles(clusterName=name)
                    record["FargateProfiles"] = fargate.get("fargateProfileNames", [])
                except botocore.exceptions.ClientError:
                    pass

                # Get access entries (RBAC)
                try:
                    access = eks.list_access_entries(clusterName=name)
                    record["AccessEntries"] = access.get("accessEntries", [])
                except botocore.exceptions.ClientError:
                    pass

                data.append(record)
            except botocore.exceptions.ClientError as exc:
                log.debug(f"describe_cluster failed for {name}: {exc}")
    except botocore.exceptions.ClientError as exc:
        log.debug(f"list_clusters failed: {exc}")

    return "eks", data


@collectors.collector(
    name="ecr",
    provider="aws",
    description="Collect ECR repositories and policies",
    services=["ecr"],
)
def collect_ecr(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect ECR repositories with their policies and scanning configuration."""
    ecr = session.client("ecr")
    data: List[Dict[str, Any]] = []

    try:
        repos = ecr.describe_repositories().get("repositories", [])
        for repo in repos:
            record: Dict[str, Any] = {"Repository": repo}
            repo_name = repo["repositoryName"]

            # Repository policy
            try:
                pol = ecr.get_repository_policy(repositoryName=repo_name)
                record["Policy"] = json.loads(pol.get("policyText", "{}"))
            except botocore.exceptions.ClientError:
                pass

            # Lifecycle policy
            try:
                lifecycle = ecr.get_lifecycle_policy(repositoryName=repo_name)
                record["LifecyclePolicy"] = lifecycle.get("lifecyclePolicyText", "")
            except botocore.exceptions.ClientError:
                pass

            # Image scan findings summary
            try:
                images = ecr.describe_images(
                    repositoryName=repo_name,
                    filter={"tagStatus": "TAGGED"},
                    maxResults=10
                )
                record["RecentImages"] = images.get("imageDetails", [])
            except botocore.exceptions.ClientError:
                pass

            data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_repositories failed: {exc}")

    return "ecr", data
