"""AWS DevOps service collectors (CodeBuild, CodePipeline, CloudFormation, CloudWatch)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="codebuild",
    provider="aws",
    description="Collect CodeBuild projects",
    services=["codebuild"],
)
def collect_codebuild(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect CodeBuild projects with their configuration."""
    cb = session.client("codebuild")
    data: List[Dict[str, Any]] = []

    try:
        projects = cb.list_projects().get("projects", [])
        if projects:
            # Batch get project details (max 100 at a time)
            for i in range(0, len(projects), 100):
                batch = projects[i:i+100]
                details = cb.batch_get_projects(names=batch).get("projects", [])
                for proj in details:
                    record: Dict[str, Any] = {"Project": proj}

                    # Check for sensitive environment variables
                    env = proj.get("environment", {})
                    env_vars = env.get("environmentVariables", [])
                    sensitive_vars = [
                        v for v in env_vars
                        if v.get("type") == "PLAINTEXT" and any(
                            keyword in v.get("name", "").upper()
                            for keyword in ["SECRET", "PASSWORD", "KEY", "TOKEN", "CREDENTIAL"]
                        )
                    ]
                    record["PotentiallySensitiveEnvVars"] = sensitive_vars

                    data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"CodeBuild collection failed: {exc}")

    return "codebuild", data


@collectors.collector(
    name="codepipeline",
    provider="aws",
    description="Collect CodePipeline pipelines",
    services=["codepipeline"],
)
def collect_codepipeline(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect CodePipeline pipelines with their configuration."""
    cp = session.client("codepipeline")
    data: List[Dict[str, Any]] = []

    try:
        pipelines = cp.list_pipelines().get("pipelines", [])
        for p in pipelines:
            try:
                pipe = cp.get_pipeline(name=p["name"])
                record: Dict[str, Any] = {"Pipeline": pipe.get("pipeline", {})}

                # Get pipeline state
                try:
                    state = cp.get_pipeline_state(name=p["name"])
                    record["State"] = state
                except botocore.exceptions.ClientError:
                    pass

                data.append(record)
            except botocore.exceptions.ClientError as exc:
                log.debug(f"get_pipeline failed for {p.get('name')}: {exc}")
    except botocore.exceptions.ClientError as exc:
        log.warning(f"CodePipeline collection failed: {exc}")

    return "codepipeline", data


@collectors.collector(
    name="cloudformation",
    provider="aws",
    description="Collect CloudFormation stacks",
    services=["cloudformation"],
)
def collect_cloudformation(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect CloudFormation stacks."""
    cfn = session.client("cloudformation")
    data: List[Dict[str, Any]] = []

    active_statuses = [
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
    ]

    try:
        stacks = cfn.list_stacks(StackStatusFilter=active_statuses)
        for stack in stacks.get("StackSummaries", []):
            record: Dict[str, Any] = {"Stack": stack}
            stack_name = stack.get("StackName")

            # Get stack details
            if stack_name:
                try:
                    detail = cfn.describe_stacks(StackName=stack_name)
                    if detail.get("Stacks"):
                        record["StackDetail"] = detail["Stacks"][0]
                except botocore.exceptions.ClientError:
                    pass

            data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"CloudFormation collection failed: {exc}")

    return "cloudformation", data


@collectors.collector(
    name="cloudwatch",
    provider="aws",
    description="Collect CloudWatch Log Groups",
    services=["logs"],
)
def collect_cloudwatch(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect CloudWatch Log Groups with their configuration."""
    cw = session.client("logs")
    data: List[Dict[str, Any]] = []

    try:
        paginator = cw.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            log_groups = page.get("logGroups", [])
            for lg in log_groups:
                record: Dict[str, Any] = {"LogGroup": lg}

                # Check retention
                if not lg.get("retentionInDays"):
                    record["NoRetentionPolicy"] = True

                # Check if encrypted with KMS
                if not lg.get("kmsKeyId"):
                    record["NotKMSEncrypted"] = True

                data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"CloudWatch Logs collection failed: {exc}")

    return "cloudwatch", data
