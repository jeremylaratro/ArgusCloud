"""AWS IAM resource collectors."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="iam-summary",
    provider="aws",
    description="Collect IAM account summary",
    services=["iam"],
)
def collect_iam_summary(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect IAM account summary."""
    iam = session.client("iam")
    summary = iam.get_account_summary()
    return "iam-summary", [summary]


@collectors.collector(
    name="iam-roles",
    provider="aws",
    description="Collect IAM roles with policies",
    services=["iam"],
)
def collect_iam_roles(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect all IAM roles with their attached and inline policies."""
    iam = session.client("iam")
    data: List[Dict[str, Any]] = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            record: Dict[str, Any] = {"Role": role}
            role_name = role["RoleName"]

            # Attached managed policies
            try:
                attached = iam.list_attached_role_policies(RoleName=role_name)
                record["AttachedPolicies"] = attached.get("AttachedPolicies", [])
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_attached_role_policies failed for {role_name}: {exc}")
                record["AttachedPolicies"] = []

            # Inline policy names
            try:
                inline = iam.list_role_policies(RoleName=role_name)
                record["InlinePolicyNames"] = inline.get("PolicyNames", [])
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_role_policies failed for {role_name}: {exc}")
                record["InlinePolicyNames"] = []

            # Fetch inline policy documents
            inline_policies = []
            for policy_name in record["InlinePolicyNames"]:
                try:
                    pol = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    inline_policies.append(pol)
                except botocore.exceptions.ClientError as exc:
                    log.debug(f"get_role_policy failed for {role_name}/{policy_name}: {exc}")
            record["InlinePolicies"] = inline_policies

            data.append(record)

    return "iam-roles", data


@collectors.collector(
    name="iam-users",
    provider="aws",
    description="Collect IAM users with policies and groups",
    services=["iam"],
)
def collect_iam_users(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect all IAM users with their policies and group memberships."""
    iam = session.client("iam")
    data: List[Dict[str, Any]] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            record: Dict[str, Any] = {"User": user}
            user_name = user["UserName"]

            # Attached managed policies
            try:
                attached = iam.list_attached_user_policies(UserName=user_name)
                record["AttachedPolicies"] = attached.get("AttachedPolicies", [])
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_attached_user_policies failed for {user_name}: {exc}")
                record["AttachedPolicies"] = []

            # Groups
            try:
                groups = iam.list_groups_for_user(UserName=user_name)
                record["Groups"] = groups.get("Groups", [])
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_groups_for_user failed for {user_name}: {exc}")
                record["Groups"] = []

            # Inline policies
            try:
                inline = iam.list_user_policies(UserName=user_name)
                record["InlinePolicyNames"] = inline.get("PolicyNames", [])
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_user_policies failed for {user_name}: {exc}")
                record["InlinePolicyNames"] = []

            inline_policies = []
            for policy_name in record["InlinePolicyNames"]:
                try:
                    pol = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                    inline_policies.append(pol)
                except botocore.exceptions.ClientError as exc:
                    log.debug(f"get_user_policy failed for {user_name}/{policy_name}: {exc}")
            record["InlinePolicies"] = inline_policies

            # MFA devices
            try:
                mfa = iam.list_mfa_devices(UserName=user_name)
                record["MFADevices"] = mfa.get("MFADevices", [])
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_mfa_devices failed for {user_name}: {exc}")
                record["MFADevices"] = []

            # Access keys
            try:
                keys = iam.list_access_keys(UserName=user_name)
                record["AccessKeys"] = keys.get("AccessKeyMetadata", [])
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_access_keys failed for {user_name}: {exc}")
                record["AccessKeys"] = []

            # Login profile (console access)
            try:
                profile = iam.get_login_profile(UserName=user_name)
                record["LoginProfile"] = profile.get("LoginProfile", {})
            except botocore.exceptions.ClientError:
                record["LoginProfile"] = None

            data.append(record)

    return "iam-users", data


@collectors.collector(
    name="iam-policies",
    provider="aws",
    description="Collect customer-managed IAM policies",
    services=["iam"],
)
def collect_iam_policies(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect customer-managed IAM policies with their default version document."""
    iam = session.client("iam")
    data: List[Dict[str, Any]] = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local", OnlyAttached=False):
        for policy in page.get("Policies", []):
            record: Dict[str, Any] = {"Policy": policy}
            policy_arn = policy["Arn"]
            default_version = policy.get("DefaultVersionId")

            if default_version:
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )
                    record["DefaultVersionDocument"] = version
                except botocore.exceptions.ClientError as exc:
                    log.debug(f"get_policy_version failed for {policy_arn}: {exc}")

            data.append(record)

    return "iam-policies", data
