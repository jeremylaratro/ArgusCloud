"""AWS Identity service collectors (IAM Identity Center/SSO)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="sso",
    provider="aws",
    description="Collect IAM Identity Center (SSO) configuration",
    services=["sso-admin", "identitystore"],
)
def collect_sso(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect IAM Identity Center instances, permission sets, and users."""
    sso_admin = session.client("sso-admin")
    data: List[Dict[str, Any]] = []

    try:
        instances = sso_admin.list_instances().get("Instances", [])
        data.append({"Instances": instances})

        for inst in instances:
            inst_arn = inst.get("InstanceArn")
            identity_store_id = inst.get("IdentityStoreId")

            if not inst_arn:
                continue

            # Permission sets
            try:
                psets = sso_admin.list_permission_sets(InstanceArn=inst_arn)
                permission_sets = psets.get("PermissionSets", [])
                data.append({
                    "InstanceArn": inst_arn,
                    "PermissionSets": permission_sets
                })

                # Get details for each permission set
                for ps_arn in permission_sets:
                    try:
                        desc = sso_admin.describe_permission_set(
                            InstanceArn=inst_arn,
                            PermissionSetArn=ps_arn
                        )
                        ps_detail = desc.get("PermissionSet", {})

                        # Get inline policy
                        try:
                            inline = sso_admin.get_inline_policy_for_permission_set(
                                InstanceArn=inst_arn,
                                PermissionSetArn=ps_arn
                            )
                            ps_detail["InlinePolicy"] = inline.get("InlinePolicy", "")
                        except botocore.exceptions.ClientError:
                            pass

                        # Get managed policies
                        try:
                            managed = sso_admin.list_managed_policies_in_permission_set(
                                InstanceArn=inst_arn,
                                PermissionSetArn=ps_arn
                            )
                            ps_detail["ManagedPolicies"] = managed.get("AttachedManagedPolicies", [])
                        except botocore.exceptions.ClientError:
                            pass

                        data.append({"PermissionSet": ps_detail})
                    except botocore.exceptions.ClientError as exc:
                        log.debug(f"describe_permission_set failed for {ps_arn}: {exc}")

                # Get account assignments
                try:
                    # Get all accounts that have assignments
                    for ps_arn in permission_sets[:5]:  # Limit to avoid API throttling
                        try:
                            accounts = sso_admin.list_accounts_for_provisioned_permission_set(
                                InstanceArn=inst_arn,
                                PermissionSetArn=ps_arn
                            )
                            if accounts.get("AccountIds"):
                                data.append({
                                    "PermissionSetArn": ps_arn,
                                    "ProvisionedAccounts": accounts.get("AccountIds", [])
                                })
                        except botocore.exceptions.ClientError:
                            pass
                except botocore.exceptions.ClientError:
                    pass

            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_permission_sets failed for {inst_arn}: {exc}")

            # Identity Store users
            if identity_store_id:
                try:
                    identity = session.client("identitystore")
                    users = identity.list_users(IdentityStoreId=identity_store_id)
                    data.append({"Users": users.get("Users", [])})

                    # Groups
                    try:
                        groups = identity.list_groups(IdentityStoreId=identity_store_id)
                        data.append({"Groups": groups.get("Groups", [])})
                    except botocore.exceptions.ClientError:
                        pass

                except botocore.exceptions.ClientError as exc:
                    log.debug(f"list_users failed for identity store {identity_store_id}: {exc}")

    except botocore.exceptions.ClientError as exc:
        log.debug(f"list_instances failed: {exc}")

    return "sso", data
