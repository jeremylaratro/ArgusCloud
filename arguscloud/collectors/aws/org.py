"""AWS Organizations collectors."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="org",
    provider="aws",
    description="Collect AWS Organizations structure",
    services=["organizations"],
)
def collect_organizations(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect AWS Organizations data including accounts and structure."""
    org = session.client("organizations")
    data: List[Dict[str, Any]] = []

    # Describe organization
    try:
        org_info = org.describe_organization()
        data.append(org_info)
    except org.exceptions.AWSOrganizationsNotInUseException:
        return "not-in-org", data
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_organization failed: {exc}")
        return "org-access-denied", data

    # List roots
    try:
        roots = org.list_roots().get("Roots", [])
        data.append({"Roots": roots})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"list_roots failed: {exc}")

    # List all accounts
    accounts = []
    try:
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            accounts.extend(page.get("Accounts", []))
        data.append({"Accounts": accounts})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"list_accounts failed: {exc}")

    # List organizational units (OUs)
    ous = []
    for root in roots:
        root_id = root.get("Id")
        if root_id:
            try:
                paginator = org.get_paginator("list_organizational_units_for_parent")
                for page in paginator.paginate(ParentId=root_id):
                    ous.extend(page.get("OrganizationalUnits", []))
            except botocore.exceptions.ClientError as exc:
                log.debug(f"list_organizational_units_for_parent failed for {root_id}: {exc}")

    if ous:
        data.append({"OrganizationalUnits": ous})

    # List SCPs (Service Control Policies)
    try:
        policies = org.list_policies(Filter="SERVICE_CONTROL_POLICY")
        scps = policies.get("Policies", [])
        for scp in scps:
            try:
                scp_detail = org.describe_policy(PolicyId=scp["Id"])
                scp["Content"] = scp_detail.get("Policy", {}).get("Content")
            except botocore.exceptions.ClientError:
                pass
        data.append({"ServiceControlPolicies": scps})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"list_policies for SCPs failed: {exc}")

    return "organization", data
