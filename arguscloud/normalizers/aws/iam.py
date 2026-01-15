"""AWS IAM normalizers."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from arguscloud.core.graph import CloudProvider, Edge, GraphData, Node
from arguscloud.core.base import extract_principals, is_admin_policy
from arguscloud.core.registry import normalizers


@normalizers.normalizer(
    name="iam-roles",
    provider="aws",
    description="Normalize IAM roles to graph nodes and edges",
    input_type="iam-roles",
)
def normalize_iam_roles(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert IAM roles to nodes and edges."""
    graph = GraphData()

    for rec in records:
        role = rec.get("Role") or {}
        arn = role.get("Arn")
        if not arn:
            continue

        is_admin = False

        # Extract trust relationships
        trust_doc = role.get("AssumeRolePolicyDocument") or {}
        principals = extract_principals(trust_doc)
        for principal in principals:
            graph.add_edge(Edge(
                src=arn,
                dst=principal,
                type="Trusts",
                properties={"source": "AssumeRolePolicyDocument"},
                provider=CloudProvider.AWS,
            ))

        # Attached managed policies
        for pol in rec.get("AttachedPolicies", []):
            pol_arn = pol.get("PolicyArn")
            if pol_arn:
                if pol.get("PolicyName") == "AdministratorAccess":
                    is_admin = True
                graph.add_edge(Edge(
                    src=arn,
                    dst=pol_arn,
                    type="AttachedPolicy",
                    properties={"policy_name": pol.get("PolicyName")},
                    provider=CloudProvider.AWS,
                ))

        # Inline policies
        for pol in rec.get("InlinePolicies", []):
            pol_name = pol.get("PolicyName")
            if not pol_name:
                continue

            pol_doc = pol.get("PolicyDocument") or {}
            if is_admin_policy(pol_doc):
                is_admin = True

            inline_id = f"{arn}:inline:{pol_name}"
            graph.add_node(Node(
                id=inline_id,
                type="InlinePolicy",
                properties={
                    "name": pol_name,
                    "document": pol_doc,
                    "parent": arn,
                },
                provider=CloudProvider.AWS,
            ))
            graph.add_edge(Edge(
                src=arn,
                dst=inline_id,
                type="AttachedInlinePolicy",
                properties={},
                provider=CloudProvider.AWS,
            ))

        # Create role node
        graph.add_node(Node(
            id=arn,
            type="Role",
            properties={
                "name": role.get("RoleName"),
                "description": role.get("Description"),
                "create_date": str(role.get("CreateDate", "")),
                "assume_role_policy": trust_doc,
                "is_admin": is_admin,
                "path": role.get("Path"),
                "max_session_duration": role.get("MaxSessionDuration"),
            },
            provider=CloudProvider.AWS,
        ))

    return graph


@normalizers.normalizer(
    name="iam-users",
    provider="aws",
    description="Normalize IAM users to graph nodes and edges",
    input_type="iam-users",
)
def normalize_iam_users(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert IAM users to nodes and edges."""
    graph = GraphData()

    for rec in records:
        user = rec.get("User") or {}
        arn = user.get("Arn")
        if not arn:
            continue

        # User properties
        has_console = rec.get("LoginProfile") is not None
        has_mfa = len(rec.get("MFADevices", [])) > 0
        access_keys = rec.get("AccessKeys", [])
        active_keys = [k for k in access_keys if k.get("Status") == "Active"]

        graph.add_node(Node(
            id=arn,
            type="User",
            properties={
                "name": user.get("UserName"),
                "create_date": str(user.get("CreateDate", "")),
                "password_last_used": str(user.get("PasswordLastUsed", "")),
                "has_console_access": has_console,
                "has_mfa": has_mfa,
                "active_access_keys": len(active_keys),
                "path": user.get("Path"),
            },
            provider=CloudProvider.AWS,
        ))

        # Group memberships
        for grp in rec.get("Groups", []):
            grp_arn = grp.get("Arn")
            if grp_arn:
                graph.add_node(Node(
                    id=grp_arn,
                    type="Group",
                    properties={"name": grp.get("GroupName")},
                    provider=CloudProvider.AWS,
                ))
                graph.add_edge(Edge(
                    src=arn,
                    dst=grp_arn,
                    type="MemberOf",
                    properties={},
                    provider=CloudProvider.AWS,
                ))

        # Attached policies
        for pol in rec.get("AttachedPolicies", []):
            pol_arn = pol.get("PolicyArn")
            if pol_arn:
                graph.add_edge(Edge(
                    src=arn,
                    dst=pol_arn,
                    type="AttachedPolicy",
                    properties={"policy_name": pol.get("PolicyName")},
                    provider=CloudProvider.AWS,
                ))

        # Inline policies
        for pol in rec.get("InlinePolicies", []):
            pol_name = pol.get("PolicyName")
            if not pol_name:
                continue

            inline_id = f"{arn}:inline:{pol_name}"
            graph.add_node(Node(
                id=inline_id,
                type="InlinePolicy",
                properties={
                    "name": pol_name,
                    "document": pol.get("PolicyDocument"),
                    "parent": arn,
                },
                provider=CloudProvider.AWS,
            ))
            graph.add_edge(Edge(
                src=arn,
                dst=inline_id,
                type="AttachedInlinePolicy",
                properties={},
                provider=CloudProvider.AWS,
            ))

    return graph


@normalizers.normalizer(
    name="iam-policies",
    provider="aws",
    description="Normalize IAM managed policies",
    input_type="iam-policies",
)
def normalize_iam_policies(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert IAM managed policies to nodes."""
    graph = GraphData()

    for rec in records:
        pol = rec.get("Policy") or {}
        arn = pol.get("Arn")
        if not arn:
            continue

        doc = (rec.get("DefaultVersionDocument") or {}).get("PolicyVersion", {}).get("Document")

        graph.add_node(Node(
            id=arn,
            type="ManagedPolicy",
            properties={
                "name": pol.get("PolicyName"),
                "path": pol.get("Path"),
                "create_date": str(pol.get("CreateDate", "")),
                "update_date": str(pol.get("UpdateDate", "")),
                "description": pol.get("Description"),
                "document": doc,
                "is_admin": is_admin_policy(doc) if doc else False,
                "attachment_count": pol.get("AttachmentCount", 0),
            },
            provider=CloudProvider.AWS,
        ))

    return graph
