"""AWS Organizations normalizers."""

from __future__ import annotations

from typing import Any, Dict, Iterable

from arguscloud.core.graph import CloudProvider, Edge, GraphData, Node
from arguscloud.core.registry import normalizers


@normalizers.normalizer(
    name="org",
    provider="aws",
    description="Normalize AWS Organizations to graph",
    input_type="org",
)
def normalize_organizations(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert AWS Organizations data to nodes and edges."""
    graph = GraphData()
    org_root_id = None
    accounts = []
    ous = []

    for rec in records:
        if "Organization" in rec:
            org = rec["Organization"]
            org_root_id = org.get("Id")
            if org_root_id:
                graph.add_node(Node(
                    id=f"org:{org_root_id}",
                    type="OrgRoot",
                    properties={
                        "master_account_arn": org.get("MasterAccountArn"),
                        "master_account_id": org.get("MasterAccountId"),
                        "master_account_email": org.get("MasterAccountEmail"),
                        "feature_set": org.get("FeatureSet"),
                        "arn": org.get("Arn"),
                    },
                    provider=CloudProvider.AWS,
                ))

        if "Accounts" in rec:
            accounts = rec.get("Accounts", [])

        if "OrganizationalUnits" in rec:
            ous = rec.get("OrganizationalUnits", [])

        if "ServiceControlPolicies" in rec:
            for scp in rec.get("ServiceControlPolicies", []):
                scp_id = scp.get("Id")
                if scp_id:
                    graph.add_node(Node(
                        id=f"scp:{scp_id}",
                        type="ServiceControlPolicy",
                        properties={
                            "name": scp.get("Name"),
                            "description": scp.get("Description"),
                            "content": scp.get("Content"),
                            "aws_managed": scp.get("AwsManaged", False),
                        },
                        provider=CloudProvider.AWS,
                    ))

    # Process accounts
    for acct in accounts:
        acct_id = acct.get("Id")
        if not acct_id:
            continue

        node_id = f"account:{acct_id}"
        graph.add_node(Node(
            id=node_id,
            type="Account",
            properties={
                "name": acct.get("Name"),
                "email": acct.get("Email"),
                "status": acct.get("Status"),
                "joined": str(acct.get("JoinedTimestamp", "")),
                "arn": acct.get("Arn"),
            },
            provider=CloudProvider.AWS,
        ))

        if org_root_id:
            graph.add_edge(Edge(
                src=f"org:{org_root_id}",
                dst=node_id,
                type="Contains",
                properties={"source": "organizations"},
                provider=CloudProvider.AWS,
            ))

    # Process OUs
    for ou in ous:
        ou_id = ou.get("Id")
        if ou_id:
            graph.add_node(Node(
                id=f"ou:{ou_id}",
                type="OrganizationalUnit",
                properties={
                    "name": ou.get("Name"),
                    "arn": ou.get("Arn"),
                },
                provider=CloudProvider.AWS,
            ))

    return graph
