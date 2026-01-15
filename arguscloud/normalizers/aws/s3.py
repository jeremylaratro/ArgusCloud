"""AWS S3 normalizers."""

from __future__ import annotations

from typing import Any, Dict, Iterable

from arguscloud.core.graph import CloudProvider, Edge, GraphData, Node
from arguscloud.core.base import extract_principals
from arguscloud.core.registry import normalizers


@normalizers.normalizer(
    name="s3",
    provider="aws",
    description="Normalize S3 buckets to graph",
    input_type="s3",
)
def normalize_s3(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert S3 buckets to nodes and edges."""
    graph = GraphData()

    for rec in records:
        bucket = rec.get("Bucket") or {}
        name = bucket.get("Name")
        if not name:
            continue

        node_id = f"arn:aws:s3:::{name}"

        # Determine if bucket is public
        is_public = False
        policy_status = (rec.get("PolicyStatus") or {}).get("PolicyStatus", {})
        if policy_status.get("IsPublic"):
            is_public = True

        # Check public access block
        pab = rec.get("PublicAccessBlock", {})
        block_all = all([
            pab.get("BlockPublicAcls"),
            pab.get("IgnorePublicAcls"),
            pab.get("BlockPublicPolicy"),
            pab.get("RestrictPublicBuckets"),
        ]) if pab else False

        # Check encryption
        encryption = rec.get("Encryption", {})
        encrypted = bool(encryption.get("Rules"))

        # Check versioning
        versioning = rec.get("Versioning", {})
        versioning_enabled = versioning.get("Status") == "Enabled"

        # Check logging
        logging_enabled = bool(rec.get("Logging"))

        graph.add_node(Node(
            id=node_id,
            type="S3Bucket",
            properties={
                "name": name,
                "creation_date": str(bucket.get("CreationDate", "")),
                "region": rec.get("Location", "us-east-1"),
                "is_public": is_public,
                "public_access_blocked": block_all,
                "encrypted": encrypted,
                "versioning_enabled": versioning_enabled,
                "logging_enabled": logging_enabled,
                "acl": rec.get("Acl"),
            },
            provider=CloudProvider.AWS,
        ))

        # Process bucket policy
        policy = rec.get("Policy")
        if policy:
            policy_id = f"{node_id}:policy"
            graph.add_node(Node(
                id=policy_id,
                type="ResourcePolicy",
                properties={"document": policy},
                provider=CloudProvider.AWS,
            ))
            graph.add_edge(Edge(
                src=node_id,
                dst=policy_id,
                type="ResourcePolicy",
                properties={},
                provider=CloudProvider.AWS,
            ))

            # Extract policy principals
            principals = extract_principals(policy)
            for principal in principals:
                graph.add_edge(Edge(
                    src=policy_id,
                    dst=principal,
                    type="PolicyPrincipal",
                    properties={},
                    provider=CloudProvider.AWS,
                ))

    return graph
