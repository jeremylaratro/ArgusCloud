"""AWS Storage and Secrets service collectors."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="kms",
    provider="aws",
    description="Collect KMS keys and policies",
    services=["kms"],
)
def collect_kms(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect KMS keys with their policies and configuration."""
    kms = session.client("kms")
    data: List[Dict[str, Any]] = []

    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                key_id = key.get("KeyId")
                if not key_id:
                    continue

                record: Dict[str, Any] = {"Key": key}

                # Key metadata
                try:
                    info = kms.describe_key(KeyId=key_id)
                    record["Metadata"] = info
                except botocore.exceptions.ClientError as exc:
                    log.debug(f"describe_key failed for {key_id}: {exc}")
                    continue

                # Key policy
                try:
                    pol = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                    record["Policy"] = json.loads(pol.get("Policy", "{}"))
                except botocore.exceptions.ClientError:
                    pass

                # Key rotation status
                try:
                    rotation = kms.get_key_rotation_status(KeyId=key_id)
                    record["RotationEnabled"] = rotation.get("KeyRotationEnabled", False)
                except botocore.exceptions.ClientError:
                    pass

                # Grants
                try:
                    grants = kms.list_grants(KeyId=key_id)
                    record["Grants"] = grants.get("Grants", [])
                except botocore.exceptions.ClientError:
                    pass

                data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"KMS collection failed: {exc}")

    return "kms", data


@collectors.collector(
    name="secretsmanager",
    provider="aws",
    description="Collect Secrets Manager secrets",
    services=["secretsmanager"],
)
def collect_secretsmanager(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect Secrets Manager secrets (metadata only, not values)."""
    sm = session.client("secretsmanager")
    data: List[Dict[str, Any]] = []

    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for sec in page.get("SecretList", []):
                record: Dict[str, Any] = {"Secret": sec}
                arn = sec.get("ARN")

                # Resource policy
                if arn:
                    try:
                        pol = sm.get_resource_policy(SecretId=arn)
                        policy_text = pol.get("ResourcePolicy")
                        if policy_text:
                            record["Policy"] = json.loads(policy_text)
                    except botocore.exceptions.ClientError:
                        pass

                data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"Secrets Manager collection failed: {exc}")

    return "secretsmanager", data


@collectors.collector(
    name="ssm-parameters",
    provider="aws",
    description="Collect SSM Parameter Store parameters",
    services=["ssm"],
)
def collect_ssm_parameters(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect SSM Parameter Store parameters (metadata only)."""
    ssm = session.client("ssm")
    data: List[Dict[str, Any]] = []

    try:
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                record: Dict[str, Any] = {"Parameter": param}

                # Check if it's a SecureString without KMS key
                if param.get("Type") == "SecureString" and not param.get("KeyId"):
                    record["UsingDefaultKMS"] = True

                data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"SSM Parameters collection failed: {exc}")

    return "ssm-parameters", data


@collectors.collector(
    name="rds",
    provider="aws",
    description="Collect RDS instances and snapshots",
    services=["rds"],
)
def collect_rds(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect RDS instances and snapshots with their sharing configuration."""
    rds = session.client("rds")
    data: List[Dict[str, Any]] = []

    # DB Instances
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                record: Dict[str, Any] = {"DBInstance": instance}
                data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_db_instances failed: {exc}")

    # DB Clusters (Aurora)
    try:
        paginator = rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            for cluster in page.get("DBClusters", []):
                record: Dict[str, Any] = {"DBCluster": cluster}
                data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_db_clusters failed: {exc}")

    # Manual Snapshots
    try:
        snaps = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
        for snap in snaps:
            record: Dict[str, Any] = {"Snapshot": snap}
            snap_id = snap.get("DBSnapshotIdentifier")

            if snap_id:
                try:
                    attrs = rds.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snap_id
                    )
                    record["Attributes"] = attrs.get("DBSnapshotAttributesResult", {})
                except botocore.exceptions.ClientError:
                    pass

            data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_db_snapshots failed: {exc}")

    # Cluster Snapshots
    try:
        cluster_snaps = rds.describe_db_cluster_snapshots(SnapshotType="manual")
        for snap in cluster_snaps.get("DBClusterSnapshots", []):
            record: Dict[str, Any] = {"ClusterSnapshot": snap}

            snap_id = snap.get("DBClusterSnapshotIdentifier")
            if snap_id:
                try:
                    attrs = rds.describe_db_cluster_snapshot_attributes(
                        DBClusterSnapshotIdentifier=snap_id
                    )
                    record["Attributes"] = attrs.get("DBClusterSnapshotAttributesResult", {})
                except botocore.exceptions.ClientError:
                    pass

            data.append(record)
    except botocore.exceptions.ClientError:
        pass

    return "rds", data
