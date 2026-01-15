"""AWS S3 collectors."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="s3",
    provider="aws",
    description="Collect S3 buckets with policies and ACLs",
    services=["s3"],
)
def collect_s3(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect S3 buckets with their policies, ACLs, and configuration."""
    s3 = session.client("s3")
    data: List[Dict[str, Any]] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except botocore.exceptions.ClientError as exc:
        log.warning(f"list_buckets failed: {exc}")
        return "s3-error", []

    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue

        record: Dict[str, Any] = {"Bucket": bucket}

        # Bucket ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            record["Acl"] = acl
        except botocore.exceptions.ClientError as exc:
            log.debug(f"get_bucket_acl failed for {name}: {exc}")

        # Bucket policy status (is public?)
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            record["PolicyStatus"] = policy_status
        except botocore.exceptions.ClientError:
            pass

        # Bucket policy document
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            record["Policy"] = json.loads(policy.get("Policy", "{}"))
        except botocore.exceptions.ClientError:
            pass

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            record["PublicAccessBlock"] = pab.get("PublicAccessBlockConfiguration", {})
        except botocore.exceptions.ClientError:
            pass

        # Bucket encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=name)
            record["Encryption"] = encryption.get("ServerSideEncryptionConfiguration", {})
        except botocore.exceptions.ClientError:
            pass

        # Bucket versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            record["Versioning"] = versioning
        except botocore.exceptions.ClientError:
            pass

        # Bucket logging
        try:
            logging_config = s3.get_bucket_logging(Bucket=name)
            record["Logging"] = logging_config.get("LoggingEnabled", {})
        except botocore.exceptions.ClientError:
            pass

        # Bucket location
        try:
            location = s3.get_bucket_location(Bucket=name)
            record["Location"] = location.get("LocationConstraint") or "us-east-1"
        except botocore.exceptions.ClientError:
            pass

        data.append(record)

    return "s3", data
