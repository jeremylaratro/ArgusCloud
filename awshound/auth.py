import datetime as dt
from dataclasses import dataclass
from typing import Optional

import boto3
import botocore


@dataclass
class CallerIdentity:
    account: str
    arn: str
    user_id: str
    resolved_region: Optional[str]
    partition: str


def resolve_session(profile: Optional[str] = None, region: Optional[str] = None) -> tuple[boto3.Session, CallerIdentity]:
    """Create a boto3 session and fetch caller identity."""
    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client("sts")
    try:
        resp = sts.get_caller_identity()
    except botocore.exceptions.BotoCoreError as exc:  # pragma: no cover - networked call
        raise RuntimeError(f"Failed to resolve caller identity: {exc}") from exc

    arn: str = resp["Arn"]
    partition = arn.split(":")[1] if ":" in arn else "aws"
    region_name = session.region_name
    return session, CallerIdentity(
        account=resp["Account"],
        arn=arn,
        user_id=resp["UserId"],
        resolved_region=region_name,
        partition=partition,
    )


def session_metadata(profile: Optional[str]) -> dict:
    """Collect lightweight metadata about the configured session for manifest context."""
    return {
        "profile": profile or "default",
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
    }
