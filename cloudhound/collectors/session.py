"""Credential-based AWS session management.

This module provides secure, memory-only credential handling for
AWS data collection from the web UI.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# AWS credential format validation
# Long-term keys: AKIA followed by 16 alphanumeric chars
# Temporary (STS) keys: ASIA followed by 16 alphanumeric chars
AWS_ACCESS_KEY_PATTERN = re.compile(r'^A[KS]IA[0-9A-Z]{16}$')
AWS_SECRET_KEY_LENGTH = 40


@dataclass
class AWSCredentials:
    """AWS credentials container (memory-only, never persisted)."""
    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None

    def __post_init__(self):
        # Validate access key format (AKIA for long-term, ASIA for STS)
        if not self.access_key or not AWS_ACCESS_KEY_PATTERN.match(self.access_key):
            raise ValueError(
                "Invalid AWS access key format. "
                "Expected AKIA/ASIA followed by 16 alphanumeric characters."
            )
        # Validate secret key length
        if not self.secret_key or len(self.secret_key) != AWS_SECRET_KEY_LENGTH:
            raise ValueError(
                f"Invalid AWS secret key. Expected {AWS_SECRET_KEY_LENGTH} characters."
            )

    def clear(self):
        """Clear credentials from memory."""
        self.access_key = "X" * len(self.access_key)
        self.secret_key = "X" * len(self.secret_key)
        if self.session_token:
            self.session_token = "X" * len(self.session_token)

    def __repr__(self):
        """Safe repr that doesn't expose credentials."""
        return f"<AWSCredentials access_key={self.access_key[:4]}*** region={self.region}>"


@dataclass
class CallerIdentity:
    """AWS caller identity information."""
    account_id: str
    arn: str
    user_id: str
    partition: str = "aws"


def create_session(credentials: AWSCredentials) -> boto3.Session:
    """Create a boto3 session from credentials.

    Args:
        credentials: AWS credentials object

    Returns:
        Configured boto3 Session
    """
    session_kwargs = {
        "aws_access_key_id": credentials.access_key,
        "aws_secret_access_key": credentials.secret_key,
    }

    if credentials.session_token:
        session_kwargs["aws_session_token"] = credentials.session_token

    if credentials.region:
        session_kwargs["region_name"] = credentials.region

    return boto3.Session(**session_kwargs)


def validate_credentials(credentials: AWSCredentials) -> CallerIdentity:
    """Validate AWS credentials by calling STS GetCallerIdentity.

    Args:
        credentials: AWS credentials to validate

    Returns:
        CallerIdentity with account info

    Raises:
        ValueError: If credentials are invalid
    """
    try:
        session = create_session(credentials)
        sts = session.client("sts")
        response = sts.get_caller_identity()

        arn = response["Arn"]
        partition = arn.split(":")[1] if ":" in arn else "aws"

        return CallerIdentity(
            account_id=response["Account"],
            arn=arn,
            user_id=response["UserId"],
            partition=partition,
        )
    except NoCredentialsError:
        raise ValueError("No credentials provided")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
            raise ValueError("Invalid AWS credentials")
        elif error_code == "ExpiredToken":
            raise ValueError("AWS session token has expired")
        elif error_code == "AccessDenied":
            raise ValueError("Access denied - check IAM permissions")
        else:
            raise ValueError(f"AWS error: {error_code}")
    except Exception as e:
        logger.error(f"Credential validation failed: {e}")
        raise ValueError(f"Failed to validate credentials: {str(e)}")


def get_available_regions(credentials: AWSCredentials) -> List[str]:
    """Get list of available AWS regions.

    Args:
        credentials: AWS credentials

    Returns:
        List of region names
    """
    try:
        session = create_session(credentials)
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions()
        return [r["RegionName"] for r in response.get("Regions", [])]
    except Exception as e:
        logger.warning(f"Failed to get regions: {e}")
        # Return default regions
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-northeast-1", "ap-southeast-1", "ap-southeast-2",
        ]
