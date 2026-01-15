"""Tests for IAM collector using moto.

These tests use moto to mock AWS IAM service and verify
the collector implementations work correctly.
"""

from __future__ import annotations

import json
import pytest
from typing import Any, Dict
from unittest.mock import MagicMock, patch

# Check if moto is available
try:
    import moto
    from moto import mock_aws
    HAS_MOTO = True
except ImportError:
    HAS_MOTO = False
    # Fallback decorator that works both as @mock_aws and @mock_aws()
    class mock_aws:
        def __init__(self, func=None):
            self.func = func
        def __call__(self, *args, **kwargs):
            if self.func is not None:
                return self.func(*args, **kwargs)
            # Called as @mock_aws() - return the function unchanged
            if len(args) == 1 and callable(args[0]):
                return args[0]
            return lambda f: f
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

import boto3


pytestmark = pytest.mark.skipif(
    not HAS_MOTO,
    reason="moto not installed (pip install moto)"
)


@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for moto."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def iam_client(aws_credentials):
    """Create a mocked IAM client."""
    with mock_aws():
        yield boto3.client("iam", region_name="us-east-1")


class TestIAMRoleCollection:
    """Tests for IAM role collection."""

    @mock_aws
    def test_collect_roles_empty(self, aws_credentials):
        """Test collecting roles when none exist."""
        from arguscloud.collectors.aws.utils import paginate_collect

        client = boto3.client("iam", region_name="us-east-1")
        roles = paginate_collect(client, "list_roles", "Roles")

        # Should only have service-linked roles or be empty
        assert isinstance(roles, list)

    @mock_aws
    def test_collect_roles_with_data(self, aws_credentials):
        """Test collecting roles when they exist."""
        from arguscloud.collectors.aws.utils import paginate_collect

        client = boto3.client("iam", region_name="us-east-1")

        # Create test roles
        client.create_role(
            RoleName="TestRole1",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            Description="Test role 1"
        )

        client.create_role(
            RoleName="TestRole2",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            Description="Test role 2"
        )

        roles = paginate_collect(client, "list_roles", "Roles")

        # Filter to just our test roles
        test_roles = [r for r in roles if r["RoleName"].startswith("TestRole")]
        assert len(test_roles) == 2

        role_names = {r["RoleName"] for r in test_roles}
        assert "TestRole1" in role_names
        assert "TestRole2" in role_names

    @mock_aws
    def test_collect_role_policies(self, aws_credentials):
        """Test collecting inline policies for a role."""
        from arguscloud.collectors.aws.utils import safe_api_call

        client = boto3.client("iam", region_name="us-east-1")

        # Create role with inline policy
        client.create_role(
            RoleName="RoleWithPolicy",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            })
        )

        client.put_role_policy(
            RoleName="RoleWithPolicy",
            PolicyName="InlinePolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }]
            })
        )

        # List inline policies
        policy_names = safe_api_call(
            client,
            "list_role_policies",
            result_key="PolicyNames",
            default=[],
            RoleName="RoleWithPolicy"
        )

        assert "InlinePolicy" in policy_names

    @mock_aws
    def test_collect_attached_policies(self, aws_credentials):
        """Test collecting attached managed policies."""
        from arguscloud.collectors.aws.utils import paginate_collect

        client = boto3.client("iam", region_name="us-east-1")

        # Create role
        client.create_role(
            RoleName="RoleWithAttached",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            })
        )

        # Attach AWS managed policy
        client.attach_role_policy(
            RoleName="RoleWithAttached",
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"
        )

        # Collect attached policies
        attached = paginate_collect(
            client,
            "list_attached_role_policies",
            "AttachedPolicies",
            RoleName="RoleWithAttached"
        )

        assert len(attached) == 1
        assert attached[0]["PolicyArn"] == "arn:aws:iam::aws:policy/ReadOnlyAccess"


class TestIAMUserCollection:
    """Tests for IAM user collection."""

    @mock_aws
    def test_collect_users(self, aws_credentials):
        """Test collecting IAM users."""
        from arguscloud.collectors.aws.utils import paginate_collect

        client = boto3.client("iam", region_name="us-east-1")

        # Create test users
        client.create_user(UserName="alice")
        client.create_user(UserName="bob")

        users = paginate_collect(client, "list_users", "Users")

        user_names = {u["UserName"] for u in users}
        assert "alice" in user_names
        assert "bob" in user_names

    @mock_aws
    def test_collect_user_groups(self, aws_credentials):
        """Test collecting groups for a user."""
        from arguscloud.collectors.aws.utils import paginate_collect

        client = boto3.client("iam", region_name="us-east-1")

        # Create user and group
        client.create_user(UserName="testuser")
        client.create_group(GroupName="admins")
        client.add_user_to_group(GroupName="admins", UserName="testuser")

        groups = paginate_collect(
            client,
            "list_groups_for_user",
            "Groups",
            UserName="testuser"
        )

        assert len(groups) == 1
        assert groups[0]["GroupName"] == "admins"

    @mock_aws
    def test_collect_user_access_keys(self, aws_credentials):
        """Test collecting access keys for a user."""
        from arguscloud.collectors.aws.utils import paginate_collect

        client = boto3.client("iam", region_name="us-east-1")

        client.create_user(UserName="keyuser")
        client.create_access_key(UserName="keyuser")

        keys = paginate_collect(
            client,
            "list_access_keys",
            "AccessKeyMetadata",
            UserName="keyuser"
        )

        assert len(keys) == 1
        assert keys[0]["UserName"] == "keyuser"


class TestIAMPolicyCollection:
    """Tests for IAM policy collection."""

    @mock_aws
    def test_collect_customer_policies(self, aws_credentials):
        """Test collecting customer managed policies."""
        from arguscloud.collectors.aws.utils import paginate_collect

        client = boto3.client("iam", region_name="us-east-1")

        # Create custom policy
        client.create_policy(
            PolicyName="CustomPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            })
        )

        policies = paginate_collect(
            client,
            "list_policies",
            "Policies",
            Scope="Local"  # Only customer policies
        )

        policy_names = {p["PolicyName"] for p in policies}
        assert "CustomPolicy" in policy_names

    @mock_aws
    def test_collect_policy_versions(self, aws_credentials):
        """Test collecting policy versions."""
        from arguscloud.collectors.aws.utils import paginate_collect, safe_api_call

        client = boto3.client("iam", region_name="us-east-1")

        # Create policy
        response = client.create_policy(
            PolicyName="VersionedPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }]
            })
        )
        policy_arn = response["Policy"]["Arn"]

        # Get the default version document
        version_response = safe_api_call(
            client,
            "get_policy_version",
            PolicyArn=policy_arn,
            VersionId="v1"
        )

        assert version_response is not None
        assert "PolicyVersion" in version_response


class TestCollectorUtilities:
    """Tests for collector utility functions."""

    def test_paginate_collect_handles_errors(self):
        """Test that paginate_collect handles errors gracefully."""
        from arguscloud.collectors.aws.utils import paginate_collect

        # Create a mock client that raises an error
        mock_client = MagicMock()
        mock_client.get_paginator.side_effect = Exception("API Error")

        result = paginate_collect(mock_client, "list_roles", "Roles")
        assert result == []

    def test_safe_api_call_returns_default_on_error(self):
        """Test that safe_api_call returns default on error."""
        from arguscloud.collectors.aws.utils import safe_api_call

        mock_client = MagicMock()
        mock_client.some_method.side_effect = Exception("API Error")

        result = safe_api_call(
            mock_client,
            "some_method",
            default={"empty": True}
        )
        assert result == {"empty": True}

    def test_safe_api_call_extracts_result_key(self):
        """Test that safe_api_call extracts the specified key."""
        from arguscloud.collectors.aws.utils import safe_api_call

        mock_client = MagicMock()
        mock_client.get_data.return_value = {
            "Data": {"value": 123},
            "Metadata": {"extra": "info"}
        }

        result = safe_api_call(
            mock_client,
            "get_data",
            result_key="Data"
        )
        assert result == {"value": 123}

    def test_batch_process(self):
        """Test batch processing utility."""
        from arguscloud.collectors.aws.utils import batch_process

        items = list(range(25))

        def processor(batch):
            return [{"item": i, "doubled": i * 2} for i in batch]

        results = batch_process(items, processor, batch_size=10)

        assert len(results) == 25
        assert results[0] == {"item": 0, "doubled": 0}
        assert results[24] == {"item": 24, "doubled": 48}

    def test_extract_arn_account_id(self):
        """Test ARN account ID extraction."""
        from arguscloud.collectors.aws.utils import extract_arn_account_id

        arn = "arn:aws:iam::123456789012:role/MyRole"
        assert extract_arn_account_id(arn) == "123456789012"

        # Global resources have empty account
        global_arn = "arn:aws:s3:::my-bucket"
        assert extract_arn_account_id(global_arn) is None

        # Invalid ARN
        assert extract_arn_account_id("not-an-arn") is None

    def test_extract_arn_region(self):
        """Test ARN region extraction."""
        from arguscloud.collectors.aws.utils import extract_arn_region

        arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-12345"
        assert extract_arn_region(arn) == "us-east-1"

        # IAM is global (no region)
        iam_arn = "arn:aws:iam::123456789012:role/MyRole"
        assert extract_arn_region(iam_arn) is None

    def test_get_tags_dict(self):
        """Test tags list to dict conversion."""
        from arguscloud.collectors.aws.utils import get_tags_dict

        tags_list = [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Team", "Value": "security"},
        ]

        result = get_tags_dict(tags_list)
        assert result == {"Environment": "prod", "Team": "security"}

        # Empty list
        assert get_tags_dict([]) == {}
        assert get_tags_dict(None) == {}

    def test_parse_policy_document(self):
        """Test policy document parsing."""
        from arguscloud.collectors.aws.utils import parse_policy_document

        # JSON string policy
        response = {
            "PolicyDocument": json.dumps({
                "Version": "2012-10-17",
                "Statement": []
            })
        }
        result = parse_policy_document(response)
        assert result["Version"] == "2012-10-17"

        # Already a dict
        response2 = {
            "PolicyDocument": {"Version": "2012-10-17", "Statement": []}
        }
        result2 = parse_policy_document(response2)
        assert result2["Version"] == "2012-10-17"

        # Invalid JSON
        response3 = {"PolicyDocument": "not-json"}
        result3 = parse_policy_document(response3, default={"error": True})
        assert result3 == {"error": True}


class TestCollectionContext:
    """Tests for CollectionContext context manager."""

    def test_collection_context_success(self):
        """Test successful collection context."""
        from arguscloud.collectors.aws.utils import CollectionContext

        with CollectionContext("test-service") as ctx:
            ctx.set_result([{"id": 1}, {"id": 2}])

        success, result = ctx.get_result()
        assert success is True
        assert len(result) == 2

    def test_collection_context_handles_exception(self):
        """Test that context handles exceptions gracefully."""
        from arguscloud.collectors.aws.utils import CollectionContext

        with CollectionContext("test-service") as ctx:
            raise ValueError("Test error")

        success, result = ctx.get_result()
        assert success is False
        assert result == []

    def test_collection_context_handles_client_error(self):
        """Test that context handles boto3 ClientError."""
        from arguscloud.collectors.aws.utils import CollectionContext
        from botocore.exceptions import ClientError

        with CollectionContext("test-service") as ctx:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "No access"}},
                "ListRoles"
            )

        success, result = ctx.get_result()
        assert success is False
