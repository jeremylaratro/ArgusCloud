"""Tests for arguscloud.rules.aws.s3 module."""

import pytest
from arguscloud.core.graph import Node, Severity
from arguscloud.core.base import RuleContext
from arguscloud.rules.aws.s3 import (
    rule_public_s3,
    rule_s3_policy_allows_all,
    rule_s3_no_encryption,
    rule_s3_no_versioning,
)


class TestRulePublicS3:
    """Tests for the public S3 bucket rule."""

    def test_public_bucket_detected(self):
        """Test detecting a public S3 bucket."""
        nodes = [
            Node(
                id="arn:aws:s3:::public-bucket",
                type="S3Bucket",
                properties={
                    "name": "public-bucket",
                    "is_public": True,
                    "public_access_blocked": False,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_s3(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].rule_id == "aws-s3-public-bucket"
        assert result.attack_paths[0].severity == Severity.HIGH
        assert result.attack_paths[0].dst == "internet"

    def test_public_bucket_with_block_passes(self):
        """Test no finding when public access is blocked."""
        nodes = [
            Node(
                id="arn:aws:s3:::bucket",
                type="S3Bucket",
                properties={
                    "name": "bucket",
                    "is_public": True,
                    "public_access_blocked": True,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_s3(ctx)
        assert result.passed is True

    def test_private_bucket_passes(self):
        """Test no finding for private bucket."""
        nodes = [
            Node(
                id="arn:aws:s3:::private-bucket",
                type="S3Bucket",
                properties={"name": "private-bucket", "is_public": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_s3(ctx)
        assert result.passed is True

    def test_ignores_non_bucket_nodes(self):
        """Test that non-S3Bucket nodes are ignored."""
        nodes = [
            Node(id="role1", type="Role", properties={"is_public": True})
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_s3(ctx)
        assert result.passed is True


class TestRuleS3PolicyAllowsAll:
    """Tests for the S3 policy allows all rule."""

    def test_s3_policy_allows_all_detected(self):
        """Test detecting S3 policy with wildcard principal."""
        nodes = [
            Node(
                id="arn:aws:s3:::bucket:policy",
                type="ResourcePolicy",
                properties={
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "s3:GetObject",
                            }
                        ]
                    }
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_policy_allows_all(ctx)
        assert result.passed is False
        assert result.finding_count == 1

    def test_s3_policy_specific_principal_passes(self):
        """Test no finding when principal is specific."""
        nodes = [
            Node(
                id="arn:aws:s3:::bucket:policy",
                type="ResourcePolicy",
                properties={
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::123:root"},
                                "Action": "s3:GetObject",
                            }
                        ]
                    }
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_policy_allows_all(ctx)
        assert result.passed is True

    def test_ignores_non_s3_policies(self):
        """Test that non-S3 policies are ignored."""
        nodes = [
            Node(
                id="arn:aws:kms:region:123:key/id:policy",
                type="ResourcePolicy",
                properties={
                    "document": {"Statement": [{"Principal": "*"}]}
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_policy_allows_all(ctx)
        assert result.passed is True

    def test_empty_policy_document(self):
        """Test handling of empty policy document."""
        nodes = [
            Node(
                id="arn:aws:s3:::bucket:policy",
                type="ResourcePolicy",
                properties={"document": None},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_policy_allows_all(ctx)
        assert result.passed is True


class TestRuleS3NoEncryption:
    """Tests for the S3 bucket without encryption rule."""

    def test_unencrypted_bucket_detected(self):
        """Test detecting an unencrypted bucket."""
        nodes = [
            Node(
                id="arn:aws:s3:::unencrypted",
                type="S3Bucket",
                properties={"name": "unencrypted", "encrypted": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_no_encryption(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_encrypted_bucket_passes(self):
        """Test no finding for encrypted bucket."""
        nodes = [
            Node(
                id="arn:aws:s3:::encrypted",
                type="S3Bucket",
                properties={"name": "encrypted", "encrypted": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_no_encryption(ctx)
        assert result.passed is True

    def test_multiple_buckets(self):
        """Test detecting multiple unencrypted buckets."""
        nodes = [
            Node(id="bucket1", type="S3Bucket", properties={"encrypted": False}),
            Node(id="bucket2", type="S3Bucket", properties={"encrypted": True}),
            Node(id="bucket3", type="S3Bucket", properties={"encrypted": False}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_no_encryption(ctx)
        assert result.finding_count == 2


class TestRuleS3NoVersioning:
    """Tests for the S3 bucket without versioning rule."""

    def test_unversioned_bucket_detected(self):
        """Test detecting a bucket without versioning."""
        nodes = [
            Node(
                id="arn:aws:s3:::unversioned",
                type="S3Bucket",
                properties={"name": "unversioned", "versioning_enabled": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_no_versioning(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.LOW

    def test_versioned_bucket_passes(self):
        """Test no finding for versioned bucket."""
        nodes = [
            Node(
                id="arn:aws:s3:::versioned",
                type="S3Bucket",
                properties={"name": "versioned", "versioning_enabled": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_no_versioning(ctx)
        assert result.passed is True

    def test_remediation_message(self):
        """Test that remediation message is included."""
        nodes = [
            Node(
                id="bucket",
                type="S3Bucket",
                properties={"versioning_enabled": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_s3_no_versioning(ctx)
        assert "versioning" in result.attack_paths[0].remediation.lower()
