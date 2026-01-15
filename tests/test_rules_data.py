"""Tests for arguscloud.rules.aws.data module."""

import pytest
from arguscloud.core.graph import Node, Severity
from arguscloud.core.base import RuleContext
from arguscloud.rules.aws.data import (
    rule_kms_public_access,
    rule_kms_no_rotation,
    rule_rds_public_snapshot,
    rule_rds_unencrypted_snapshot,
    rule_secrets_no_rotation,
)


class TestRuleKmsPublicAccess:
    """Tests for the KMS public access rule."""

    def test_kms_public_access_detected(self):
        """Test detecting KMS key with wildcard principal."""
        nodes = [
            Node(
                id="arn:aws:kms:us-east-1:123:key/abc:policy",
                type="ResourcePolicy",
                properties={
                    "document": {
                        "Statement": [{"Effect": "Allow", "Principal": "*"}]
                    }
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_kms_public_access(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_kms_specific_principal_passes(self):
        """Test no finding for specific principal."""
        nodes = [
            Node(
                id="arn:aws:kms:us-east-1:123:key/abc:policy",
                type="ResourcePolicy",
                properties={
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::123:root"},
                            }
                        ]
                    }
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_kms_public_access(ctx)
        assert result.passed is True

    def test_ignores_non_kms_policies(self):
        """Test that non-KMS policies are ignored."""
        nodes = [
            Node(
                id="arn:aws:s3:::bucket:policy",
                type="ResourcePolicy",
                properties={"document": {"Statement": [{"Principal": "*"}]}},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_kms_public_access(ctx)
        assert result.passed is True


class TestRuleKmsNoRotation:
    """Tests for the KMS no rotation rule."""

    def test_no_rotation_detected(self):
        """Test detecting KMS key without rotation."""
        nodes = [
            Node(
                id="arn:aws:kms:us-east-1:123:key/abc",
                type="KMSKey",
                properties={
                    "rotation_enabled": False,
                    "key_state": "Enabled",
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_kms_no_rotation(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.LOW

    def test_rotation_enabled_passes(self):
        """Test no finding when rotation is enabled."""
        nodes = [
            Node(
                id="arn:aws:kms:us-east-1:123:key/abc",
                type="KMSKey",
                properties={
                    "rotation_enabled": True,
                    "key_state": "Enabled",
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_kms_no_rotation(ctx)
        assert result.passed is True

    def test_disabled_key_passes(self):
        """Test no finding for disabled keys."""
        nodes = [
            Node(
                id="arn:aws:kms:us-east-1:123:key/abc",
                type="KMSKey",
                properties={
                    "rotation_enabled": False,
                    "key_state": "Disabled",
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_kms_no_rotation(ctx)
        assert result.passed is True


class TestRuleRdsPublicSnapshot:
    """Tests for the RDS public snapshot rule."""

    def test_public_snapshot_detected(self):
        """Test detecting public RDS snapshot."""
        nodes = [
            Node(
                id="rds:snap-123",
                type="RDSSnapshot",
                properties={"public": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_rds_public_snapshot(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_private_snapshot_passes(self):
        """Test no finding for private snapshot."""
        nodes = [
            Node(
                id="rds:snap-123",
                type="RDSSnapshot",
                properties={"public": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_rds_public_snapshot(ctx)
        assert result.passed is True


class TestRuleRdsUnencryptedSnapshot:
    """Tests for the RDS unencrypted snapshot rule."""

    def test_unencrypted_snapshot_detected(self):
        """Test detecting unencrypted RDS snapshot."""
        nodes = [
            Node(
                id="rds:snap-123",
                type="RDSSnapshot",
                properties={"encrypted": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_rds_unencrypted_snapshot(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_encrypted_snapshot_passes(self):
        """Test no finding for encrypted snapshot."""
        nodes = [
            Node(
                id="rds:snap-123",
                type="RDSSnapshot",
                properties={"encrypted": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_rds_unencrypted_snapshot(ctx)
        assert result.passed is True

    def test_missing_encrypted_field_passes(self):
        """Test no finding when encrypted field is missing."""
        nodes = [
            Node(
                id="rds:snap-123",
                type="RDSSnapshot",
                properties={},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_rds_unencrypted_snapshot(ctx)
        assert result.passed is True


class TestRuleSecretsNoRotation:
    """Tests for the Secrets Manager no rotation rule."""

    def test_no_rotation_detected(self):
        """Test detecting secret without rotation."""
        nodes = [
            Node(
                id="arn:aws:secretsmanager:us-east-1:123:secret:my-secret",
                type="Secret",
                properties={"name": "my-secret", "rotation_enabled": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_secrets_no_rotation(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_rotation_enabled_passes(self):
        """Test no finding when rotation is enabled."""
        nodes = [
            Node(
                id="arn:aws:secretsmanager:us-east-1:123:secret:my-secret",
                type="Secret",
                properties={"name": "my-secret", "rotation_enabled": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_secrets_no_rotation(ctx)
        assert result.passed is True

    def test_multiple_secrets(self):
        """Test detecting multiple secrets without rotation."""
        nodes = [
            Node(id="secret-1", type="Secret", properties={"rotation_enabled": False}),
            Node(id="secret-2", type="Secret", properties={"rotation_enabled": True}),
            Node(id="secret-3", type="Secret", properties={"rotation_enabled": False}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_secrets_no_rotation(ctx)
        assert result.finding_count == 2
