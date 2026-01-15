"""Tests for arguscloud.collectors.session module.

This module tests AWS credential handling, validation, and
session creation functionality.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError, NoCredentialsError

from arguscloud.collectors.session import (
    AWSCredentials,
    CallerIdentity,
    create_session,
    validate_credentials,
    get_available_regions,
    AWS_ACCESS_KEY_PATTERN,
    AWS_SECRET_KEY_LENGTH,
)


class TestAWSAccessKeyPattern:
    """Tests for AWS access key pattern validation."""

    def test_pattern_matches_long_term_key(self):
        """Test pattern matches AKIA (long-term) keys."""
        assert AWS_ACCESS_KEY_PATTERN.match("AKIAIOSFODNN7EXAMPLE") is not None

    def test_pattern_matches_sts_key(self):
        """Test pattern matches ASIA (STS) keys."""
        assert AWS_ACCESS_KEY_PATTERN.match("ASIAIOSFODNN7EXAMPLE") is not None

    def test_pattern_rejects_invalid_prefix(self):
        """Test pattern rejects keys with invalid prefix."""
        assert AWS_ACCESS_KEY_PATTERN.match("AGIAIOSFODNN7EXAMPLE") is None
        assert AWS_ACCESS_KEY_PATTERN.match("AXIAIOSFODNN7EXAMPLE") is None

    def test_pattern_rejects_short_key(self):
        """Test pattern rejects keys that are too short."""
        assert AWS_ACCESS_KEY_PATTERN.match("AKIAIOSFODNN7EXAMPL") is None

    def test_pattern_rejects_long_key(self):
        """Test pattern rejects keys that are too long."""
        assert AWS_ACCESS_KEY_PATTERN.match("AKIAIOSFODNN7EXAMPLEE") is None

    def test_pattern_rejects_lowercase(self):
        """Test pattern rejects lowercase characters."""
        assert AWS_ACCESS_KEY_PATTERN.match("AKIAiosfodnn7example") is None


class TestAWSCredentials:
    """Tests for AWSCredentials dataclass."""

    def test_valid_long_term_credentials(self, valid_aws_credentials):
        """Test creating credentials with valid long-term keys."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        assert creds.access_key == valid_aws_credentials["access_key"]
        assert creds.secret_key == valid_aws_credentials["secret_key"]
        assert creds.session_token is None
        assert creds.region is None

    def test_valid_sts_credentials(self, valid_sts_credentials):
        """Test creating credentials with STS temporary keys."""
        creds = AWSCredentials(
            access_key=valid_sts_credentials["access_key"],
            secret_key=valid_sts_credentials["secret_key"],
            session_token=valid_sts_credentials["session_token"],
            region=valid_sts_credentials["region"]
        )

        assert creds.access_key == valid_sts_credentials["access_key"]
        assert creds.session_token == valid_sts_credentials["session_token"]
        assert creds.region == "us-west-2"

    def test_invalid_access_key_format_raises_error(self):
        """Test that invalid access key format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid AWS access key format"):
            AWSCredentials(
                access_key="invalid-key",
                secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )

    def test_empty_access_key_raises_error(self):
        """Test that empty access key raises ValueError."""
        with pytest.raises(ValueError, match="Invalid AWS access key format"):
            AWSCredentials(
                access_key="",
                secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )

    def test_none_access_key_raises_error(self):
        """Test that None access key raises ValueError."""
        with pytest.raises(ValueError, match="Invalid AWS access key format"):
            AWSCredentials(
                access_key=None,
                secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )

    def test_invalid_secret_key_length_raises_error(self):
        """Test that invalid secret key length raises ValueError."""
        with pytest.raises(ValueError, match="Invalid AWS secret key"):
            AWSCredentials(
                access_key="AKIAIOSFODNN7EXAMPLE",
                secret_key="short-key"
            )

    def test_empty_secret_key_raises_error(self):
        """Test that empty secret key raises ValueError."""
        with pytest.raises(ValueError, match="Invalid AWS secret key"):
            AWSCredentials(
                access_key="AKIAIOSFODNN7EXAMPLE",
                secret_key=""
            )

    def test_secret_key_must_be_40_characters(self):
        """Test that secret key must be exactly 40 characters."""
        # 39 characters
        with pytest.raises(ValueError):
            AWSCredentials(
                access_key="AKIAIOSFODNN7EXAMPLE",
                secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE"
            )

        # 41 characters
        with pytest.raises(ValueError):
            AWSCredentials(
                access_key="AKIAIOSFODNN7EXAMPLE",
                secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYY"
            )

    def test_clear_overwrites_credentials(self, valid_aws_credentials):
        """Test that clear() overwrites credentials with X characters."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"],
            session_token="test-session-token"
        )

        creds.clear()

        # All characters should be 'X'
        assert all(c == "X" for c in creds.access_key)
        assert all(c == "X" for c in creds.secret_key)
        assert all(c == "X" for c in creds.session_token)

    def test_clear_preserves_length(self, valid_aws_credentials):
        """Test that clear() preserves original string lengths."""
        token = "test-session-token-12345"
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"],
            session_token=token
        )

        original_access_len = len(creds.access_key)
        original_secret_len = len(creds.secret_key)
        original_token_len = len(creds.session_token)

        creds.clear()

        assert len(creds.access_key) == original_access_len
        assert len(creds.secret_key) == original_secret_len
        assert len(creds.session_token) == original_token_len

    def test_clear_handles_none_session_token(self, valid_aws_credentials):
        """Test that clear() handles None session token gracefully."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        # Should not raise
        creds.clear()

        assert all(c == "X" for c in creds.access_key)
        assert all(c == "X" for c in creds.secret_key)
        assert creds.session_token is None

    def test_repr_does_not_expose_full_credentials(self, valid_aws_credentials):
        """Test that repr() only shows partial access key."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        repr_str = repr(creds)

        # Should show first 4 chars of access key
        assert "AKIA***" in repr_str
        # Should NOT show full access key or any of secret key
        assert valid_aws_credentials["access_key"] not in repr_str
        assert valid_aws_credentials["secret_key"] not in repr_str


class TestCallerIdentity:
    """Tests for CallerIdentity dataclass."""

    def test_caller_identity_creation(self):
        """Test CallerIdentity with required fields."""
        identity = CallerIdentity(
            account_id="123456789012",
            arn="arn:aws:iam::123456789012:user/testuser",
            user_id="AIDAEXAMPLEUSERID"
        )

        assert identity.account_id == "123456789012"
        assert identity.arn == "arn:aws:iam::123456789012:user/testuser"
        assert identity.user_id == "AIDAEXAMPLEUSERID"
        assert identity.partition == "aws"  # Default value

    def test_caller_identity_with_custom_partition(self):
        """Test CallerIdentity with custom partition."""
        identity = CallerIdentity(
            account_id="123456789012",
            arn="arn:aws-us-gov:iam::123456789012:user/testuser",
            user_id="AIDAEXAMPLEUSERID",
            partition="aws-us-gov"
        )

        assert identity.partition == "aws-us-gov"


class TestCreateSession:
    """Tests for create_session function."""

    def test_create_session_with_basic_credentials(self, valid_aws_credentials):
        """Test create_session with basic credentials."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        with patch("arguscloud.collectors.session.boto3.Session") as mock_session:
            create_session(creds)

            mock_session.assert_called_once_with(
                aws_access_key_id=valid_aws_credentials["access_key"],
                aws_secret_access_key=valid_aws_credentials["secret_key"]
            )

    def test_create_session_with_session_token(self, valid_sts_credentials):
        """Test create_session includes session token when provided."""
        creds = AWSCredentials(
            access_key=valid_sts_credentials["access_key"],
            secret_key=valid_sts_credentials["secret_key"],
            session_token=valid_sts_credentials["session_token"]
        )

        with patch("arguscloud.collectors.session.boto3.Session") as mock_session:
            create_session(creds)

            call_kwargs = mock_session.call_args[1]
            assert "aws_session_token" in call_kwargs
            assert call_kwargs["aws_session_token"] == valid_sts_credentials["session_token"]

    def test_create_session_with_region(self, valid_aws_credentials):
        """Test create_session includes region when provided."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"],
            region="eu-west-1"
        )

        with patch("arguscloud.collectors.session.boto3.Session") as mock_session:
            create_session(creds)

            call_kwargs = mock_session.call_args[1]
            assert call_kwargs["region_name"] == "eu-west-1"


class TestValidateCredentials:
    """Tests for validate_credentials function."""

    def test_validate_credentials_success(self, valid_aws_credentials, mock_sts_client):
        """Test validate_credentials returns CallerIdentity on success."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts_client
            mock_create.return_value = mock_session

            identity = validate_credentials(creds)

            assert identity.account_id == "123456789012"
            assert identity.arn == "arn:aws:iam::123456789012:user/testuser"
            assert identity.partition == "aws"

    def test_validate_credentials_extracts_partition_from_arn(self, valid_aws_credentials):
        """Test validate_credentials extracts partition from ARN."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "UserId": "AIDAEXAMPLEUSERID",
            "Account": "123456789012",
            "Arn": "arn:aws-us-gov:iam::123456789012:user/testuser"
        }

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts
            mock_create.return_value = mock_session

            identity = validate_credentials(creds)

            assert identity.partition == "aws-us-gov"

    def test_validate_credentials_invalid_token_error(self, valid_aws_credentials):
        """Test validate_credentials raises for InvalidClientTokenId."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "Invalid"}},
            "GetCallerIdentity"
        )

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts
            mock_create.return_value = mock_session

            with pytest.raises(ValueError, match="Invalid AWS credentials"):
                validate_credentials(creds)

    def test_validate_credentials_signature_mismatch_error(self, valid_aws_credentials):
        """Test validate_credentials raises for SignatureDoesNotMatch."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "SignatureDoesNotMatch", "Message": "Signature mismatch"}},
            "GetCallerIdentity"
        )

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts
            mock_create.return_value = mock_session

            with pytest.raises(ValueError, match="Invalid AWS credentials"):
                validate_credentials(creds)

    def test_validate_credentials_expired_token_error(self, valid_sts_credentials):
        """Test validate_credentials raises for ExpiredToken."""
        creds = AWSCredentials(
            access_key=valid_sts_credentials["access_key"],
            secret_key=valid_sts_credentials["secret_key"],
            session_token=valid_sts_credentials["session_token"]
        )

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "ExpiredToken", "Message": "Token expired"}},
            "GetCallerIdentity"
        )

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts
            mock_create.return_value = mock_session

            with pytest.raises(ValueError, match="session token has expired"):
                validate_credentials(creds)

    def test_validate_credentials_access_denied_error(self, valid_aws_credentials):
        """Test validate_credentials raises for AccessDenied."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "GetCallerIdentity"
        )

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts
            mock_create.return_value = mock_session

            with pytest.raises(ValueError, match="Access denied"):
                validate_credentials(creds)

    def test_validate_credentials_no_credentials_error(self, valid_aws_credentials):
        """Test validate_credentials raises for NoCredentialsError."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts
            mock_create.return_value = mock_session

            with pytest.raises(ValueError, match="No credentials provided"):
                validate_credentials(creds)


class TestGetAvailableRegions:
    """Tests for get_available_regions function."""

    def test_get_available_regions_success(self, valid_aws_credentials):
        """Test get_available_regions returns region list on success."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"},
                {"RegionName": "eu-west-1"},
            ]
        }

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_ec2
            mock_create.return_value = mock_session

            regions = get_available_regions(creds)

            assert "us-east-1" in regions
            assert "us-west-2" in regions
            assert "eu-west-1" in regions

    def test_get_available_regions_returns_defaults_on_error(self, valid_aws_credentials):
        """Test get_available_regions returns default regions on error."""
        creds = AWSCredentials(
            access_key=valid_aws_credentials["access_key"],
            secret_key=valid_aws_credentials["secret_key"]
        )

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.side_effect = Exception("API error")

        with patch("arguscloud.collectors.session.create_session") as mock_create:
            mock_session = MagicMock()
            mock_session.client.return_value = mock_ec2
            mock_create.return_value = mock_session

            regions = get_available_regions(creds)

            # Should return default regions
            assert "us-east-1" in regions
            assert "us-west-2" in regions
            assert len(regions) >= 10  # Default list has at least 10 regions
