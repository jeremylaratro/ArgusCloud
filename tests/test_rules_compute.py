"""Tests for arguscloud.rules.aws.compute module."""

import pytest
from arguscloud.core.graph import Node, Severity
from arguscloud.core.base import RuleContext
from arguscloud.rules.aws.compute import (
    rule_lambda_public_url,
    rule_eks_public_endpoint,
    rule_codebuild_privileged,
    rule_codebuild_env_secrets,
    rule_ecr_cross_account,
)


class TestRuleLambdaPublicUrl:
    """Tests for the Lambda public URL rule."""

    def test_public_url_no_auth_detected(self):
        """Test detecting Lambda with public URL without auth."""
        nodes = [
            Node(
                id="func-1",
                type="LambdaFunction",
                properties={
                    "name": "my-func",
                    "has_public_url": True,
                    "url_auth_type": "NONE",
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_lambda_public_url(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_public_url_with_auth_passes(self):
        """Test no finding when public URL has IAM auth."""
        nodes = [
            Node(
                id="func-1",
                type="LambdaFunction",
                properties={
                    "name": "my-func",
                    "has_public_url": True,
                    "url_auth_type": "AWS_IAM",
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_lambda_public_url(ctx)
        assert result.passed is True

    def test_no_public_url_passes(self):
        """Test no finding when function has no public URL."""
        nodes = [
            Node(
                id="func-1",
                type="LambdaFunction",
                properties={"name": "my-func", "has_public_url": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_lambda_public_url(ctx)
        assert result.passed is True


class TestRuleEksPublicEndpoint:
    """Tests for the EKS public endpoint rule."""

    def test_public_only_endpoint_detected(self):
        """Test detecting EKS with public-only endpoint."""
        nodes = [
            Node(
                id="cluster-1",
                type="EKSCluster",
                properties={
                    "name": "my-cluster",
                    "public_access": True,
                    "private_access": False,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_eks_public_endpoint(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_public_and_private_passes(self):
        """Test no finding when both public and private enabled."""
        nodes = [
            Node(
                id="cluster-1",
                type="EKSCluster",
                properties={
                    "name": "my-cluster",
                    "public_access": True,
                    "private_access": True,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_eks_public_endpoint(ctx)
        assert result.passed is True

    def test_private_only_passes(self):
        """Test no finding when only private endpoint."""
        nodes = [
            Node(
                id="cluster-1",
                type="EKSCluster",
                properties={
                    "name": "my-cluster",
                    "public_access": False,
                    "private_access": True,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_eks_public_endpoint(ctx)
        assert result.passed is True


class TestRuleCodebuildPrivileged:
    """Tests for the CodeBuild privileged mode rule."""

    def test_privileged_mode_detected(self):
        """Test detecting CodeBuild with privileged mode."""
        nodes = [
            Node(
                id="project-1",
                type="CodeBuildProject",
                properties={"name": "my-project", "environment_privileged": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_codebuild_privileged(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_non_privileged_passes(self):
        """Test no finding for non-privileged project."""
        nodes = [
            Node(
                id="project-1",
                type="CodeBuildProject",
                properties={"name": "my-project", "environment_privileged": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_codebuild_privileged(ctx)
        assert result.passed is True


class TestRuleCodebuildEnvSecrets:
    """Tests for the CodeBuild environment secrets rule."""

    def test_env_secrets_detected(self):
        """Test detecting potentially sensitive env vars."""
        nodes = [
            Node(
                id="project-1",
                type="CodeBuildProject",
                properties={
                    "name": "my-project",
                    "environment_vars": [
                        {"name": "AWS_SECRET_ACCESS_KEY", "value": "xxx"},
                        {"name": "BUILD_NUMBER", "value": "123"},
                    ],
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_codebuild_env_secrets(ctx)
        assert result.passed is False
        assert result.finding_count == 1

    def test_no_secrets_passes(self):
        """Test no finding when no sensitive env vars."""
        nodes = [
            Node(
                id="project-1",
                type="CodeBuildProject",
                properties={
                    "name": "my-project",
                    "environment_vars": [
                        {"name": "BUILD_NUMBER", "value": "123"},
                        {"name": "ENVIRONMENT", "value": "prod"},
                    ],
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_codebuild_env_secrets(ctx)
        assert result.passed is True

    def test_detects_various_sensitive_keywords(self):
        """Test detection of various sensitive keywords."""
        sensitive_names = [
            "PASSWORD",
            "API_KEY",
            "SECRET_TOKEN",
            "CREDENTIAL_FILE",
        ]
        for name in sensitive_names:
            nodes = [
                Node(
                    id="project-1",
                    type="CodeBuildProject",
                    properties={
                        "environment_vars": [{"name": name, "value": "xxx"}]
                    },
                )
            ]
            ctx = RuleContext(nodes=nodes, edges=[])
            result = rule_codebuild_env_secrets(ctx)
            assert result.passed is False, f"Should detect {name} as sensitive"

    def test_empty_env_vars_passes(self):
        """Test no finding when no env vars."""
        nodes = [
            Node(
                id="project-1",
                type="CodeBuildProject",
                properties={"environment_vars": []},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_codebuild_env_secrets(ctx)
        assert result.passed is True


class TestRuleEcrCrossAccount:
    """Tests for the ECR cross-account access rule."""

    def test_ecr_wildcard_principal_detected(self):
        """Test detecting ECR with wildcard principal."""
        nodes = [
            Node(
                id="arn:aws:ecr:us-east-1:123:repository/my-repo:policy",
                type="ResourcePolicy",
                properties={
                    "document": {
                        "Statement": [{"Effect": "Allow", "Principal": "*"}]
                    }
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_ecr_cross_account(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        # Wildcard should be HIGH severity
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_ecr_cross_account_principal_detected(self):
        """Test detecting ECR with cross-account principal."""
        nodes = [
            Node(
                id="arn:aws:ecr:us-east-1:123:repository/my-repo:policy",
                type="ResourcePolicy",
                properties={
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                            }
                        ]
                    }
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_ecr_cross_account(ctx)
        assert result.passed is False
        # Cross-account should be MEDIUM severity
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_same_account_passes(self):
        """Test no finding for same-account access."""
        nodes = [
            Node(
                id="arn:aws:ecr:us-east-1:123:repository/my-repo:policy",
                type="ResourcePolicy",
                properties={
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                            }
                        ]
                    }
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_ecr_cross_account(ctx)
        assert result.passed is True

    def test_ignores_non_ecr_policies(self):
        """Test that non-ECR policies are ignored."""
        nodes = [
            Node(
                id="arn:aws:s3:::bucket:policy",
                type="ResourcePolicy",
                properties={
                    "document": {"Statement": [{"Principal": "*"}]}
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_ecr_cross_account(ctx)
        assert result.passed is True
