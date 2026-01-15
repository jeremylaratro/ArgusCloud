"""Tests for arguscloud.normalizers.aws.iam module."""

import pytest
from arguscloud.normalizers.aws.iam import (
    normalize_iam_roles,
    normalize_iam_users,
    normalize_iam_policies,
)
from arguscloud.core.graph import CloudProvider


class TestNormalizeIamRoles:
    """Tests for IAM role normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_iam_roles([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_role(self):
        """Test normalizing a basic role."""
        records = [
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/TestRole",
                    "RoleName": "TestRole",
                    "Description": "Test role",
                    "Path": "/",
                    "AssumeRolePolicyDocument": {},
                    "CreateDate": "2024-01-01T00:00:00Z",
                    "MaxSessionDuration": 3600,
                },
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_roles(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "arn:aws:iam::123456789012:role/TestRole"
        assert node.type == "Role"
        assert node.properties["name"] == "TestRole"
        assert node.provider == CloudProvider.AWS

    def test_normalize_role_with_trust_policy(self):
        """Test normalizing role with trust relationships."""
        records = [
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/TestRole",
                    "RoleName": "TestRole",
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                            }
                        ]
                    },
                },
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_roles(records)
        trust_edges = [e for e in graph.edges if e.type == "Trusts"]
        assert len(trust_edges) == 1
        assert trust_edges[0].src == "arn:aws:iam::123456789012:role/TestRole"
        assert trust_edges[0].dst == "arn:aws:iam::999999999999:root"

    def test_normalize_role_with_wildcard_trust(self):
        """Test normalizing role with wildcard trust."""
        records = [
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/PublicRole",
                    "RoleName": "PublicRole",
                    "AssumeRolePolicyDocument": {
                        "Statement": [{"Effect": "Allow", "Principal": "*"}]
                    },
                },
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_roles(records)
        trust_edges = [e for e in graph.edges if e.type == "Trusts"]
        assert len(trust_edges) == 1
        assert trust_edges[0].dst == "*"

    def test_normalize_role_with_attached_policies(self):
        """Test normalizing role with attached managed policies."""
        records = [
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/AdminRole",
                    "RoleName": "AdminRole",
                    "AssumeRolePolicyDocument": {},
                },
                "AttachedPolicies": [
                    {
                        "PolicyName": "AdministratorAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    }
                ],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_roles(records)
        role_node = [n for n in graph.nodes if n.type == "Role"][0]
        assert role_node.properties["is_admin"] is True

        policy_edges = [e for e in graph.edges if e.type == "AttachedPolicy"]
        assert len(policy_edges) == 1
        assert policy_edges[0].dst == "arn:aws:iam::aws:policy/AdministratorAccess"

    def test_normalize_role_with_inline_policy(self):
        """Test normalizing role with inline policies."""
        records = [
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/TestRole",
                    "RoleName": "TestRole",
                    "AssumeRolePolicyDocument": {},
                },
                "AttachedPolicies": [],
                "InlinePolicies": [
                    {
                        "PolicyName": "S3Access",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                ],
            }
        ]
        graph = normalize_iam_roles(records)
        inline_nodes = [n for n in graph.nodes if n.type == "InlinePolicy"]
        assert len(inline_nodes) == 1
        assert inline_nodes[0].properties["name"] == "S3Access"

        inline_edges = [e for e in graph.edges if e.type == "AttachedInlinePolicy"]
        assert len(inline_edges) == 1

    def test_normalize_role_with_admin_inline_policy(self):
        """Test detecting admin via inline policy."""
        records = [
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/AdminRole",
                    "RoleName": "AdminRole",
                    "AssumeRolePolicyDocument": {},
                },
                "AttachedPolicies": [],
                "InlinePolicies": [
                    {
                        "PolicyName": "FullAdmin",
                        "PolicyDocument": {
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ]
                        },
                    }
                ],
            }
        ]
        graph = normalize_iam_roles(records)
        role_node = [n for n in graph.nodes if n.type == "Role"][0]
        assert role_node.properties["is_admin"] is True

    def test_skip_record_without_arn(self):
        """Test that records without ARN are skipped."""
        records = [
            {"Role": {"RoleName": "NoArn"}, "AttachedPolicies": [], "InlinePolicies": []}
        ]
        graph = normalize_iam_roles(records)
        assert len(graph.nodes) == 0


class TestNormalizeIamUsers:
    """Tests for IAM user normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty user records."""
        graph = normalize_iam_users([])
        assert len(graph.nodes) == 0

    def test_normalize_basic_user(self):
        """Test normalizing a basic user."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                    "CreateDate": "2024-01-01T00:00:00Z",
                    "Path": "/",
                },
                "Groups": [],
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_users(records)
        assert len(graph.nodes) == 1
        user = graph.nodes[0]
        assert user.id == "arn:aws:iam::123456789012:user/alice"
        assert user.type == "User"
        assert user.properties["name"] == "alice"

    def test_normalize_user_with_console_access(self):
        """Test normalizing user with console access."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                },
                "LoginProfile": {"CreateDate": "2024-01-01"},
                "Groups": [],
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_users(records)
        user = graph.nodes[0]
        assert user.properties["has_console_access"] is True

    def test_normalize_user_with_mfa(self):
        """Test normalizing user with MFA enabled."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                },
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}],
                "Groups": [],
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_users(records)
        user = graph.nodes[0]
        assert user.properties["has_mfa"] is True

    def test_normalize_user_without_mfa(self):
        """Test normalizing user without MFA."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                },
                "MFADevices": [],
                "Groups": [],
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_users(records)
        user = graph.nodes[0]
        assert user.properties["has_mfa"] is False

    def test_normalize_user_with_access_keys(self):
        """Test normalizing user with access keys."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                },
                "AccessKeys": [
                    {"AccessKeyId": "AKIA1", "Status": "Active"},
                    {"AccessKeyId": "AKIA2", "Status": "Active"},
                    {"AccessKeyId": "AKIA3", "Status": "Inactive"},
                ],
                "Groups": [],
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_users(records)
        user = graph.nodes[0]
        assert user.properties["active_access_keys"] == 2

    def test_normalize_user_with_groups(self):
        """Test normalizing user group memberships."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                },
                "Groups": [
                    {
                        "Arn": "arn:aws:iam::123456789012:group/developers",
                        "GroupName": "developers",
                    }
                ],
                "AttachedPolicies": [],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_users(records)
        group_nodes = [n for n in graph.nodes if n.type == "Group"]
        assert len(group_nodes) == 1

        member_edges = [e for e in graph.edges if e.type == "MemberOf"]
        assert len(member_edges) == 1
        assert member_edges[0].dst == "arn:aws:iam::123456789012:group/developers"

    def test_normalize_user_with_attached_policies(self):
        """Test normalizing user with attached policies."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                },
                "Groups": [],
                "AttachedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                        "PolicyName": "ReadOnlyAccess",
                    }
                ],
                "InlinePolicies": [],
            }
        ]
        graph = normalize_iam_users(records)
        policy_edges = [e for e in graph.edges if e.type == "AttachedPolicy"]
        assert len(policy_edges) == 1

    def test_normalize_user_with_inline_policies(self):
        """Test normalizing user with inline policies."""
        records = [
            {
                "User": {
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "UserName": "alice",
                },
                "Groups": [],
                "AttachedPolicies": [],
                "InlinePolicies": [
                    {
                        "PolicyName": "CustomPolicy",
                        "PolicyDocument": {"Statement": []},
                    }
                ],
            }
        ]
        graph = normalize_iam_users(records)
        inline_nodes = [n for n in graph.nodes if n.type == "InlinePolicy"]
        assert len(inline_nodes) == 1

        inline_edges = [e for e in graph.edges if e.type == "AttachedInlinePolicy"]
        assert len(inline_edges) == 1


class TestNormalizeIamPolicies:
    """Tests for IAM managed policy normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty policy records."""
        graph = normalize_iam_policies([])
        assert len(graph.nodes) == 0

    def test_normalize_basic_policy(self):
        """Test normalizing a basic managed policy."""
        records = [
            {
                "Policy": {
                    "Arn": "arn:aws:iam::123456789012:policy/CustomPolicy",
                    "PolicyName": "CustomPolicy",
                    "Path": "/",
                    "Description": "Custom policy",
                    "CreateDate": "2024-01-01T00:00:00Z",
                    "UpdateDate": "2024-01-02T00:00:00Z",
                    "AttachmentCount": 5,
                },
                "DefaultVersionDocument": {
                    "PolicyVersion": {
                        "Document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ]
                        }
                    }
                },
            }
        ]
        graph = normalize_iam_policies(records)
        assert len(graph.nodes) == 1
        policy = graph.nodes[0]
        assert policy.type == "ManagedPolicy"
        assert policy.properties["name"] == "CustomPolicy"
        assert policy.properties["attachment_count"] == 5
        assert policy.properties["is_admin"] is False

    def test_normalize_admin_policy(self):
        """Test detecting admin managed policy."""
        records = [
            {
                "Policy": {
                    "Arn": "arn:aws:iam::123456789012:policy/AdminPolicy",
                    "PolicyName": "AdminPolicy",
                },
                "DefaultVersionDocument": {
                    "PolicyVersion": {
                        "Document": {
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ]
                        }
                    }
                },
            }
        ]
        graph = normalize_iam_policies(records)
        policy = graph.nodes[0]
        assert policy.properties["is_admin"] is True

    def test_normalize_policy_without_document(self):
        """Test normalizing policy without document."""
        records = [
            {
                "Policy": {
                    "Arn": "arn:aws:iam::123456789012:policy/NoDoc",
                    "PolicyName": "NoDoc",
                }
            }
        ]
        graph = normalize_iam_policies(records)
        policy = graph.nodes[0]
        assert policy.properties["document"] is None
        assert policy.properties["is_admin"] is False

    def test_skip_policy_without_arn(self):
        """Test that policies without ARN are skipped."""
        records = [{"Policy": {"PolicyName": "NoArn"}}]
        graph = normalize_iam_policies(records)
        assert len(graph.nodes) == 0
