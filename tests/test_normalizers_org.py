"""Tests for arguscloud.normalizers.aws.org module (AWS Organizations)."""

import pytest
from arguscloud.normalizers.aws.org import normalize_organizations
from arguscloud.core.graph import CloudProvider


class TestNormalizeOrganizations:
    """Tests for AWS Organizations normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_organizations([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_organization_root(self):
        """Test normalizing organization root."""
        records = [
            {
                "Organization": {
                    "Id": "o-abcd1234",
                    "Arn": "arn:aws:organizations::123456789012:organization/o-abcd1234",
                    "MasterAccountArn": "arn:aws:organizations::123456789012:account/o-abcd1234/123456789012",
                    "MasterAccountId": "123456789012",
                    "MasterAccountEmail": "admin@example.com",
                    "FeatureSet": "ALL",
                }
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "org:o-abcd1234"
        assert node.type == "OrgRoot"
        assert node.properties["master_account_id"] == "123456789012"
        assert node.properties["master_account_email"] == "admin@example.com"
        assert node.properties["feature_set"] == "ALL"
        assert node.provider == CloudProvider.AWS

    def test_org_without_id_skipped(self):
        """Test that organization without ID is skipped."""
        records = [
            {
                "Organization": {
                    "Arn": "arn:aws:organizations::123456789012:organization/o-abcd1234",
                    "MasterAccountId": "123456789012",
                }
            }
        ]
        graph = normalize_organizations(records)
        org_nodes = [n for n in graph.nodes if n.type == "OrgRoot"]
        assert len(org_nodes) == 0

    def test_normalize_accounts(self):
        """Test normalizing organization accounts."""
        records = [
            {
                "Accounts": [
                    {
                        "Id": "111111111111",
                        "Arn": "arn:aws:organizations::123456789012:account/o-abcd1234/111111111111",
                        "Name": "Production",
                        "Email": "production@example.com",
                        "Status": "ACTIVE",
                        "JoinedTimestamp": "2024-01-01T00:00:00Z",
                    },
                    {
                        "Id": "222222222222",
                        "Arn": "arn:aws:organizations::123456789012:account/o-abcd1234/222222222222",
                        "Name": "Development",
                        "Email": "dev@example.com",
                        "Status": "ACTIVE",
                        "JoinedTimestamp": "2024-02-01T00:00:00Z",
                    },
                ]
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 2

        account_nodes = [n for n in graph.nodes if n.type == "Account"]
        assert len(account_nodes) == 2

        account_names = [n.properties["name"] for n in account_nodes]
        assert "Production" in account_names
        assert "Development" in account_names

    def test_account_without_id_skipped(self):
        """Test that account without ID is skipped."""
        records = [
            {
                "Accounts": [
                    {
                        "Name": "NoIdAccount",
                        "Email": "noid@example.com",
                    }
                ]
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 0

    def test_account_linked_to_org(self):
        """Test that accounts are linked to organization with Contains edge."""
        records = [
            {
                "Organization": {
                    "Id": "o-abcd1234",
                    "MasterAccountId": "123456789012",
                }
            },
            {
                "Accounts": [
                    {
                        "Id": "111111111111",
                        "Name": "Account1",
                    }
                ]
            },
        ]
        graph = normalize_organizations(records)

        org_nodes = [n for n in graph.nodes if n.type == "OrgRoot"]
        account_nodes = [n for n in graph.nodes if n.type == "Account"]
        assert len(org_nodes) == 1
        assert len(account_nodes) == 1

        contains_edges = [e for e in graph.edges if e.type == "Contains"]
        assert len(contains_edges) == 1
        assert contains_edges[0].src == "org:o-abcd1234"
        assert contains_edges[0].dst == "account:111111111111"
        assert contains_edges[0].properties["source"] == "organizations"

    def test_account_without_org_no_edge(self):
        """Test that accounts without organization have no Contains edge."""
        records = [
            {
                "Accounts": [
                    {
                        "Id": "111111111111",
                        "Name": "StandaloneAccount",
                    }
                ]
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 0

    def test_normalize_organizational_units(self):
        """Test normalizing organizational units."""
        records = [
            {
                "OrganizationalUnits": [
                    {
                        "Id": "ou-abcd-11111111",
                        "Arn": "arn:aws:organizations::123456789012:ou/o-abcd1234/ou-abcd-11111111",
                        "Name": "Production",
                    },
                    {
                        "Id": "ou-abcd-22222222",
                        "Arn": "arn:aws:organizations::123456789012:ou/o-abcd1234/ou-abcd-22222222",
                        "Name": "Development",
                    },
                ]
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 2

        ou_nodes = [n for n in graph.nodes if n.type == "OrganizationalUnit"]
        assert len(ou_nodes) == 2

        ou_names = [n.properties["name"] for n in ou_nodes]
        assert "Production" in ou_names
        assert "Development" in ou_names

    def test_ou_without_id_skipped(self):
        """Test that OU without ID is skipped."""
        records = [
            {
                "OrganizationalUnits": [
                    {
                        "Name": "NoIdOU",
                    }
                ]
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 0

    def test_normalize_service_control_policies(self):
        """Test normalizing service control policies."""
        records = [
            {
                "ServiceControlPolicies": [
                    {
                        "Id": "p-FullAWSAccess",
                        "Name": "FullAWSAccess",
                        "Description": "Allows access to every operation",
                        "AwsManaged": True,
                        "Content": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                        },
                    },
                    {
                        "Id": "p-DenyS3Public",
                        "Name": "DenyS3PublicAccess",
                        "Description": "Deny S3 public access",
                        "AwsManaged": False,
                        "Content": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Deny", "Action": "s3:PutBucketPublicAccessBlock", "Resource": "*"}],
                        },
                    },
                ]
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 2

        scp_nodes = [n for n in graph.nodes if n.type == "ServiceControlPolicy"]
        assert len(scp_nodes) == 2

        # Check AWS managed vs customer managed
        aws_managed = [n for n in scp_nodes if n.properties["aws_managed"] is True]
        customer_managed = [n for n in scp_nodes if n.properties["aws_managed"] is False]
        assert len(aws_managed) == 1
        assert len(customer_managed) == 1

    def test_scp_without_id_skipped(self):
        """Test that SCP without ID is skipped."""
        records = [
            {
                "ServiceControlPolicies": [
                    {
                        "Name": "NoIdSCP",
                        "Description": "SCP without ID",
                    }
                ]
            }
        ]
        graph = normalize_organizations(records)
        assert len(graph.nodes) == 0

    def test_scp_aws_managed_default(self):
        """Test that AwsManaged defaults to False."""
        records = [
            {
                "ServiceControlPolicies": [
                    {
                        "Id": "p-CustomPolicy",
                        "Name": "CustomPolicy",
                    }
                ]
            }
        ]
        graph = normalize_organizations(records)
        node = graph.nodes[0]
        assert node.properties["aws_managed"] is False

    def test_all_components(self):
        """Test normalizing organization with all components."""
        records = [
            {
                "Organization": {
                    "Id": "o-abcd1234",
                    "MasterAccountId": "123456789012",
                    "FeatureSet": "ALL",
                }
            },
            {
                "Accounts": [
                    {"Id": "111111111111", "Name": "Account1", "Status": "ACTIVE"},
                    {"Id": "222222222222", "Name": "Account2", "Status": "ACTIVE"},
                ]
            },
            {
                "OrganizationalUnits": [
                    {"Id": "ou-prod", "Name": "Production"},
                ]
            },
            {
                "ServiceControlPolicies": [
                    {"Id": "p-policy1", "Name": "Policy1"},
                ]
            },
        ]
        graph = normalize_organizations(records)

        org_nodes = [n for n in graph.nodes if n.type == "OrgRoot"]
        account_nodes = [n for n in graph.nodes if n.type == "Account"]
        ou_nodes = [n for n in graph.nodes if n.type == "OrganizationalUnit"]
        scp_nodes = [n for n in graph.nodes if n.type == "ServiceControlPolicy"]

        assert len(org_nodes) == 1
        assert len(account_nodes) == 2
        assert len(ou_nodes) == 1
        assert len(scp_nodes) == 1

        # Check Contains edges
        contains_edges = [e for e in graph.edges if e.type == "Contains"]
        assert len(contains_edges) == 2  # Two accounts linked to org

    def test_account_status_suspended(self):
        """Test account with suspended status."""
        records = [
            {
                "Accounts": [
                    {
                        "Id": "111111111111",
                        "Name": "SuspendedAccount",
                        "Status": "SUSPENDED",
                    }
                ]
            }
        ]
        graph = normalize_organizations(records)
        node = graph.nodes[0]
        assert node.properties["status"] == "SUSPENDED"

    def test_account_missing_joined_timestamp(self):
        """Test account with missing JoinedTimestamp."""
        records = [
            {
                "Accounts": [
                    {
                        "Id": "111111111111",
                        "Name": "Account",
                    }
                ]
            }
        ]
        graph = normalize_organizations(records)
        node = graph.nodes[0]
        assert node.properties["joined"] == ""

    def test_org_consolidated_billing_only(self):
        """Test organization with consolidated billing only feature set."""
        records = [
            {
                "Organization": {
                    "Id": "o-billing",
                    "FeatureSet": "CONSOLIDATED_BILLING",
                }
            }
        ]
        graph = normalize_organizations(records)
        node = graph.nodes[0]
        assert node.properties["feature_set"] == "CONSOLIDATED_BILLING"
