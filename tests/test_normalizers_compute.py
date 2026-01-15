"""Tests for arguscloud.normalizers.aws.compute module (Lambda, EKS, ECR)."""

import pytest
from arguscloud.normalizers.aws.compute import (
    normalize_lambda,
    normalize_eks,
    normalize_ecr,
)
from arguscloud.core.graph import CloudProvider


class TestNormalizeLambda:
    """Tests for Lambda function normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_lambda([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_lambda(self):
        """Test normalizing a basic Lambda function."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
                    "FunctionName": "my-function",
                    "Runtime": "python3.11",
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                    "Handler": "index.handler",
                    "MemorySize": 128,
                    "Timeout": 30,
                }
            }
        ]
        graph = normalize_lambda(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "arn:aws:lambda:us-east-1:123456789012:function:my-function"
        assert node.type == "LambdaFunction"
        assert node.properties["name"] == "my-function"
        assert node.properties["runtime"] == "python3.11"
        assert node.properties["handler"] == "index.handler"
        assert node.properties["memory_size"] == 128
        assert node.properties["timeout"] == 30
        assert node.properties["has_public_url"] is False
        assert node.provider == CloudProvider.AWS

    def test_lambda_with_public_url_none_auth(self):
        """Test Lambda with public URL and NONE auth type."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:public-fn",
                    "FunctionName": "public-fn",
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                },
                "FunctionUrlConfig": {
                    "FunctionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
                    "AuthType": "NONE",
                },
            }
        ]
        graph = normalize_lambda(records)
        node = graph.nodes[0]
        assert node.properties["has_public_url"] is True
        assert node.properties["url_auth_type"] == "NONE"

    def test_lambda_with_public_url_iam_auth(self):
        """Test Lambda with public URL and AWS_IAM auth type."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:iam-fn",
                    "FunctionName": "iam-fn",
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                },
                "FunctionUrlConfig": {
                    "FunctionUrl": "https://xyz789.lambda-url.us-east-1.on.aws/",
                    "AuthType": "AWS_IAM",
                },
            }
        ]
        graph = normalize_lambda(records)
        node = graph.nodes[0]
        assert node.properties["has_public_url"] is True
        assert node.properties["url_auth_type"] == "AWS_IAM"

    def test_lambda_role_edge_creation(self):
        """Test that Lambda creates edge to execution role."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn",
                    "FunctionName": "fn",
                    "Role": "arn:aws:iam::123456789012:role/lambda-exec-role",
                }
            }
        ]
        graph = normalize_lambda(records)
        role_edges = [e for e in graph.edges if e.type == "AssumesRole"]
        assert len(role_edges) == 1
        assert role_edges[0].src == "arn:aws:lambda:us-east-1:123456789012:function:fn"
        assert role_edges[0].dst == "arn:aws:iam::123456789012:role/lambda-exec-role"
        assert role_edges[0].properties["source"] == "lambda-execution-role"

    def test_lambda_without_role(self):
        """Test Lambda without execution role doesn't create edge."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn",
                    "FunctionName": "fn",
                }
            }
        ]
        graph = normalize_lambda(records)
        assert len(graph.edges) == 0

    def test_lambda_with_resource_policy(self):
        """Test Lambda with resource policy creates policy nodes and edges."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn",
                    "FunctionName": "fn",
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                },
                "Policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                            "Action": "lambda:InvokeFunction",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        graph = normalize_lambda(records)

        # Should have function node and policy node
        fn_nodes = [n for n in graph.nodes if n.type == "LambdaFunction"]
        policy_nodes = [n for n in graph.nodes if n.type == "ResourcePolicy"]
        assert len(fn_nodes) == 1
        assert len(policy_nodes) == 1

        # Check policy edges
        policy_edges = [e for e in graph.edges if e.type == "ResourcePolicy"]
        assert len(policy_edges) == 1
        assert policy_edges[0].src == "arn:aws:lambda:us-east-1:123456789012:function:fn"

        # Check principal edges
        principal_edges = [e for e in graph.edges if e.type == "PolicyPrincipal"]
        assert len(principal_edges) == 1
        assert principal_edges[0].dst == "arn:aws:iam::999999999999:root"

    def test_lambda_with_wildcard_principal_policy(self):
        """Test Lambda with wildcard principal in policy."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn",
                    "FunctionName": "fn",
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                },
                "Policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "lambda:InvokeFunction",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        graph = normalize_lambda(records)
        principal_edges = [e for e in graph.edges if e.type == "PolicyPrincipal"]
        assert len(principal_edges) == 1
        assert principal_edges[0].dst == "*"

    def test_lambda_without_arn_skipped(self):
        """Test that Lambda without ARN is skipped."""
        records = [
            {
                "Function": {
                    "FunctionName": "no-arn-function",
                    "Runtime": "python3.11",
                }
            }
        ]
        graph = normalize_lambda(records)
        assert len(graph.nodes) == 0

    def test_lambda_empty_function_dict(self):
        """Test Lambda with empty Function dict is skipped."""
        records = [{"Function": {}}]
        graph = normalize_lambda(records)
        assert len(graph.nodes) == 0

    def test_lambda_missing_function_key(self):
        """Test Lambda without Function key is skipped."""
        records = [{"SomeOtherKey": "value"}]
        graph = normalize_lambda(records)
        assert len(graph.nodes) == 0

    def test_multiple_lambda_functions(self):
        """Test normalizing multiple Lambda functions."""
        records = [
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn1",
                    "FunctionName": "fn1",
                    "Role": "arn:aws:iam::123456789012:role/role1",
                }
            },
            {
                "Function": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn2",
                    "FunctionName": "fn2",
                    "Role": "arn:aws:iam::123456789012:role/role2",
                }
            },
        ]
        graph = normalize_lambda(records)
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 2  # Two role edges


class TestNormalizeEKS:
    """Tests for EKS cluster normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_eks([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_eks_cluster(self):
        """Test normalizing a basic EKS cluster."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster",
                    "name": "my-cluster",
                    "version": "1.28",
                    "status": "ACTIVE",
                    "endpoint": "https://abc123.eks.us-east-1.amazonaws.com",
                    "roleArn": "arn:aws:iam::123456789012:role/eks-cluster-role",
                    "resourcesVpcConfig": {
                        "endpointPublicAccess": True,
                        "endpointPrivateAccess": True,
                        "securityGroupIds": ["sg-12345"],
                        "subnetIds": ["subnet-1", "subnet-2"],
                    },
                }
            }
        ]
        graph = normalize_eks(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster"
        assert node.type == "EKSCluster"
        assert node.properties["name"] == "my-cluster"
        assert node.properties["version"] == "1.28"
        assert node.properties["status"] == "ACTIVE"
        assert node.properties["public_access"] is True
        assert node.properties["private_access"] is True
        assert node.properties["security_groups"] == ["sg-12345"]
        assert node.properties["subnet_ids"] == ["subnet-1", "subnet-2"]
        assert node.provider == CloudProvider.AWS

    def test_eks_public_endpoint_only(self):
        """Test EKS with public endpoint only."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/public-cluster",
                    "name": "public-cluster",
                    "resourcesVpcConfig": {
                        "endpointPublicAccess": True,
                        "endpointPrivateAccess": False,
                    },
                }
            }
        ]
        graph = normalize_eks(records)
        node = graph.nodes[0]
        assert node.properties["public_access"] is True
        assert node.properties["private_access"] is False

    def test_eks_private_endpoint_only(self):
        """Test EKS with private endpoint only."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/private-cluster",
                    "name": "private-cluster",
                    "resourcesVpcConfig": {
                        "endpointPublicAccess": False,
                        "endpointPrivateAccess": True,
                    },
                }
            }
        ]
        graph = normalize_eks(records)
        node = graph.nodes[0]
        assert node.properties["public_access"] is False
        assert node.properties["private_access"] is True

    def test_eks_role_edge_creation(self):
        """Test that EKS creates edge to cluster service role."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster",
                    "name": "my-cluster",
                    "roleArn": "arn:aws:iam::123456789012:role/eks-service-role",
                    "resourcesVpcConfig": {},
                }
            }
        ]
        graph = normalize_eks(records)
        role_edges = [e for e in graph.edges if e.type == "AssumesRole"]
        assert len(role_edges) == 1
        assert role_edges[0].src == "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster"
        assert role_edges[0].dst == "arn:aws:iam::123456789012:role/eks-service-role"
        assert role_edges[0].properties["source"] == "eks-cluster-service-role"

    def test_eks_without_role(self):
        """Test EKS without role doesn't create edge."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster",
                    "name": "my-cluster",
                    "resourcesVpcConfig": {},
                }
            }
        ]
        graph = normalize_eks(records)
        assert len(graph.edges) == 0

    def test_eks_with_node_groups(self):
        """Test EKS with node groups creates node group nodes."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster",
                    "name": "my-cluster",
                    "resourcesVpcConfig": {},
                },
                "NodeGroups": ["ng-1", "ng-2", "ng-3"],
            }
        ]
        graph = normalize_eks(records)
        cluster_nodes = [n for n in graph.nodes if n.type == "EKSCluster"]
        ng_nodes = [n for n in graph.nodes if n.type == "EKSNodeGroup"]
        assert len(cluster_nodes) == 1
        assert len(ng_nodes) == 3

        # Check node group properties
        ng_names = [n.properties["name"] for n in ng_nodes]
        assert "ng-1" in ng_names
        assert "ng-2" in ng_names
        assert "ng-3" in ng_names

        # Check node group IDs
        ng_ids = [n.id for n in ng_nodes]
        assert "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster:nodegroup:ng-1" in ng_ids

    def test_eks_without_arn_skipped(self):
        """Test that EKS without ARN is skipped."""
        records = [
            {
                "Cluster": {
                    "name": "no-arn-cluster",
                    "version": "1.28",
                }
            }
        ]
        graph = normalize_eks(records)
        assert len(graph.nodes) == 0

    def test_eks_empty_cluster_dict(self):
        """Test EKS with empty Cluster dict is skipped."""
        records = [{"Cluster": {}}]
        graph = normalize_eks(records)
        assert len(graph.nodes) == 0

    def test_eks_missing_vpc_config(self):
        """Test EKS with missing VPC config uses defaults."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/minimal",
                    "name": "minimal",
                }
            }
        ]
        graph = normalize_eks(records)
        node = graph.nodes[0]
        assert node.properties["public_access"] is False
        assert node.properties["private_access"] is False
        assert node.properties["security_groups"] == []
        assert node.properties["subnet_ids"] == []

    def test_multiple_eks_clusters(self):
        """Test normalizing multiple EKS clusters."""
        records = [
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/cluster1",
                    "name": "cluster1",
                    "roleArn": "arn:aws:iam::123456789012:role/role1",
                    "resourcesVpcConfig": {},
                }
            },
            {
                "Cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/cluster2",
                    "name": "cluster2",
                    "roleArn": "arn:aws:iam::123456789012:role/role2",
                    "resourcesVpcConfig": {},
                }
            },
        ]
        graph = normalize_eks(records)
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 2


class TestNormalizeECR:
    """Tests for ECR repository normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_ecr([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_ecr_repository(self):
        """Test normalizing a basic ECR repository."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/my-repo",
                    "repositoryName": "my-repo",
                    "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
                    "imageScanningConfiguration": {"scanOnPush": True},
                    "encryptionConfiguration": {"encryptionType": "AES256"},
                }
            }
        ]
        graph = normalize_ecr(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "arn:aws:ecr:us-east-1:123456789012:repository/my-repo"
        assert node.type == "ECRRepository"
        assert node.properties["name"] == "my-repo"
        assert node.properties["uri"] == "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo"
        assert node.properties["scan_on_push"] is True
        assert node.properties["encryption_type"] == "AES256"
        assert node.provider == CloudProvider.AWS

    def test_ecr_scan_on_push_disabled(self):
        """Test ECR with scan on push disabled."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/no-scan",
                    "repositoryName": "no-scan",
                    "imageScanningConfiguration": {"scanOnPush": False},
                }
            }
        ]
        graph = normalize_ecr(records)
        node = graph.nodes[0]
        assert node.properties["scan_on_push"] is False

    def test_ecr_missing_scan_config(self):
        """Test ECR without scan configuration uses default."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/minimal",
                    "repositoryName": "minimal",
                }
            }
        ]
        graph = normalize_ecr(records)
        node = graph.nodes[0]
        assert node.properties["scan_on_push"] is False

    def test_ecr_kms_encryption(self):
        """Test ECR with KMS encryption."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/kms-repo",
                    "repositoryName": "kms-repo",
                    "encryptionConfiguration": {
                        "encryptionType": "KMS",
                        "kmsKey": "arn:aws:kms:us-east-1:123456789012:key/abcd1234",
                    },
                }
            }
        ]
        graph = normalize_ecr(records)
        node = graph.nodes[0]
        assert node.properties["encryption_type"] == "KMS"

    def test_ecr_with_resource_policy(self):
        """Test ECR with resource policy creates policy nodes and edges."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/my-repo",
                    "repositoryName": "my-repo",
                },
                "Policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                            "Action": "ecr:GetDownloadUrlForLayer",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        graph = normalize_ecr(records)

        # Should have repo node and policy node
        repo_nodes = [n for n in graph.nodes if n.type == "ECRRepository"]
        policy_nodes = [n for n in graph.nodes if n.type == "ResourcePolicy"]
        assert len(repo_nodes) == 1
        assert len(policy_nodes) == 1

        # Check policy edges
        policy_edges = [e for e in graph.edges if e.type == "ResourcePolicy"]
        assert len(policy_edges) == 1

        # Check principal edges
        principal_edges = [e for e in graph.edges if e.type == "PolicyPrincipal"]
        assert len(principal_edges) == 1
        assert principal_edges[0].dst == "arn:aws:iam::999999999999:root"

    def test_ecr_with_cross_account_policy(self):
        """Test ECR with cross-account access policy."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/shared",
                    "repositoryName": "shared",
                },
                "Policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": [
                                    "arn:aws:iam::111111111111:root",
                                    "arn:aws:iam::222222222222:root",
                                ]
                            },
                            "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],
                        }
                    ]
                },
            }
        ]
        graph = normalize_ecr(records)
        principal_edges = [e for e in graph.edges if e.type == "PolicyPrincipal"]
        assert len(principal_edges) == 2
        dsts = [e.dst for e in principal_edges]
        assert "arn:aws:iam::111111111111:root" in dsts
        assert "arn:aws:iam::222222222222:root" in dsts

    def test_ecr_with_public_policy(self):
        """Test ECR with public access policy (wildcard principal)."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/public",
                    "repositoryName": "public",
                },
                "Policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "ecr:GetDownloadUrlForLayer",
                        }
                    ]
                },
            }
        ]
        graph = normalize_ecr(records)
        principal_edges = [e for e in graph.edges if e.type == "PolicyPrincipal"]
        assert len(principal_edges) == 1
        assert principal_edges[0].dst == "*"

    def test_ecr_without_arn_skipped(self):
        """Test that ECR without ARN is skipped."""
        records = [
            {
                "Repository": {
                    "repositoryName": "no-arn-repo",
                }
            }
        ]
        graph = normalize_ecr(records)
        assert len(graph.nodes) == 0

    def test_ecr_empty_repository_dict(self):
        """Test ECR with empty Repository dict is skipped."""
        records = [{"Repository": {}}]
        graph = normalize_ecr(records)
        assert len(graph.nodes) == 0

    def test_ecr_missing_repository_key(self):
        """Test ECR without Repository key is skipped."""
        records = [{"SomeOtherKey": "value"}]
        graph = normalize_ecr(records)
        assert len(graph.nodes) == 0

    def test_multiple_ecr_repositories(self):
        """Test normalizing multiple ECR repositories."""
        records = [
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/repo1",
                    "repositoryName": "repo1",
                }
            },
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/repo2",
                    "repositoryName": "repo2",
                }
            },
            {
                "Repository": {
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/repo3",
                    "repositoryName": "repo3",
                }
            },
        ]
        graph = normalize_ecr(records)
        assert len(graph.nodes) == 3
