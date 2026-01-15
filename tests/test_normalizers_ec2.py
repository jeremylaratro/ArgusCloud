"""Tests for arguscloud.normalizers.aws.ec2 module."""

import pytest
from arguscloud.normalizers.aws.ec2 import (
    normalize_ec2,
    normalize_ec2_images,
    normalize_vpc,
)
from arguscloud.core.graph import CloudProvider


class TestNormalizeEC2:
    """Tests for EC2 instance normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_ec2([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_instance(self):
        """Test normalizing a basic EC2 instance."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-1234567890abcdef0",
                    "InstanceType": "t2.micro",
                    "State": {"Name": "running"},
                    "SubnetId": "subnet-123",
                    "VpcId": "vpc-123",
                    "Platform": "linux",
                    "LaunchTime": "2024-01-01T00:00:00Z",
                }
            }
        ]
        graph = normalize_ec2(records)
        assert len(graph.nodes) == 1
        instance = graph.nodes[0]
        assert instance.id == "i-1234567890abcdef0"
        assert instance.type == "EC2Instance"
        assert instance.properties["instance_type"] == "t2.micro"
        assert instance.properties["state"] == "running"
        assert instance.provider == CloudProvider.AWS

    def test_normalize_instance_with_public_ip(self):
        """Test normalizing instance with public IP."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-public",
                    "PublicIpAddress": "1.2.3.4",
                    "PrivateIpAddress": "10.0.0.5",
                }
            }
        ]
        graph = normalize_ec2(records)
        instance = graph.nodes[0]
        assert instance.properties["public_ip"] == "1.2.3.4"
        assert instance.properties["private_ip"] == "10.0.0.5"

    def test_normalize_instance_with_iam_role(self):
        """Test normalizing instance with IAM instance profile."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-with-role",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::123:instance-profile/MyProfile"
                    },
                }
            }
        ]
        graph = normalize_ec2(records)
        instance = graph.nodes[0]
        assert instance.properties["iam_instance_profile"] == "arn:aws:iam::123:instance-profile/MyProfile"

        profile_edges = [e for e in graph.edges if e.type == "HasInstanceProfile"]
        assert len(profile_edges) == 1
        assert profile_edges[0].dst == "arn:aws:iam::123:instance-profile/MyProfile"

    def test_normalize_instance_imds_v2_required(self):
        """Test normalizing instance with IMDSv2 required."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-imdsv2",
                },
                "MetadataOptions": {"HttpTokens": "required"},
            }
        ]
        graph = normalize_ec2(records)
        instance = graph.nodes[0]
        assert instance.properties["imds_v2_required"] is True

    def test_normalize_instance_imds_optional(self):
        """Test normalizing instance with IMDSv1 allowed."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-imdsv1",
                    "MetadataOptions": {"HttpTokens": "optional"},
                }
            }
        ]
        graph = normalize_ec2(records)
        instance = graph.nodes[0]
        assert instance.properties["imds_v2_required"] is False

    def test_normalize_instance_with_security_groups(self):
        """Test normalizing instance security group relationships."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-with-sg",
                    "SecurityGroups": [
                        {"GroupId": "sg-123", "GroupName": "web"},
                        {"GroupId": "sg-456", "GroupName": "db"},
                    ],
                }
            }
        ]
        graph = normalize_ec2(records)
        sg_edges = [e for e in graph.edges if e.type == "MemberOfSecurityGroup"]
        assert len(sg_edges) == 2
        sg_ids = [e.dst for e in sg_edges]
        assert "sg-123" in sg_ids
        assert "sg-456" in sg_ids

    def test_normalize_instance_subnet_edge(self):
        """Test normalizing instance subnet relationship."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-subnet",
                    "SubnetId": "subnet-123",
                }
            }
        ]
        graph = normalize_ec2(records)
        subnet_edges = [e for e in graph.edges if e.type == "InSubnet"]
        assert len(subnet_edges) == 1
        assert subnet_edges[0].dst == "subnet-123"

    def test_normalize_instance_vpc_edge(self):
        """Test normalizing instance VPC relationship."""
        records = [
            {
                "Instance": {
                    "InstanceId": "i-vpc",
                    "VpcId": "vpc-123",
                }
            }
        ]
        graph = normalize_ec2(records)
        vpc_edges = [e for e in graph.edges if e.type == "InVPC"]
        assert len(vpc_edges) == 1
        assert vpc_edges[0].dst == "vpc-123"

    def test_skip_instance_without_id(self):
        """Test that instances without ID are skipped."""
        records = [{"Instance": {"InstanceType": "t2.micro"}}]
        graph = normalize_ec2(records)
        assert len(graph.nodes) == 0


class TestNormalizeEC2Images:
    """Tests for EC2 snapshot and AMI normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_ec2_images([])
        assert len(graph.nodes) == 0

    def test_normalize_snapshot(self):
        """Test normalizing an EC2 snapshot."""
        records = [
            {
                "Snapshot": {
                    "SnapshotId": "snap-123",
                    "VolumeId": "vol-123",
                    "Encrypted": True,
                    "State": "completed",
                    "VolumeSize": 100,
                }
            }
        ]
        graph = normalize_ec2_images(records)
        assert len(graph.nodes) == 1
        snap = graph.nodes[0]
        assert snap.id == "snap-123"
        assert snap.type == "Snapshot"
        assert snap.properties["encrypted"] is True
        assert snap.properties["size_gb"] == 100

    def test_normalize_public_snapshot(self):
        """Test normalizing a public snapshot."""
        records = [
            {
                "Snapshot": {"SnapshotId": "snap-public"},
                "CreateVolumePermission": [{"Group": "all"}],
            }
        ]
        graph = normalize_ec2_images(records)
        snap = graph.nodes[0]
        assert snap.properties["is_public"] is True

    def test_normalize_private_snapshot(self):
        """Test normalizing a private snapshot."""
        records = [
            {
                "Snapshot": {"SnapshotId": "snap-private"},
                "CreateVolumePermission": [
                    {"UserId": "123456789012"}
                ],
            }
        ]
        graph = normalize_ec2_images(records)
        snap = graph.nodes[0]
        assert snap.properties["is_public"] is False

    def test_normalize_ami(self):
        """Test normalizing an AMI."""
        records = [
            {
                "AMI": {
                    "ImageId": "ami-123",
                    "Name": "my-ami",
                    "State": "available",
                    "Platform": "linux",
                    "Architecture": "x86_64",
                    "Public": False,
                }
            }
        ]
        graph = normalize_ec2_images(records)
        assert len(graph.nodes) == 1
        ami = graph.nodes[0]
        assert ami.id == "ami-123"
        assert ami.type == "AMI"
        assert ami.properties["name"] == "my-ami"
        assert ami.properties["public"] is False

    def test_normalize_public_ami_via_permissions(self):
        """Test normalizing AMI made public via launch permissions."""
        records = [
            {
                "AMI": {
                    "ImageId": "ami-public",
                    "Public": False,
                },
                "LaunchPermissions": [{"Group": "all"}],
            }
        ]
        graph = normalize_ec2_images(records)
        ami = graph.nodes[0]
        assert ami.properties["public"] is True

    def test_normalize_mixed_records(self):
        """Test normalizing records with both snapshots and AMIs."""
        records = [
            {"Snapshot": {"SnapshotId": "snap-1"}},
            {"AMI": {"ImageId": "ami-1"}},
            {"Snapshot": {"SnapshotId": "snap-2"}},
        ]
        graph = normalize_ec2_images(records)
        assert len(graph.nodes) == 3
        types = [n.type for n in graph.nodes]
        assert types.count("Snapshot") == 2
        assert types.count("AMI") == 1


class TestNormalizeVPC:
    """Tests for VPC resource normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_vpc([])
        assert len(graph.nodes) == 0

    def test_normalize_vpc(self):
        """Test normalizing a VPC."""
        records = [
            {
                "Vpcs": [
                    {
                        "VpcId": "vpc-123",
                        "CidrBlock": "10.0.0.0/16",
                        "IsDefault": False,
                        "State": "available",
                    }
                ]
            }
        ]
        graph = normalize_vpc(records)
        assert len(graph.nodes) == 1
        vpc = graph.nodes[0]
        assert vpc.id == "vpc-123"
        assert vpc.type == "VPC"
        assert vpc.properties["cidr"] == "10.0.0.0/16"

    def test_normalize_subnets(self):
        """Test normalizing subnets."""
        records = [
            {
                "Subnets": [
                    {
                        "SubnetId": "subnet-123",
                        "VpcId": "vpc-123",
                        "CidrBlock": "10.0.1.0/24",
                        "AvailabilityZone": "us-east-1a",
                        "MapPublicIpOnLaunch": True,
                    }
                ]
            }
        ]
        graph = normalize_vpc(records)
        subnet_nodes = [n for n in graph.nodes if n.type == "Subnet"]
        assert len(subnet_nodes) == 1
        subnet = subnet_nodes[0]
        assert subnet.properties["az"] == "us-east-1a"
        assert subnet.properties["public_ip_on_launch"] is True

        # Check VPC -> Subnet edge
        contains_edges = [e for e in graph.edges if e.type == "Contains"]
        assert len(contains_edges) == 1
        assert contains_edges[0].src == "vpc-123"
        assert contains_edges[0].dst == "subnet-123"

    def test_normalize_security_group(self):
        """Test normalizing a security group."""
        records = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123",
                        "GroupName": "web-sg",
                        "VpcId": "vpc-123",
                        "Description": "Web security group",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 80,
                                "ToPort": 80,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ]
        graph = normalize_vpc(records)
        sg_nodes = [n for n in graph.nodes if n.type == "SecurityGroup"]
        assert len(sg_nodes) == 1
        sg = sg_nodes[0]
        assert sg.properties["name"] == "web-sg"
        assert sg.properties["has_open_ingress"] is True

    def test_normalize_security_group_no_open_ingress(self):
        """Test security group without open ingress."""
        records = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-private",
                        "GroupName": "private-sg",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                            }
                        ],
                    }
                ]
            }
        ]
        graph = normalize_vpc(records)
        sg = graph.nodes[0]
        assert sg.properties["has_open_ingress"] is False

    def test_normalize_route_table(self):
        """Test normalizing a route table."""
        records = [
            {
                "RouteTables": [
                    {
                        "RouteTableId": "rtb-123",
                        "VpcId": "vpc-123",
                        "Routes": [
                            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}
                        ],
                    }
                ]
            }
        ]
        graph = normalize_vpc(records)
        rt_nodes = [n for n in graph.nodes if n.type == "RouteTable"]
        assert len(rt_nodes) == 1
        rt = rt_nodes[0]
        assert rt.id == "rtb-123"

    def test_normalize_vpc_endpoint(self):
        """Test normalizing a VPC endpoint."""
        records = [
            {
                "VpcEndpoints": [
                    {
                        "VpcEndpointId": "vpce-123",
                        "ServiceName": "com.amazonaws.us-east-1.s3",
                        "VpcId": "vpc-123",
                        "State": "available",
                        "VpcEndpointType": "Gateway",
                    }
                ]
            }
        ]
        graph = normalize_vpc(records)
        ep_nodes = [n for n in graph.nodes if n.type == "VPCEndpoint"]
        assert len(ep_nodes) == 1
        ep = ep_nodes[0]
        assert ep.properties["service"] == "com.amazonaws.us-east-1.s3"
        assert ep.properties["type"] == "Gateway"

    def test_normalize_vpc_peering(self):
        """Test normalizing a VPC peering connection."""
        records = [
            {
                "VpcPeeringConnections": [
                    {
                        "VpcPeeringConnectionId": "pcx-123",
                        "Status": {"Code": "active"},
                        "RequesterVpcInfo": {
                            "VpcId": "vpc-111",
                            "OwnerId": "111111111111",
                        },
                        "AccepterVpcInfo": {
                            "VpcId": "vpc-222",
                            "OwnerId": "222222222222",
                        },
                    }
                ]
            }
        ]
        graph = normalize_vpc(records)
        peer_nodes = [n for n in graph.nodes if n.type == "VPCPeering"]
        assert len(peer_nodes) == 1
        peer = peer_nodes[0]
        assert peer.properties["status"] == "active"
        assert peer.properties["requester_vpc"] == "vpc-111"
        assert peer.properties["accepter_vpc"] == "vpc-222"

    def test_normalize_all_vpc_resources(self):
        """Test normalizing a record with all VPC resource types."""
        records = [
            {
                "Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
                "Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}],
                "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "test"}],
                "RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1"}],
                "VpcEndpoints": [{"VpcEndpointId": "vpce-1", "VpcId": "vpc-1"}],
            }
        ]
        graph = normalize_vpc(records)
        types = [n.type for n in graph.nodes]
        assert "VPC" in types
        assert "Subnet" in types
        assert "SecurityGroup" in types
        assert "RouteTable" in types
        assert "VPCEndpoint" in types
