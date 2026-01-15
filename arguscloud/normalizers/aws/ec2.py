"""AWS EC2 and VPC normalizers."""

from __future__ import annotations

from typing import Any, Dict, Iterable

from arguscloud.core.graph import CloudProvider, Edge, GraphData, Node
from arguscloud.core.registry import normalizers


@normalizers.normalizer(
    name="ec2",
    provider="aws",
    description="Normalize EC2 instances to graph",
    input_type="ec2",
)
def normalize_ec2(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert EC2 instances to nodes and edges."""
    graph = GraphData()

    for rec in records:
        inst = rec.get("Instance") or {}
        inst_id = inst.get("InstanceId")
        if not inst_id:
            continue

        # IMDS configuration
        metadata_opts = rec.get("MetadataOptions") or inst.get("MetadataOptions", {})
        imds_v2_required = metadata_opts.get("HttpTokens") == "required"

        graph.add_node(Node(
            id=inst_id,
            type="EC2Instance",
            properties={
                "state": (inst.get("State") or {}).get("Name"),
                "instance_type": inst.get("InstanceType"),
                "subnet_id": inst.get("SubnetId"),
                "vpc_id": inst.get("VpcId"),
                "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
                "public_ip": inst.get("PublicIpAddress"),
                "private_ip": inst.get("PrivateIpAddress"),
                "imds_v2_required": imds_v2_required,
                "platform": inst.get("Platform", "linux"),
                "launch_time": str(inst.get("LaunchTime", "")),
            },
            provider=CloudProvider.AWS,
        ))

        # Security group relationships
        for sg in inst.get("SecurityGroups", []):
            sg_id = sg.get("GroupId")
            if sg_id:
                graph.add_edge(Edge(
                    src=inst_id,
                    dst=sg_id,
                    type="MemberOfSecurityGroup",
                    properties={},
                    provider=CloudProvider.AWS,
                ))

        # Subnet relationship
        if inst.get("SubnetId"):
            graph.add_edge(Edge(
                src=inst_id,
                dst=inst["SubnetId"],
                type="InSubnet",
                properties={},
                provider=CloudProvider.AWS,
            ))

        # VPC relationship
        if inst.get("VpcId"):
            graph.add_edge(Edge(
                src=inst_id,
                dst=inst["VpcId"],
                type="InVPC",
                properties={},
                provider=CloudProvider.AWS,
            ))

        # IAM role relationship
        profile = (inst.get("IamInstanceProfile") or {}).get("Arn")
        if profile:
            graph.add_edge(Edge(
                src=inst_id,
                dst=profile,
                type="HasInstanceProfile",
                properties={},
                provider=CloudProvider.AWS,
            ))

    return graph


@normalizers.normalizer(
    name="ec2-images",
    provider="aws",
    description="Normalize EC2 snapshots and AMIs",
    input_type="ec2-images",
)
def normalize_ec2_images(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert EC2 snapshots and AMIs to nodes."""
    graph = GraphData()

    for rec in records:
        # Snapshots
        snap = rec.get("Snapshot")
        if snap:
            snap_id = snap.get("SnapshotId")
            if snap_id:
                # Check if shared publicly
                perms = rec.get("CreateVolumePermission", [])
                is_public = any(
                    p.get("Group") == "all" for p in perms
                )

                graph.add_node(Node(
                    id=snap_id,
                    type="Snapshot",
                    properties={
                        "volume_id": snap.get("VolumeId"),
                        "encrypted": snap.get("Encrypted"),
                        "state": snap.get("State"),
                        "size_gb": snap.get("VolumeSize"),
                        "is_public": is_public,
                    },
                    provider=CloudProvider.AWS,
                ))

        # AMIs
        ami = rec.get("AMI")
        if ami:
            ami_id = ami.get("ImageId")
            if ami_id:
                # Check launch permissions
                perms = rec.get("LaunchPermissions", [])
                is_public = any(
                    p.get("Group") == "all" for p in perms
                )

                graph.add_node(Node(
                    id=ami_id,
                    type="AMI",
                    properties={
                        "name": ami.get("Name"),
                        "state": ami.get("State"),
                        "public": ami.get("Public") or is_public,
                        "platform": ami.get("Platform"),
                        "architecture": ami.get("Architecture"),
                    },
                    provider=CloudProvider.AWS,
                ))

    return graph


@normalizers.normalizer(
    name="vpc",
    provider="aws",
    description="Normalize VPC networking resources",
    input_type="vpc",
)
def normalize_vpc(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert VPC resources to nodes and edges."""
    graph = GraphData()

    for rec in records:
        # VPCs
        if rec.get("Vpcs"):
            for vpc in rec["Vpcs"]:
                vpc_id = vpc.get("VpcId")
                if vpc_id:
                    graph.add_node(Node(
                        id=vpc_id,
                        type="VPC",
                        properties={
                            "cidr": vpc.get("CidrBlock"),
                            "is_default": vpc.get("IsDefault"),
                            "state": vpc.get("State"),
                        },
                        provider=CloudProvider.AWS,
                    ))

        # Subnets
        if rec.get("Subnets"):
            for subnet in rec["Subnets"]:
                subnet_id = subnet.get("SubnetId")
                if subnet_id:
                    graph.add_node(Node(
                        id=subnet_id,
                        type="Subnet",
                        properties={
                            "cidr": subnet.get("CidrBlock"),
                            "vpc_id": subnet.get("VpcId"),
                            "az": subnet.get("AvailabilityZone"),
                            "public_ip_on_launch": subnet.get("MapPublicIpOnLaunch"),
                        },
                        provider=CloudProvider.AWS,
                    ))
                    if subnet.get("VpcId"):
                        graph.add_edge(Edge(
                            src=subnet.get("VpcId"),
                            dst=subnet_id,
                            type="Contains",
                            properties={},
                            provider=CloudProvider.AWS,
                        ))

        # Security Groups
        if rec.get("SecurityGroups"):
            for sg in rec["SecurityGroups"]:
                sg_id = sg.get("GroupId")
                if sg_id:
                    # Check for open ingress
                    ingress = sg.get("IpPermissions", [])
                    has_open_ingress = any(
                        any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                        for rule in ingress
                    )

                    graph.add_node(Node(
                        id=sg_id,
                        type="SecurityGroup",
                        properties={
                            "name": sg.get("GroupName"),
                            "vpc_id": sg.get("VpcId"),
                            "description": sg.get("Description"),
                            "ingress": ingress,
                            "egress": sg.get("IpPermissionsEgress"),
                            "has_open_ingress": has_open_ingress,
                        },
                        provider=CloudProvider.AWS,
                    ))

        # Route Tables
        if rec.get("RouteTables"):
            for rt in rec["RouteTables"]:
                rt_id = rt.get("RouteTableId")
                if rt_id:
                    graph.add_node(Node(
                        id=rt_id,
                        type="RouteTable",
                        properties={
                            "vpc_id": rt.get("VpcId"),
                            "routes": rt.get("Routes"),
                        },
                        provider=CloudProvider.AWS,
                    ))

        # VPC Endpoints
        if rec.get("VpcEndpoints"):
            for ep in rec["VpcEndpoints"]:
                ep_id = ep.get("VpcEndpointId")
                if ep_id:
                    graph.add_node(Node(
                        id=ep_id,
                        type="VPCEndpoint",
                        properties={
                            "service": ep.get("ServiceName"),
                            "vpc_id": ep.get("VpcId"),
                            "state": ep.get("State"),
                            "type": ep.get("VpcEndpointType"),
                        },
                        provider=CloudProvider.AWS,
                    ))

        # VPC Peering
        if rec.get("VpcPeeringConnections"):
            for peer in rec["VpcPeeringConnections"]:
                peer_id = peer.get("VpcPeeringConnectionId")
                if peer_id:
                    requester = peer.get("RequesterVpcInfo", {})
                    accepter = peer.get("AccepterVpcInfo", {})
                    graph.add_node(Node(
                        id=peer_id,
                        type="VPCPeering",
                        properties={
                            "status": peer.get("Status", {}).get("Code"),
                            "requester_vpc": requester.get("VpcId"),
                            "requester_account": requester.get("OwnerId"),
                            "accepter_vpc": accepter.get("VpcId"),
                            "accepter_account": accepter.get("OwnerId"),
                        },
                        provider=CloudProvider.AWS,
                    ))

    return graph
