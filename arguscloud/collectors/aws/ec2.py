"""AWS EC2 and VPC collectors."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="ec2",
    provider="aws",
    description="Collect EC2 instances",
    services=["ec2"],
)
def collect_ec2_instances(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect all EC2 instances with their metadata."""
    ec2 = session.client("ec2")
    data: List[Dict[str, Any]] = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    record: Dict[str, Any] = {"Instance": instance}

                    # Check IMDS configuration
                    inst_id = instance.get("InstanceId")
                    if inst_id:
                        try:
                            metadata_options = instance.get("MetadataOptions", {})
                            record["MetadataOptions"] = metadata_options
                        except Exception:
                            pass

                    data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"describe_instances failed: {exc}")

    return "ec2", data


@collectors.collector(
    name="ec2-images",
    provider="aws",
    description="Collect EC2 snapshots and AMIs",
    services=["ec2"],
)
def collect_ec2_snapshots_images(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect EC2 snapshots and AMIs owned by the account."""
    ec2 = session.client("ec2")
    data: List[Dict[str, Any]] = []

    # Snapshots
    try:
        snaps = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
        for snap in snaps:
            record: Dict[str, Any] = {"Snapshot": snap}

            # Check snapshot attributes for sharing
            snap_id = snap.get("SnapshotId")
            if snap_id:
                try:
                    attrs = ec2.describe_snapshot_attribute(
                        SnapshotId=snap_id,
                        Attribute="createVolumePermission"
                    )
                    record["CreateVolumePermission"] = attrs.get("CreateVolumePermissions", [])
                except botocore.exceptions.ClientError:
                    pass

            data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_snapshots failed: {exc}")

    # AMIs
    try:
        images = ec2.describe_images(Owners=["self"]).get("Images", [])
        for image in images:
            record: Dict[str, Any] = {"AMI": image}

            # Check image launch permissions
            image_id = image.get("ImageId")
            if image_id:
                try:
                    attrs = ec2.describe_image_attribute(
                        ImageId=image_id,
                        Attribute="launchPermission"
                    )
                    record["LaunchPermissions"] = attrs.get("LaunchPermissions", [])
                except botocore.exceptions.ClientError:
                    pass

            data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_images failed: {exc}")

    return "ec2-images", data


@collectors.collector(
    name="vpc",
    provider="aws",
    description="Collect VPC, subnets, security groups, and networking",
    services=["ec2"],
)
def collect_vpc(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect VPC infrastructure: VPCs, subnets, security groups, route tables, endpoints."""
    ec2 = session.client("ec2")
    data: List[Dict[str, Any]] = []

    # VPCs
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        data.append({"Vpcs": vpcs})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_vpcs failed: {exc}")

    # Subnets
    try:
        subnets = ec2.describe_subnets().get("Subnets", [])
        data.append({"Subnets": subnets})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_subnets failed: {exc}")

    # Security Groups
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        data.append({"SecurityGroups": sgs})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_security_groups failed: {exc}")

    # Route Tables
    try:
        route_tables = ec2.describe_route_tables().get("RouteTables", [])
        data.append({"RouteTables": route_tables})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_route_tables failed: {exc}")

    # VPC Endpoints
    try:
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        data.append({"VpcEndpoints": endpoints})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_vpc_endpoints failed: {exc}")

    # NAT Gateways
    try:
        nat_gws = ec2.describe_nat_gateways().get("NatGateways", [])
        data.append({"NatGateways": nat_gws})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_nat_gateways failed: {exc}")

    # Internet Gateways
    try:
        igws = ec2.describe_internet_gateways().get("InternetGateways", [])
        data.append({"InternetGateways": igws})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_internet_gateways failed: {exc}")

    # Network ACLs
    try:
        nacls = ec2.describe_network_acls().get("NetworkAcls", [])
        data.append({"NetworkAcls": nacls})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_network_acls failed: {exc}")

    # VPC Peering Connections
    try:
        peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
        data.append({"VpcPeeringConnections": peerings})
    except botocore.exceptions.ClientError as exc:
        log.debug(f"describe_vpc_peering_connections failed: {exc}")

    return "vpc", data
