from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Tuple

from .graph import Edge, Node


def normalize(raw: Dict[str, List[dict]]) -> Tuple[List[Node], List[Edge]]:
    """Convert raw service outputs into graph nodes and edges."""
    nodes: List[Node] = []
    edges: List[Edge] = []

    if "sts" in raw:
        nodes.extend(_normalize_sts(raw["sts"], edges))
    if "org" in raw:
        nodes.extend(_normalize_org(raw["org"], edges))
    if "iam" in raw:
        nodes.extend(_normalize_iam(raw["iam"], edges))
    if "iam-roles" in raw:
        nodes.extend(_normalize_iam_roles(raw["iam-roles"], edges))
    if "iam-users" in raw:
        nodes.extend(_normalize_iam_users(raw["iam-users"], edges))
    if "iam-policies" in raw:
        nodes.extend(_normalize_iam_policies(raw["iam-policies"], edges))
    if "cloudtrail" in raw:
        nodes.extend(_normalize_cloudtrail(raw["cloudtrail"], edges))
    if "guardduty" in raw:
        nodes.extend(_normalize_guardduty(raw["guardduty"], edges))
    if "s3" in raw:
        nodes.extend(_normalize_s3(raw["s3"], edges))
    if "kms" in raw:
        nodes.extend(_normalize_kms(raw["kms"], edges))
    if "vpc" in raw:
        nodes.extend(_normalize_vpc(raw["vpc"], edges))
    if "ec2" in raw:
        nodes.extend(_normalize_ec2(raw["ec2"], edges))
    if "ec2-images" in raw:
        nodes.extend(_normalize_ec2_images(raw["ec2-images"], edges))
    if "eks" in raw:
        nodes.extend(_normalize_eks(raw["eks"], edges))
    if "ecr" in raw:
        nodes.extend(_normalize_ecr(raw["ecr"], edges))
    if "lambda" in raw:
        nodes.extend(_normalize_lambda(raw["lambda"], edges))
    if "cloudformation" in raw:
        nodes.extend(_normalize_cloudformation(raw["cloudformation"], edges))
    if "codebuild" in raw:
        nodes.extend(_normalize_codebuild(raw["codebuild"], edges))
    if "secretsmanager" in raw:
        nodes.extend(_normalize_secrets(raw["secretsmanager"], edges))
    if "ssm-parameters" in raw:
        nodes.extend(_normalize_ssm_parameters(raw["ssm-parameters"], edges))
    if "sns" in raw:
        nodes.extend(_normalize_sns(raw["sns"], edges))
    if "sqs" in raw:
        nodes.extend(_normalize_sqs(raw["sqs"], edges))
    if "securityhub" in raw:
        nodes.extend(_normalize_securityhub(raw["securityhub"], edges))
    if "detective" in raw:
        nodes.extend(_normalize_detective(raw["detective"], edges))
    if "config" in raw:
        nodes.extend(_normalize_config(raw["config"], edges))
    if "sso" in raw:
        nodes.extend(_normalize_sso(raw["sso"], edges))
    if "rds" in raw:
        nodes.extend(_normalize_rds(raw["rds"], edges))
    if "codepipeline" in raw:
        nodes.extend(_normalize_codepipeline(raw["codepipeline"], edges))
    if "cloudwatch" in raw:
        nodes.extend(_normalize_cloudwatch(raw["cloudwatch"], edges))
    if "waf" in raw:
        nodes.extend(_normalize_waf(raw["waf"], edges))
    if "shield" in raw:
        nodes.extend(_normalize_shield(raw["shield"], edges))
    if "fms" in raw:
        nodes.extend(_normalize_fms(raw["fms"], edges))

    nodes, edges = _dedupe(nodes, edges)
    return nodes, edges


def _normalize_sts(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        arn = rec.get("Arn")
        if not arn:
            continue
        nodes.append(
            Node(
                id=arn,
                type="Principal",
                properties={
                    "arn": arn,
                    "account": rec.get("Account"),
                    "user_id": rec.get("UserId"),
                    "source": "sts:get-caller-identity",
                },
            )
        )
    return nodes


def _extract_principals(doc: Dict[str, Any]) -> List[str]:
    principals: List[str] = []
    stmts = doc.get("Statement") or []
    if not isinstance(stmts, list):
        stmts = [stmts]
    for stmt in stmts:
        principal = stmt.get("Principal")
        if principal == "*":
            principals.append("*")
        elif isinstance(principal, dict):
            for _, val in principal.items():
                if isinstance(val, list):
                    principals.extend(val)
                else:
                    principals.append(val)
        elif principal:
            principals.append(principal)
    return principals


def _is_admin_policy(doc: Dict[str, Any]) -> bool:
    """Heuristic: policy has Allow * on *."""
    stmts = doc.get("Statement") or []
    if not isinstance(stmts, list):
        stmts = [stmts]
    for stmt in stmts:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action")
        resources = stmt.get("Resource")
        if actions == "*" or (isinstance(actions, list) and "*" in actions):
            if resources == "*" or (isinstance(resources, list) and "*" in resources):
                return True
    return False


def _normalize_iam_roles(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        role = rec.get("Role") or {}
        arn = role.get("Arn")
        if not arn:
            continue
        node_id = arn
        is_admin = False
        principals = _extract_principals(role.get("AssumeRolePolicyDocument") or {})
        for principal in principals:
            edges.append(
                Edge(
                    src=node_id,
                    dst=principal,
                    type="Trusts",
                    properties={"source": "iam:AssumeRolePolicyDocument"},
                )
            )
        for pol in rec.get("AttachedPolicies", []):
            if pol.get("PolicyArn"):
                if pol.get("PolicyName") == "AdministratorAccess":
                    is_admin = True
                edges.append(
                    Edge(
                        src=node_id,
                        dst=pol["PolicyArn"],
                        type="AttachedPolicy",
                        properties={"policy_name": pol.get("PolicyName")},
                    )
                )
        for pol in rec.get("InlinePolicies", []):
            pol_name = pol.get("PolicyName")
            if not pol_name:
                continue
            if _is_admin_policy(pol.get("PolicyDocument") or {}):
                is_admin = True
            inline_id = f"{node_id}:inline:{pol_name}"
            nodes.append(
                Node(
                    id=inline_id,
                    type="InlinePolicy",
                    properties={
                        "name": pol_name,
                        "document": pol.get("PolicyDocument"),
                        "parent": node_id,
                    },
                )
            )
            edges.append(
                Edge(
                    src=node_id,
                    dst=inline_id,
                    type="AttachedInlinePolicy",
                    properties={},
                )
            )
        nodes.append(
            Node(
                id=node_id,
                type="Role",
                properties={
                    "role_name": role.get("RoleName"),
                    "description": role.get("Description"),
                    "create_date": role.get("CreateDate"),
                    "assume_role_policy": role.get("AssumeRolePolicyDocument"),
                    "is_admin": is_admin,
                },
            )
        )
    return nodes


def _normalize_iam_users(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        user = rec.get("User") or {}
        arn = user.get("Arn")
        if not arn:
            continue
        node_id = arn
        nodes.append(
            Node(
                id=node_id,
                type="User",
                properties={
                    "user_name": user.get("UserName"),
                    "create_date": user.get("CreateDate"),
                },
            )
        )
        for grp in rec.get("Groups", []):
            if grp.get("Arn"):
                grp_id = grp["Arn"]
                nodes.append(
                    Node(
                        id=grp_id,
                        type="Group",
                        properties={"group_name": grp.get("GroupName")},
                    )
                )
                edges.append(
                    Edge(
                        src=node_id,
                        dst=grp_id,
                        type="MemberOf",
                        properties={},
                    )
                )
        for pol in rec.get("AttachedPolicies", []):
            if pol.get("PolicyArn"):
                edges.append(
                    Edge(
                        src=node_id,
                        dst=pol["PolicyArn"],
                        type="AttachedPolicy",
                        properties={"policy_name": pol.get("PolicyName")},
                    )
                )
        for pol in rec.get("InlinePolicies", []):
            pol_name = pol.get("PolicyName")
            if not pol_name:
                continue
            inline_id = f"{node_id}:inline:{pol_name}"
            nodes.append(
                Node(
                    id=inline_id,
                    type="InlinePolicy",
                    properties={
                        "name": pol_name,
                        "document": pol.get("PolicyDocument"),
                        "parent": node_id,
                    },
                )
            )
            edges.append(
                Edge(
                    src=node_id,
                    dst=inline_id,
                    type="AttachedInlinePolicy",
                    properties={},
                )
            )
    return nodes


def _normalize_iam_policies(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        pol = rec.get("Policy") or {}
        arn = pol.get("Arn")
        if not arn:
            continue
        nodes.append(
            Node(
                id=arn,
                type="ManagedPolicy",
                properties={
                    "name": pol.get("PolicyName"),
                    "path": pol.get("Path"),
                    "create_date": pol.get("CreateDate"),
                    "update_date": pol.get("UpdateDate"),
                    "description": pol.get("Description"),
                    "document": (rec.get("DefaultVersionDocument") or {}).get("PolicyVersion", {}).get("Document"),
                },
            )
        )
    return nodes


def _normalize_cloudtrail(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        if rec.get("Trails"):
            for trail in rec["Trails"]:
                name = trail.get("Name")
                if not name:
                    continue
                node_id = f"cloudtrail:{name}"
                nodes.append(
                    Node(
                        id=node_id,
                        type="CloudTrailTrail",
                        properties={
                            "name": name,
                            "home_region": trail.get("HomeRegion"),
                            "is_multi_region": trail.get("IsMultiRegionTrail"),
                            "s3_bucket": trail.get("S3BucketName"),
                        },
                    )
                )
        if rec.get("TrailStatus"):
            name = rec.get("Name")
            status = rec["TrailStatus"]
            node_id = f"cloudtrail:{name}"
            nodes.append(
                Node(
                    id=node_id,
                    type="CloudTrailTrail",
                    properties={
                        "name": name,
                        "is_logging": status.get("IsLogging"),
                        "latest_delivery_time": status.get("LatestDeliveryTime"),
                    },
                )
            )
    return nodes


def _normalize_guardduty(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        det_id = rec.get("Detector")
        info = rec.get("Info") or {}
        if not det_id:
            continue
        nodes.append(
            Node(
                id=f"guardduty:{det_id}",
                type="GuardDutyDetector",
                properties={
                    "status": info.get("Status"),
                    "finding_publishing_frequency": info.get("FindingPublishingFrequency"),
                    "data_sources": info.get("DataSources"),
                    "tags": info.get("Tags"),
                },
            )
        )
    return nodes


def _dedupe(nodes: List[Node], edges: List[Edge]) -> Tuple[List[Node], List[Edge]]:
    """Remove duplicate nodes/edges to keep bundle size manageable."""
    node_map: Dict[str, Node] = {}
    for n in nodes:
        node_map.setdefault(n.id, n)
    edge_keys = set()
    dedup_edges: List[Edge] = []
    for e in edges:
        key = (e.src, e.dst, e.type, json.dumps(e.properties, sort_keys=True))
        if key in edge_keys:
            continue
        edge_keys.add(key)
        dedup_edges.append(e)
    return list(node_map.values()), dedup_edges


def _normalize_s3(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        bucket = rec.get("Bucket") or {}
        name = bucket.get("Name")
        if not name:
            continue
        node_id = f"arn:aws:s3:::{name}"
        nodes.append(
            Node(
                id=node_id,
                type="S3Bucket",
                properties={
                    "name": name,
                    "creation_date": bucket.get("CreationDate"),
                    "policy_status": (rec.get("PolicyStatus") or {}).get("PolicyStatus"),
                    "acl": rec.get("Acl"),
                },
            )
        )
        policy = rec.get("Policy")
        if policy:
            nodes.append(
                Node(
                    id=f"{node_id}:policy",
                    type="ResourcePolicy",
                    properties={"document": policy},
                )
            )
            edges.append(
                Edge(
                    src=node_id,
                    dst=f"{node_id}:policy",
                    type="ResourcePolicy",
                    properties={},
                )
            )
            principals = _extract_principals(policy)
            for principal in principals:
                edges.append(
                    Edge(
                        src=f"{node_id}:policy",
                        dst=principal,
                        type="PolicyPrincipal",
                        properties={},
                    )
                )
    return nodes


def _normalize_kms(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        key = rec.get("Key") or {}
        meta = (rec.get("Metadata") or {}).get("KeyMetadata", {})
        key_id = key.get("KeyId") or meta.get("Arn")
        if not key_id:
            continue
        node_id = meta.get("Arn") or f"kms:{key_id}"
        nodes.append(
            Node(
                id=node_id,
                type="KMSKey",
                properties={
                    "key_id": key_id,
                    "description": meta.get("Description"),
                    "enabled": meta.get("Enabled"),
                    "key_state": meta.get("KeyState"),
                    "key_usage": meta.get("KeyUsage"),
                    "creation_date": meta.get("CreationDate"),
                },
            )
        )
        policy = rec.get("Policy")
        if policy:
            pol_id = f"{node_id}:policy"
            nodes.append(
                Node(
                    id=pol_id,
                    type="ResourcePolicy",
                    properties={"document": policy},
                )
            )
            edges.append(Edge(src=node_id, dst=pol_id, type="ResourcePolicy", properties={}))
            principals = _extract_principals(policy)
            for principal in principals:
                edges.append(
                    Edge(
                        src=pol_id,
                        dst=principal,
                        type="PolicyPrincipal",
                        properties={},
                    )
                )
    return nodes


def _normalize_vpc(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        if rec.get("Vpcs"):
            for vpc in rec["Vpcs"]:
                vpc_id = vpc.get("VpcId")
                if not vpc_id:
                    continue
                nodes.append(
                    Node(
                        id=vpc_id,
                        type="VPC",
                        properties={"cidr": vpc.get("CidrBlock"), "is_default": vpc.get("IsDefault")},
                    )
                )
        if rec.get("Subnets"):
            for sn in rec["Subnets"]:
                sn_id = sn.get("SubnetId")
                if not sn_id:
                    continue
                nodes.append(
                    Node(
                        id=sn_id,
                        type="Subnet",
                        properties={"cidr": sn.get("CidrBlock"), "vpc_id": sn.get("VpcId"), "az": sn.get("AvailabilityZone")},
                    )
                )
                if sn.get("VpcId"):
                    edges.append(Edge(src=sn.get("VpcId"), dst=sn_id, type="Contains", properties={"source": "vpc"}))
        if rec.get("SecurityGroups"):
            for sg in rec["SecurityGroups"]:
                sg_id = sg.get("GroupId")
                if not sg_id:
                    continue
                nodes.append(
                    Node(
                        id=sg_id,
                        type="SecurityGroup",
                        properties={"name": sg.get("GroupName"), "vpc_id": sg.get("VpcId"), "ingress": sg.get("IpPermissions"), "egress": sg.get("IpPermissionsEgress")},
                    )
                )
        if rec.get("RouteTables"):
            for rt in rec["RouteTables"]:
                rt_id = rt.get("RouteTableId")
                if not rt_id:
                    continue
                nodes.append(
                    Node(
                        id=rt_id,
                        type="RouteTable",
                        properties={"vpc_id": rt.get("VpcId"), "routes": rt.get("Routes")},
                    )
                )
        if rec.get("VpcEndpoints"):
            for ep in rec["VpcEndpoints"]:
                ep_id = ep.get("VpcEndpointId")
                if not ep_id:
                    continue
                nodes.append(
                    Node(
                        id=ep_id,
                        type="VPCEndpoint",
                        properties={"service": ep.get("ServiceName"), "vpc_id": ep.get("VpcId"), "state": ep.get("State")},
                    )
                )
    return nodes


def _normalize_ec2(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        inst = rec.get("Instance") or {}
        inst_id = inst.get("InstanceId")
        if not inst_id:
            continue
        nodes.append(
            Node(
                id=inst_id,
                type="EC2Instance",
                properties={
                    "state": (inst.get("State") or {}).get("Name"),
                    "type": inst.get("InstanceType"),
                    "subnet_id": inst.get("SubnetId"),
                    "vpc_id": inst.get("VpcId"),
                    "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                },
            )
        )
        for sg in inst.get("SecurityGroups", []):
            if sg.get("GroupId"):
                edges.append(Edge(src=inst_id, dst=sg["GroupId"], type="MemberOfSecurityGroup", properties={}))
        if inst.get("SubnetId"):
            edges.append(Edge(src=inst_id, dst=inst["SubnetId"], type="InSubnet", properties={}))
        if inst.get("VpcId"):
            edges.append(Edge(src=inst_id, dst=inst["VpcId"], type="InVPC", properties={}))
    return nodes


def _normalize_ec2_images(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        for snap in rec.get("Snapshots", []) or []:
            sid = snap.get("SnapshotId")
            if not sid:
                continue
            nodes.append(
                Node(
                    id=sid,
                    type="Snapshot",
                    properties={"volume_id": snap.get("VolumeId"), "encrypted": snap.get("Encrypted"), "state": snap.get("State")},
                )
            )
        for img in rec.get("Images", []) or []:
            ami = img.get("ImageId")
            if not ami:
                continue
            nodes.append(
                Node(
                    id=ami,
                    type="AMI",
                    properties={"name": img.get("Name"), "public": img.get("Public"), "state": img.get("State")},
                )
            )
    return nodes


def _normalize_eks(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        cluster = rec.get("Cluster") or {}
        name = cluster.get("name")
        arn = cluster.get("arn")
        if not arn:
            continue
        nodes.append(
            Node(
                id=arn,
                type="EKSCluster",
                properties={
                    "name": name,
                    "endpoint": cluster.get("endpoint"),
                    "version": cluster.get("version"),
                    "role_arn": cluster.get("roleArn"),
                    "vpc_config": cluster.get("resourcesVpcConfig"),
                },
            )
        )
        role_arn = cluster.get("roleArn")
        if role_arn:
            edges.append(Edge(src=arn, dst=role_arn, type="AssumesRole", properties={"source": "eks-cluster-service-role"}))
    return nodes


def _normalize_ecr(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        repo = rec.get("Repository") or {}
        arn = repo.get("repositoryArn")
        if not arn:
            continue
        nodes.append(
            Node(
                id=arn,
                type="ECRRepository",
                properties={
                    "name": repo.get("repositoryName"),
                    "uri": repo.get("repositoryUri"),
                    "scan_on_push": (repo.get("imageScanningConfiguration") or {}).get("scanOnPush"),
                },
            )
        )
        pol = rec.get("Policy")
        if pol:
            pol_id = f"{arn}:policy"
            nodes.append(Node(id=pol_id, type="ResourcePolicy", properties={"document": pol}))
            edges.append(Edge(src=arn, dst=pol_id, type="ResourcePolicy", properties={}))
            for principal in _extract_principals(pol):
                edges.append(Edge(src=pol_id, dst=principal, type="PolicyPrincipal", properties={}))
    return nodes


def _normalize_lambda(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        fn = rec.get("Function") or {}
        arn = fn.get("FunctionArn")
        if not arn:
            continue
        nodes.append(
            Node(
                id=arn,
                type="LambdaFunction",
                properties={
                    "name": fn.get("FunctionName"),
                    "runtime": fn.get("Runtime"),
                    "role": fn.get("Role"),
                },
            )
        )
        if fn.get("Role"):
            edges.append(Edge(src=arn, dst=fn["Role"], type="AssumesRole", properties={"source": "lambda-execution-role"}))
        pol = rec.get("Policy")
        if pol:
            pol_id = f"{arn}:policy"
            nodes.append(Node(id=pol_id, type="ResourcePolicy", properties={"document": pol}))
            edges.append(Edge(src=arn, dst=pol_id, type="ResourcePolicy", properties={}))
            for principal in _extract_principals(pol):
                edges.append(Edge(src=pol_id, dst=principal, type="PolicyPrincipal", properties={}))
    return nodes


def _normalize_cloudformation(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        stack = rec.get("Stack") or {}
        stack_id = stack.get("StackId") or stack.get("StackName")
        if not stack_id:
            continue
        nodes.append(
            Node(
                id=stack_id,
                type="CloudFormationStack",
                properties={
                    "name": stack.get("StackName"),
                    "status": stack.get("StackStatus"),
                    "creation_time": stack.get("CreationTime"),
                },
            )
        )
    return nodes


def _normalize_codebuild(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        proj = rec.get("Project") or {}
        arn = proj.get("arn")
        if not arn:
            continue
        nodes.append(
            Node(
                id=arn,
                type="CodeBuildProject",
                properties={
                    "name": proj.get("name"),
                    "service_role": proj.get("serviceRole"),
                    "source_type": (proj.get("source") or {}).get("type"),
                    "artifacts_type": (proj.get("artifacts") or {}).get("type"),
                    "environment_privileged": (proj.get("environment") or {}).get("privilegedMode"),
                    "environment_vars": (proj.get("environment") or {}).get("environmentVariables"),
                },
            )
        )
        if proj.get("serviceRole"):
            edges.append(Edge(src=arn, dst=proj["serviceRole"], type="AssumesRole", properties={"source": "codebuild-service-role"}))
    return nodes


def _normalize_secrets(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        sec = rec.get("Secret") or {}
        arn = sec.get("ARN")
        if not arn:
            continue
        nodes.append(
            Node(
                id=arn,
                type="Secret",
                properties={
                    "name": sec.get("Name"),
                    "kms_key_id": sec.get("KmsKeyId"),
                    "rotation_enabled": sec.get("RotationEnabled"),
                },
            )
        )
        pol = rec.get("Policy")
        if pol:
            pol_id = f"{arn}:policy"
            nodes.append(Node(id=pol_id, type="ResourcePolicy", properties={"document": pol}))
            edges.append(Edge(src=arn, dst=pol_id, type="ResourcePolicy", properties={}))
            for principal in _extract_principals(pol):
                edges.append(Edge(src=pol_id, dst=principal, type="PolicyPrincipal", properties={}))
    return nodes


def _normalize_ssm_parameters(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        param = rec.get("Parameter") or {}
        name = param.get("Name")
        if not name:
            continue
        nodes.append(
            Node(
                id=f"ssm:{name}",
                type="SSMParameter",
                properties={
                    "name": name,
                    "type": param.get("Type"),
                    "tier": param.get("Tier"),
                    "key_id": param.get("KeyId"),
                },
            )
        )
    return nodes


def _normalize_sns(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        topic = rec.get("Topic") or {}
        arn = topic.get("TopicArn")
        if not arn:
            continue
        nodes.append(Node(id=arn, type="SNSTopic", properties={"arn": arn}))
        attrs = rec.get("Attributes") or {}
        pol = attrs.get("Policy")
        if pol:
            try:
                pol_doc = json.loads(pol)
            except Exception:
                pol_doc = {}
            pol_id = f"{arn}:policy"
            nodes.append(Node(id=pol_id, type="ResourcePolicy", properties={"document": pol_doc}))
            edges.append(Edge(src=arn, dst=pol_id, type="ResourcePolicy", properties={}))
            for principal in _extract_principals(pol_doc):
                edges.append(Edge(src=pol_id, dst=principal, type="PolicyPrincipal", properties={}))
    return nodes


def _normalize_sqs(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        url = rec.get("QueueUrl")
        if not url:
            continue
        nodes.append(Node(id=url, type="SQSQueue", properties={"url": url}))
        attrs = rec.get("Attributes") or {}
        pol = attrs.get("Policy")
        if pol:
            try:
                pol_doc = json.loads(pol)
            except Exception:
                pol_doc = {}
            pol_id = f"{url}:policy"
            nodes.append(Node(id=pol_id, type="ResourcePolicy", properties={"document": pol_doc}))
            edges.append(Edge(src=url, dst=pol_id, type="ResourcePolicy", properties={}))
            for principal in _extract_principals(pol_doc):
                edges.append(Edge(src=pol_id, dst=principal, type="PolicyPrincipal", properties={}))
    return nodes


def _normalize_securityhub(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        if rec.get("Hub"):
            hub = rec["Hub"]
            hub_arn = hub.get("HubArn")
            if hub_arn:
                nodes.append(Node(id=hub_arn, type="SecurityHub", properties={"status": hub.get("HubArn") is not None}))
        if rec.get("Findings"):
            for finding in rec["Findings"]:
                fid = finding.get("Id")
                if not fid:
                    continue
                nodes.append(
                    Node(
                        id=fid,
                        type="SecurityFinding",
                        properties={
                            "title": finding.get("Title"),
                            "severity": (finding.get("Severity") or {}).get("Label"),
                            "product": finding.get("ProductArn"),
                        },
                    )
                )
    return nodes


def _normalize_detective(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        for graph in rec.get("Graphs", []):
            gid = graph.get("Arn")
            if not gid:
                continue
            nodes.append(Node(id=gid, type="DetectiveGraph", properties={"creation_time": graph.get("CreatedTime")}))
    return nodes


def _normalize_config(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        if rec.get("Recorders"):
            for recorder in rec["Recorders"]:
                name = recorder.get("name")
                if not name:
                    continue
                nodes.append(
                    Node(
                        id=f"config-recorder:{name}",
                        type="ConfigRecorder",
                        properties={
                            "role_arn": recorder.get("roleARN"),
                            "resource_types": recorder.get("recordingGroup", {}).get("resourceTypes"),
                        },
                    )
                )
        if rec.get("RecorderStatus"):
            for status in rec["RecorderStatus"]:
                name = status.get("name")
                if not name:
                    continue
                nodes.append(
                    Node(
                        id=f"config-recorder:{name}",
                        type="ConfigRecorder",
                        properties={
                            "recording": status.get("recording"),
                            "last_status": status.get("lastStatus"),
                        },
                    )
                )
    return nodes


def _normalize_sso(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        if rec.get("Instances"):
            for inst in rec["Instances"]:
                arn = inst.get("InstanceArn")
                if not arn:
                    continue
                nodes.append(Node(id=arn, type="SSOInstance", properties={"identity_store_id": inst.get("IdentityStoreId")}))
        if rec.get("PermissionSets"):
            inst_arn = rec.get("InstanceArn")
            for ps in rec["PermissionSets"]:
                nodes.append(Node(id=ps, type="PermissionSet", properties={"instance": inst_arn}))
        if rec.get("PermissionSet"):
            ps = rec["PermissionSet"]
            ps_arn = ps.get("PermissionSetArn")
            if ps_arn:
                nodes.append(
                    Node(
                        id=ps_arn,
                        type="PermissionSet",
                        properties={
                            "name": ps.get("Name"),
                            "relay_state": ps.get("RelayState"),
                            "session_duration": ps.get("SessionDuration"),
                        },
                    )
                )
        if rec.get("Users"):
            for user in rec["Users"]:
                uid = user.get("UserId") or user.get("UserName")
                if not uid:
                    continue
                nodes.append(Node(id=f"sso-user:{uid}", type="SSOUser", properties={"user_name": user.get("UserName")}))
    return nodes


def _normalize_rds(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        snap = rec.get("Snapshot") or {}
        attrs = rec.get("Attributes") or {}
        sid = snap.get("DBSnapshotIdentifier")
        if not sid:
            continue
        public = False
        for attr in attrs.get("DBSnapshotAttributes", []):
            if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                public = True
        nodes.append(
            Node(
                id=sid,
                type="RDSSnapshot",
                properties={
                    "db_instance": snap.get("DBInstanceIdentifier"),
                    "public": public,
                    "encrypted": snap.get("Encrypted"),
                    "engine": snap.get("Engine"),
                },
            )
        )
    return nodes


def _normalize_codepipeline(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        pipe = rec.get("Pipeline") or {}
        name = pipe.get("name")
        if not name:
            continue
        nodes.append(
            Node(
                id=f"codepipeline:{name}",
                type="CodePipeline",
                properties={
                    "name": name,
                    "role_arn": pipe.get("roleArn"),
                    "artifact_store": (pipe.get("artifactStore") or {}).get("location"),
                },
            )
        )
        if pipe.get("roleArn"):
            edges.append(Edge(src=f"codepipeline:{name}", dst=pipe["roleArn"], type="AssumesRole", properties={"source": "codepipeline-role"}))
    return nodes


def _normalize_cloudwatch(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        for lg in rec.get("LogGroups", []) or []:
            name = lg.get("logGroupName")
            if not name:
                continue
            nodes.append(
                Node(
                    id=f"loggroup:{name}",
                    type="LogGroup",
                    properties={"retention": lg.get("retentionInDays"), "kms_key_id": lg.get("kmsKeyId")},
                )
            )
    return nodes


def _normalize_waf(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        scope = rec.get("Scope")
        for acl in rec.get("WebACLs", []) or []:
            acl_arn = acl.get("ARN")
            if not acl_arn:
                continue
            nodes.append(Node(id=acl_arn, type="WebACL", properties={"name": acl.get("Name"), "scope": scope}))
    return nodes


def _normalize_shield(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        sub = rec.get("Subscription") or {}
        if sub:
            nodes.append(Node(id="shield:subscription", type="ShieldSubscription", properties=sub))
    return nodes


def _normalize_fms(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    for rec in records:
        admin = rec.get("Admin") or {}
        if admin.get("AdminAccount"):
            nodes.append(Node(id=f"fms-admin:{admin['AdminAccount']}", type="FMSAdmin", properties=admin))
    return nodes


def _normalize_org(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    nodes: List[Node] = []
    org_root_id = None
    accounts = []
    for rec in records:
        if "Organization" in rec:
            org = rec["Organization"]
            org_root_id = org.get("Id")
            if org_root_id:
                nodes.append(
                    Node(
                        id=f"org:{org_root_id}",
                        type="OrgRoot",
                        properties={
                            "master_account_arn": org.get("MasterAccountArn"),
                            "master_account_id": org.get("MasterAccountId"),
                            "feature_set": org.get("FeatureSet"),
                            "arn": org.get("Arn"),
                        },
                    )
                )
        if "Accounts" in rec:
            accounts = rec.get("Accounts", [])
    if accounts:
        for acct in accounts:
            acct_id = acct.get("Id")
            if not acct_id:
                continue
            node_id = f"account:{acct_id}"
            nodes.append(
                Node(
                    id=node_id,
                    type="Account",
                    properties={
                        "name": acct.get("Name"),
                        "email": acct.get("Email"),
                        "status": acct.get("Status"),
                        "joined": acct.get("JoinedTimestamp"),
                        "arn": acct.get("Arn"),
                    },
                )
            )
            if org_root_id:
                edges.append(
                    Edge(
                        src=f"org:{org_root_id}",
                        dst=node_id,
                        type="Contains",
                        properties={"source": "organizations"},
                    )
                )
    return nodes


def _normalize_iam(records: Iterable[dict], edges: List[Edge]) -> List[Node]:
    # Current collector only adds account summary; turn it into a node.
    nodes: List[Node] = []
    for rec in records:
        summary = rec.get("SummaryMap") or rec.get("AccountSummary") or {}
        if not summary:
            continue
        nodes.append(
            Node(
                id="iam:account-summary",
                type="IAMSummary",
                properties=summary,
            )
        )
    return nodes
