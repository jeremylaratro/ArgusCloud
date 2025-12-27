from __future__ import annotations

import json
import logging
from typing import Callable, Dict, Iterable, List, Tuple

import botocore

from .manifest import Manifest
from .modes import RunMode

log = logging.getLogger(__name__)


CollectorFn = Callable[[object], Tuple[str, Iterable[dict]]]


def collect_services(session, services: List[str], manifest: Manifest, mode: RunMode) -> Dict[str, List[dict]]:
    """Run enabled collectors and accumulate raw records keyed by service."""
    outputs: Dict[str, List[dict]] = {}
    for svc in services:
        collector = SERVICE_COLLECTORS.get(svc)
        if collector is None:
            manifest.add_service(svc, status="skipped", detail="collector-not-implemented")
            continue
        try:
            detail, records_iter = collector(session)
            records = list(records_iter)
            outputs[svc] = records
            manifest.add_service(svc, status="ok", detail=detail, collected_resources=len(records))
        except botocore.exceptions.ClientError as exc:
            log.warning("Collector %s failed: %s", svc, exc)
            manifest.add_service(svc, status="error", detail=str(exc))
        except Exception as exc:  # pragma: no cover - safety catch
            log.exception("Collector %s crashed", svc)
            manifest.add_service(svc, status="error", detail=str(exc))
    return outputs


def _collect_sts_identity(session):
    sts = session.client("sts")
    resp = sts.get_caller_identity()
    return "sts-get-caller-identity", [resp]


def _collect_org(session):
    org = session.client("organizations")
    data = []
    try:
        data.append(org.describe_organization())
    except org.exceptions.AWSOrganizationsNotInUseException:
        return "not-in-org", data
    roots = org.list_roots().get("Roots", [])
    data.extend({"Roots": roots})
    accounts = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        accounts.extend(page.get("Accounts", []))
    data.append({"Accounts": accounts})
    return "organization", data


def _collect_iam_summary(session):
    iam = session.client("iam")
    summary = iam.get_account_summary()
    return "iam-summary", [summary]


def _collect_iam_roles(session):
    iam = session.client("iam")
    data: List[dict] = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            record = {"Role": role}
            # Attached managed policies
            attached = iam.list_attached_role_policies(RoleName=role["RoleName"]).get("AttachedPolicies", [])
            record["AttachedPolicies"] = attached
            # Inline policies (names only)
            inline = iam.list_role_policies(RoleName=role["RoleName"]).get("PolicyNames", [])
            record["InlinePolicyNames"] = inline
            # Fetch inline policy documents
            inline_policies = []
            for name in inline:
                try:
                    pol = iam.get_role_policy(RoleName=role["RoleName"], PolicyName=name)
                    inline_policies.append(pol)
                except botocore.exceptions.ClientError as exc:
                    log.debug("get_role_policy failed for %s/%s: %s", role["RoleName"], name, exc)
            record["InlinePolicies"] = inline_policies
            data.append(record)
    return "iam-roles", data


def _collect_iam_users(session):
    iam = session.client("iam")
    data: List[dict] = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            record = {"User": user}
            attached = iam.list_attached_user_policies(UserName=user["UserName"]).get("AttachedPolicies", [])
            record["AttachedPolicies"] = attached
            groups = iam.list_groups_for_user(UserName=user["UserName"]).get("Groups", [])
            record["Groups"] = groups
            inline = iam.list_user_policies(UserName=user["UserName"]).get("PolicyNames", [])
            record["InlinePolicyNames"] = inline
            inline_policies = []
            for name in inline:
                try:
                    pol = iam.get_user_policy(UserName=user["UserName"], PolicyName=name)
                    inline_policies.append(pol)
                except botocore.exceptions.ClientError as exc:
                    log.debug("get_user_policy failed for %s/%s: %s", user["UserName"], name, exc)
            record["InlinePolicies"] = inline_policies
            data.append(record)
    return "iam-users", data


def _collect_iam_policies(session):
    iam = session.client("iam")
    data: List[dict] = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local", OnlyAttached=False):
        for pol in page.get("Policies", []):
            record = {"Policy": pol}
            default_version = pol.get("DefaultVersionId")
            if default_version:
                try:
                    version = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=default_version)
                    record["DefaultVersionDocument"] = version
                except botocore.exceptions.ClientError as exc:
                    log.debug("get_policy_version failed for %s: %s", pol["Arn"], exc)
            data.append(record)
    return "iam-policies", data


def _collect_cloudtrail(session):
    ct = session.client("cloudtrail")
    data: List[dict] = []
    trails = ct.list_trails().get("Trails", [])
    if trails:
        names = [t["Name"] for t in trails if "Name" in t]
        describe = ct.describe_trails(trailNameList=names) if names else {"trailList": []}
        data.append({"Trails": describe.get("trailList", [])})
        for name in names:
            try:
                status = ct.get_trail_status(Name=name)
                data.append({"TrailStatus": status, "Name": name})
            except botocore.exceptions.ClientError as exc:
                log.debug("get_trail_status failed for %s: %s", name, exc)
    return "cloudtrail", data


def _collect_guardduty(session):
    gd = session.client("guardduty")
    data: List[dict] = []
    detectors = gd.list_detectors().get("DetectorIds", [])
    for det in detectors:
        try:
            info = gd.get_detector(DetectorId=det)
            data.append({"Detector": det, "Info": info})
        except botocore.exceptions.ClientError as exc:
            log.debug("get_detector failed for %s: %s", det, exc)
    return "guardduty", data


def _collect_s3(session):
    s3 = session.client("s3")
    data: List[dict] = []
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b.get("Name")
        record = {"Bucket": b}
        if not name:
            continue
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            record["Acl"] = acl
        except botocore.exceptions.ClientError as exc:
            log.debug("get_bucket_acl failed for %s: %s", name, exc)
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            record["PolicyStatus"] = policy_status
        except botocore.exceptions.ClientError:
            pass
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            record["Policy"] = json.loads(policy.get("Policy", "{}"))
        except botocore.exceptions.ClientError:
            pass
        data.append(record)
    return "s3", data


def _collect_kms(session):
    kms = session.client("kms")
    data: List[dict] = []
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page.get("Keys", []):
            key_id = key.get("KeyId")
            if not key_id:
                continue
            record = {"Key": key}
            try:
                info = kms.describe_key(KeyId=key_id)
                record["Metadata"] = info
            except botocore.exceptions.ClientError as exc:
                log.debug("describe_key failed for %s: %s", key_id, exc)
            try:
                pol = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                record["Policy"] = json.loads(pol.get("Policy", "{}"))
            except botocore.exceptions.ClientError:
                pass
            data.append(record)
    return "kms", data


def _collect_vpc(session):
    ec2 = session.client("ec2")
    data: List[dict] = []
    data.append({"Vpcs": ec2.describe_vpcs().get("Vpcs", [])})
    data.append({"Subnets": ec2.describe_subnets().get("Subnets", [])})
    data.append({"SecurityGroups": ec2.describe_security_groups().get("SecurityGroups", [])})
    data.append({"RouteTables": ec2.describe_route_tables().get("RouteTables", [])})
    data.append({"VpcEndpoints": ec2.describe_vpc_endpoints().get("VpcEndpoints", [])})
    return "vpc", data


def _collect_ec2(session):
    ec2 = session.client("ec2")
    data: List[dict] = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                data.append({"Instance": inst})
    return "ec2", data


def _collect_ec2_snapshots_images(session):
    ec2 = session.client("ec2")
    data: List[dict] = []
    try:
        snaps = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
        data.append({"Snapshots": snaps})
    except botocore.exceptions.ClientError:
        pass
    try:
        images = ec2.describe_images(Owners=["self"]).get("Images", [])
        data.append({"Images": images})
    except botocore.exceptions.ClientError:
        pass
    return "ec2-images", data


def _collect_eks(session):
    eks = session.client("eks")
    data: List[dict] = []
    clusters = eks.list_clusters().get("clusters", [])
    for name in clusters:
        try:
            desc = eks.describe_cluster(name=name).get("cluster", {})
            data.append({"Cluster": desc})
        except botocore.exceptions.ClientError as exc:
            log.debug("describe_cluster failed for %s: %s", name, exc)
    return "eks", data


def _collect_ecr(session):
    ecr = session.client("ecr")
    data: List[dict] = []
    repos = ecr.describe_repositories().get("repositories", [])
    for repo in repos:
        record = {"Repository": repo}
        try:
            pol = ecr.get_repository_policy(repositoryName=repo["repositoryName"])
            record["Policy"] = json.loads(pol.get("policyText", "{}"))
        except botocore.exceptions.ClientError:
            pass
        data.append(record)
    return "ecr", data


def _collect_lambda(session):
    lam = session.client("lambda")
    data: List[dict] = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            record = {"Function": fn}
            try:
                pol = lam.get_policy(FunctionName=fn["FunctionName"])
                record["Policy"] = json.loads(pol.get("Policy", "{}"))
            except botocore.exceptions.ClientError:
                pass
            data.append(record)
    return "lambda", data


def _collect_cloudformation(session):
    cfn = session.client("cloudformation")
    data: List[dict] = []
    stacks = cfn.list_stacks(StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"]).get("StackSummaries", [])
    for st in stacks:
        data.append({"Stack": st})
    return "cloudformation", data


def _collect_codebuild(session):
    cb = session.client("codebuild")
    data: List[dict] = []
    projects = cb.list_projects().get("projects", [])
    if projects:
        details = cb.batch_get_projects(names=projects).get("projects", [])
        for proj in details:
            data.append({"Project": proj})
    return "codebuild", data


def _collect_secretsmanager(session):
    sm = session.client("secretsmanager")
    data: List[dict] = []
    paginator = sm.get_paginator("list_secrets")
    for page in paginator.paginate():
        for sec in page.get("SecretList", []):
            record = {"Secret": sec}
            arn = sec.get("ARN")
            if arn:
                try:
                    pol = sm.get_resource_policy(SecretId=arn)
                    record["Policy"] = json.loads(pol.get("ResourcePolicy", "{}"))
                except botocore.exceptions.ClientError:
                    pass
            data.append(record)
    return "secretsmanager", data


def _collect_ssm_parameters(session):
    ssm = session.client("ssm")
    data: List[dict] = []
    paginator = ssm.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            data.append({"Parameter": param})
    return "ssm-parameters", data


def _collect_sns(session):
    sns = session.client("sns")
    data: List[dict] = []
    topics = sns.list_topics().get("Topics", [])
    for t in topics:
        arn = t.get("TopicArn")
        record = {"Topic": t}
        if arn:
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn)
                record["Attributes"] = attrs.get("Attributes", {})
            except botocore.exceptions.ClientError:
                pass
        data.append(record)
    return "sns", data


def _collect_sqs(session):
    sqs = session.client("sqs")
    data: List[dict] = []
    queues = sqs.list_queues().get("QueueUrls", []) or []
    for q in queues:
        record = {"QueueUrl": q}
        try:
            attrs = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["All"])
            record["Attributes"] = attrs.get("Attributes", {})
        except botocore.exceptions.ClientError:
            pass
        data.append(record)
    return "sqs", data


def _collect_securityhub(session):
    sh = session.client("securityhub")
    data: List[dict] = []
    try:
        hub = sh.describe_hub()
        data.append({"Hub": hub})
    except botocore.exceptions.ClientError:
        pass
    try:
        findings = sh.get_findings(MaxResults=50)
        data.append({"Findings": findings.get("Findings", [])})
    except botocore.exceptions.ClientError:
        pass
    return "securityhub", data


def _collect_detective(session):
    det = session.client("detective")
    data: List[dict] = []
    try:
        graphs = det.list_graphs().get("GraphList", [])
        data.append({"Graphs": graphs})
    except botocore.exceptions.ClientError:
        pass
    return "detective", data


def _collect_config(session):
    cfg = session.client("config")
    data: List[dict] = []
    try:
        rec = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        data.append({"Recorders": rec})
        status = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        data.append({"RecorderStatus": status})
    except botocore.exceptions.ClientError:
        pass
    return "config", data


def _collect_sso(session):
    sso_admin = session.client("sso-admin")
    identity = session.client("identitystore")
    data: List[dict] = []
    try:
        instances = sso_admin.list_instances().get("Instances", [])
        data.append({"Instances": instances})
        for inst in instances:
            inst_arn = inst.get("InstanceArn")
            if not inst_arn:
                continue
            psets = sso_admin.list_permission_sets(InstanceArn=inst_arn).get("PermissionSets", [])
            data.append({"InstanceArn": inst_arn, "PermissionSets": psets})
            for ps in psets:
                try:
                    desc = sso_admin.describe_permission_set(InstanceArn=inst_arn, PermissionSetArn=ps)
                    data.append({"PermissionSet": desc.get("PermissionSet")})
                except botocore.exceptions.ClientError:
                    pass
            try:
                acct_assign = sso_admin.list_accounts_for_provisioned_permission_set(InstanceArn=inst_arn, PermissionSetArn=psets[0]) if psets else {}
                if acct_assign:
                    data.append({"Assignments": acct_assign})
            except botocore.exceptions.ClientError:
                pass
            # Identity store basic users
            store_id = inst.get("IdentityStoreId")
            if store_id:
                try:
                    users = identity.list_users(IdentityStoreId=store_id).get("Users", [])
                    data.append({"Users": users})
                except botocore.exceptions.ClientError:
                    pass
    except botocore.exceptions.ClientError:
        pass
    return "sso", data


def _collect_rds(session):
    rds = session.client("rds")
    data: List[dict] = []
    try:
        snaps = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
        for snap in snaps:
            attrs = {}
            try:
                attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap["DBSnapshotIdentifier"]).get(
                    "DBSnapshotAttributesResult", {}
                )
            except botocore.exceptions.ClientError:
                pass
            data.append({"Snapshot": snap, "Attributes": attrs})
    except botocore.exceptions.ClientError:
        pass
    return "rds", data


def _collect_codepipeline(session):
    cp = session.client("codepipeline")
    data: List[dict] = []
    try:
        pipes = cp.list_pipelines().get("pipelines", [])
        for p in pipes:
            try:
                pipe = cp.get_pipeline(name=p["name"]).get("pipeline", {})
                data.append({"Pipeline": pipe})
            except botocore.exceptions.ClientError:
                pass
    except botocore.exceptions.ClientError:
        pass
    return "codepipeline", data


def _collect_cloudwatch(session):
    cw = session.client("logs")
    data: List[dict] = []
    try:
        paginator = cw.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            data.append({"LogGroups": page.get("logGroups", [])})
    except botocore.exceptions.ClientError:
        pass
    return "cloudwatch", data


def _collect_waf(session):
    waf = session.client("wafv2")
    data: List[dict] = []
    try:
        for scope in ["REGIONAL", "CLOUDFRONT"]:
            resp = waf.list_web_acls(Scope=scope)
            data.append({"Scope": scope, "WebACLs": resp.get("WebACLs", [])})
    except botocore.exceptions.ClientError:
        pass
    return "waf", data


def _collect_shield(session):
    shield = session.client("shield")
    data: List[dict] = []
    try:
        sub = shield.describe_subscription()
        data.append({"Subscription": sub.get("Subscription", {})})
    except botocore.exceptions.ClientError:
        pass
    return "shield", data


def _collect_firewall_manager(session):
    fms = session.client("fms")
    data: List[dict] = []
    try:
        admin = fms.get_admin_account()
        data.append({"Admin": admin})
    except botocore.exceptions.ClientError:
        pass
    return "fms", data


SERVICE_COLLECTORS: Dict[str, CollectorFn] = {
    "sts": _collect_sts_identity,
    "org": _collect_org,
    "iam": _collect_iam_summary,
    "iam-roles": _collect_iam_roles,
    "iam-users": _collect_iam_users,
    "iam-policies": _collect_iam_policies,
    "cloudtrail": _collect_cloudtrail,
    "guardduty": _collect_guardduty,
    "s3": _collect_s3,
    "kms": _collect_kms,
    "vpc": _collect_vpc,
    "ec2": _collect_ec2,
    "ec2-images": _collect_ec2_snapshots_images,
    "eks": _collect_eks,
    "ecr": _collect_ecr,
    "lambda": _collect_lambda,
    "cloudformation": _collect_cloudformation,
    "codebuild": _collect_codebuild,
    "secretsmanager": _collect_secretsmanager,
    "ssm-parameters": _collect_ssm_parameters,
    "sns": _collect_sns,
    "sqs": _collect_sqs,
    "securityhub": _collect_securityhub,
    "detective": _collect_detective,
    "config": _collect_config,
    "sso": _collect_sso,
    "rds": _collect_rds,
    "codepipeline": _collect_codepipeline,
    "cloudwatch": _collect_cloudwatch,
    "waf": _collect_waf,
    "shield": _collect_shield,
    "fms": _collect_firewall_manager,
}
