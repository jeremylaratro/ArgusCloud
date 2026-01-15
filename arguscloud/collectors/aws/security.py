"""AWS Security service collectors (CloudTrail, GuardDuty, SecurityHub, etc.)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="cloudtrail",
    provider="aws",
    description="Collect CloudTrail trails and status",
    services=["cloudtrail"],
)
def collect_cloudtrail(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect CloudTrail trails and their logging status."""
    ct = session.client("cloudtrail")
    data: List[Dict[str, Any]] = []

    try:
        trails = ct.list_trails().get("Trails", [])
        if trails:
            names = [t["Name"] for t in trails if "Name" in t]
            if names:
                describe = ct.describe_trails(trailNameList=names)
                data.append({"Trails": describe.get("trailList", [])})

            for name in names:
                try:
                    status = ct.get_trail_status(Name=name)
                    data.append({"TrailStatus": status, "Name": name})
                except botocore.exceptions.ClientError as exc:
                    log.debug(f"get_trail_status failed for {name}: {exc}")

                # Get event selectors
                try:
                    selectors = ct.get_event_selectors(TrailName=name)
                    data.append({"EventSelectors": selectors, "Name": name})
                except botocore.exceptions.ClientError:
                    pass
    except botocore.exceptions.ClientError as exc:
        log.warning(f"CloudTrail collection failed: {exc}")

    return "cloudtrail", data


@collectors.collector(
    name="guardduty",
    provider="aws",
    description="Collect GuardDuty detectors and findings",
    services=["guardduty"],
)
def collect_guardduty(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect GuardDuty detectors and their configuration."""
    gd = session.client("guardduty")
    data: List[Dict[str, Any]] = []

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        for det_id in detectors:
            try:
                info = gd.get_detector(DetectorId=det_id)
                record: Dict[str, Any] = {"Detector": det_id, "Info": info}

                # Get findings summary
                try:
                    findings = gd.list_findings(
                        DetectorId=det_id,
                        FindingCriteria={
                            "Criterion": {
                                "severity": {"Gte": 4}  # Medium and higher
                            }
                        },
                        MaxResults=50
                    )
                    record["HighSeverityFindings"] = len(findings.get("FindingIds", []))
                except botocore.exceptions.ClientError:
                    pass

                data.append(record)
            except botocore.exceptions.ClientError as exc:
                log.debug(f"get_detector failed for {det_id}: {exc}")
    except botocore.exceptions.ClientError as exc:
        log.debug(f"list_detectors failed: {exc}")

    return "guardduty", data


@collectors.collector(
    name="securityhub",
    provider="aws",
    description="Collect Security Hub configuration and findings",
    services=["securityhub"],
)
def collect_securityhub(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect Security Hub hub info and high-severity findings."""
    sh = session.client("securityhub")
    data: List[Dict[str, Any]] = []

    try:
        hub = sh.describe_hub()
        data.append({"Hub": hub})
    except botocore.exceptions.ClientError:
        pass

    try:
        # Get critical and high findings
        findings = sh.get_findings(
            Filters={
                "SeverityLabel": [
                    {"Value": "CRITICAL", "Comparison": "EQUALS"},
                    {"Value": "HIGH", "Comparison": "EQUALS"},
                ]
            },
            MaxResults=100
        )
        data.append({"Findings": findings.get("Findings", [])})
    except botocore.exceptions.ClientError:
        pass

    try:
        # Get enabled standards
        standards = sh.get_enabled_standards()
        data.append({"EnabledStandards": standards.get("StandardsSubscriptions", [])})
    except botocore.exceptions.ClientError:
        pass

    return "securityhub", data


@collectors.collector(
    name="detective",
    provider="aws",
    description="Collect Amazon Detective graphs",
    services=["detective"],
)
def collect_detective(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect Amazon Detective behavior graphs."""
    det = session.client("detective")
    data: List[Dict[str, Any]] = []

    try:
        graphs = det.list_graphs().get("GraphList", [])
        data.append({"Graphs": graphs})
    except botocore.exceptions.ClientError:
        pass

    return "detective", data


@collectors.collector(
    name="config",
    provider="aws",
    description="Collect AWS Config recorder status",
    services=["config"],
)
def collect_config(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect AWS Config recorder configuration and status."""
    cfg = session.client("config")
    data: List[Dict[str, Any]] = []

    try:
        recorders = cfg.describe_configuration_recorders()
        data.append({"Recorders": recorders.get("ConfigurationRecorders", [])})

        status = cfg.describe_configuration_recorder_status()
        data.append({"RecorderStatus": status.get("ConfigurationRecordersStatus", [])})
    except botocore.exceptions.ClientError:
        pass

    try:
        # Get conformance packs
        packs = cfg.describe_conformance_packs()
        data.append({"ConformancePacks": packs.get("ConformancePackDetails", [])})
    except botocore.exceptions.ClientError:
        pass

    return "config", data


@collectors.collector(
    name="waf",
    provider="aws",
    description="Collect WAFv2 Web ACLs",
    services=["wafv2"],
)
def collect_waf(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect WAFv2 Web ACLs for regional and CloudFront scopes."""
    waf = session.client("wafv2")
    data: List[Dict[str, Any]] = []

    for scope in ["REGIONAL", "CLOUDFRONT"]:
        try:
            resp = waf.list_web_acls(Scope=scope)
            acls = resp.get("WebACLs", [])
            data.append({"Scope": scope, "WebACLs": acls})

            # Get details for each ACL
            for acl in acls:
                try:
                    detail = waf.get_web_acl(
                        Name=acl["Name"],
                        Scope=scope,
                        Id=acl["Id"]
                    )
                    data.append({
                        "WebACLDetail": detail.get("WebACL", {}),
                        "Scope": scope
                    })
                except botocore.exceptions.ClientError:
                    pass
        except botocore.exceptions.ClientError:
            pass

    return "waf", data


@collectors.collector(
    name="shield",
    provider="aws",
    description="Collect AWS Shield Advanced subscription",
    services=["shield"],
)
def collect_shield(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect AWS Shield Advanced subscription status."""
    shield = session.client("shield")
    data: List[Dict[str, Any]] = []

    try:
        sub = shield.describe_subscription()
        data.append({"Subscription": sub.get("Subscription", {})})
    except botocore.exceptions.ClientError:
        pass

    try:
        protections = shield.list_protections()
        data.append({"Protections": protections.get("Protections", [])})
    except botocore.exceptions.ClientError:
        pass

    return "shield", data


@collectors.collector(
    name="fms",
    provider="aws",
    description="Collect Firewall Manager admin account",
    services=["fms"],
)
def collect_firewall_manager(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect Firewall Manager configuration."""
    fms = session.client("fms")
    data: List[Dict[str, Any]] = []

    try:
        admin = fms.get_admin_account()
        data.append({"Admin": admin})
    except botocore.exceptions.ClientError:
        pass

    try:
        policies = fms.list_policies()
        data.append({"Policies": policies.get("PolicyList", [])})
    except botocore.exceptions.ClientError:
        pass

    return "fms", data
