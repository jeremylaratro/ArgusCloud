# AWSHound Domain Model & Architecture

## Graph Schema (Nodes)
- `OrgRoot`, `OrgUnit`, `Account`: org structure; include SCP links and delegated admins.
- `Principal`: `User`, `Role`, `Group`, `SSOIdentity`, `ExternalIdPUser` (SAML/OIDC). Track boundary/session policy, MFA status, last-used services.
- `Policy`: managed/inline, SCP, permission sets, permission boundaries, session policies.
- `ServiceResource`: typed per service (S3Bucket, KMSKey, Lambda, EKSCluster, ECRRepo, EC2Instance/Snapshot/AMI, VPC/Subnet/SG/RouteTable/Endpoint, RDSCluster, CloudFormationStack, CodeBuildProject, Secret, SSMParameter, Queue/Topic, CloudTrailTrail, GuardDutyDetector, ConfigRecorder).
- `NetworkNode`: CIDR/VPC/Subnet/SecurityGroup/EKS API endpoint/LoadBalancer for reachability edges.
- `Finding/Detection`: GuardDuty finding, SecurityHub control status, Config rule state (optional ingestion).

## Graph Schema (Edges)
- `Contains`: OrgRoot→OU/Account, OU→OU/Account.
- `SCPApplies`: SCP→OU/Account.
- `AssumableBy` / `Trusts`: Role→Principal/Account/IdP; includes external principal ARNs and conditions.
- `MemberOf`: User→Group; PermissionSet→Principal (via SSO assignment).
- `AttachedPolicy`: Principal/Group/Role/PermissionSet→Policy; `ResourcePolicy`: Resource→Principal/Service.
- `HasBoundary` / `HasSessionCap`: Principal/Session→Policy.
- `CanRead/Write/Admin`: Policy-derived effective edges Principal→Resource (capability typed per service/action category).
- `DelegatedAdmin`: Security services delegated admin (GuardDuty/Detective/SecurityHub/Config) Account→Service.
- `NetworkReachable`: Source→Destination via SG/route analysis; `InternetExposed`: Resource→Internet.
- `Logging`: Trail→Account/Region; `GuardDutyMonitors`: Detector→Account/Region.
- `AttackPath`: computed edge with rule id, likelihood, and preconditions (e.g., `AssumeRoleOpenTrust`, `EKSAPIBypassCloudTrail`, `SnapshotExfil`, `CodeBuildSecretLeak`, `KMSRansomware`).

## Core Queries (BloodHound-style)
- How can principal X reach Admin? (assume-role chains, misconfig trusts, privilege-escalation rules).
- What can this principal access? (effective actions with SCP/boundary/session caps, resource policies).
- Cross-account reachability map (Org and non-Org trusts).
- Publicly exposed assets (S3/KMS, internet-facing SG/ELB, public ECR).
- Detection posture (where CloudTrail/GuardDuty/Config/Detective/SecurityHub enabled or missing).
- Path to data exfil (from principal → data store with egress).

## Architecture (MVP)
- Collector CLI: modular service collectors, throttling/region filters, MFA/session policy support, offline bundle writer (JSONL/CSV + manifest).
- Normalizer: converts raw AWS outputs into canonical nodes/edges; dedupes ARNs across partitions.
- Rule Engine: evaluates escalation/lateral rules from training-derived playbooks; outputs AttackPath edges with evidence.
- Storage: pluggable backends (initial JSON bundle + optional Neo4j/SQLite/networkx loader); schema versioning in manifest.
- UI/Visualizer: BloodHound-like query UI and canned views (Org tree, trust graph, exposure map, detections map).
- Safety: “stealth” profile (slow, minimal API set), detection-surface reporter (CloudTrail/GuardDuty/Config presence).

## Prioritized Service Coverage (training-informed)
1) Org, IAM, STS, SSO/Identity Center (permission sets), CloudTrail, GuardDuty, Config.  
2) S3, KMS, Lambda, EKS/ECR, EC2 (instances/snapshots/AMIs/IMDS reachability), VPC (SG/Route), CloudFormation.  
3) CodeBuild/CodePipeline, Secrets Manager/SSM, RDS/Aurora, SNS/SQS, SecurityHub/Detective/Inspector, WAF/Shield/Firewall Manager.  
4) Additional high-value services as encountered in target environments.

## Data Model Notes
- Effective permissions = IAM allow minus explicit deny, intersected with SCP, permission boundary, and session policy; resource policies can grant without IAM membership.
- Track conditions (MFA, IP ranges, time) to avoid overclaiming paths.
- Support partitions (aws, aws-us-gov, aws-cn); include partition in ARN keys.
