# Collector MVP Plan

## Goals
- Single-binary CLI that ingests credentials (env/profile/STS token), enumerates priority services safely, and writes an offline bundle (JSONL/CSV + manifest) for graph ingest.
- Provide a minimal read policy template and warn when capabilities are capped by SCP/boundary/session.
- Offer modes: `fast` (broad, parallel), `stealth` (slow, minimal API set), `scoped` (region/account filters).

## Minimal Read Policy (starting point)
- Org: `organizations:DescribeOrganization`, `ListAccounts`, `ListOrganizationalUnitsForParent`, `ListParents`, `ListRoots`, `ListPolicies`, `ListPoliciesForTarget`, `DescribePolicy`.
- IAM/STS: `iam:GetAccountAuthorizationDetails`, `iam:ListUsers|Roles|Groups|Policies|InstanceProfiles`, `iam:Get*Policy*`, `iam:ListAttached*`, `iam:ListRoleTags`, `sts:GetCallerIdentity`, `sts:AssumeRole` (optional discovery chaining).
- SSO/Identity Center: `sso-admin:ListInstances`, `ListPermissionSets`, `DescribePermissionSet`, `ListManagedPoliciesInPermissionSet`, `ListAccountsForProvisionedPermissionSet`, `ListAccountAssignments`; `identitystore:ListUsers|Groups`.
- CloudTrail: `cloudtrail:ListTrails`, `DescribeTrails`, `GetTrailStatus`, `GetEventSelectors`, `GetInsightSelectors`, `ListPublicKeys`.
- GuardDuty: `guardduty:ListDetectors`, `GetDetector`, `ListFindings`, `GetFindings`, `ListOrganizationAdminAccounts`, `ListInvitations`, `ListIPSets`, `ListThreatIntelSets`.
- Config: `config:DescribeConfigurationRecorders`, `DescribeConfigurationRecorderStatus`, `DescribeConformancePacks`, `DescribeDeliveryChannels`, `GetComplianceDetailsByConfigRule`.
- VPC/Network: `ec2:DescribeVpcs|Subnets|SecurityGroups|RouteTables|VpcEndpoints|InternetGateways|NatGateways`.
- EC2 Core: `ec2:DescribeInstances|Images|Snapshots|Volumes|InstanceAttribute`, `ec2:DescribeIamInstanceProfileAssociations`.
- EKS/ECR: `eks:ListClusters`, `DescribeCluster`; `ecr:DescribeRepositories`, `GetRepositoryPolicy`.
- Lambda: `lambda:ListFunctions`, `GetPolicy`, `ListEventSourceMappings`.
- S3/KMS: `s3:ListAllMyBuckets`, `GetBucketAcl`, `GetBucketPolicyStatus`, `GetBucketPolicy`; `kms:ListKeys`, `DescribeKey`, `GetKeyPolicy`.
- CloudFormation: `cloudformation:DescribeStacks`, `ListStacks`, `GetTemplateSummary`.
- CodeBuild: `codebuild:ListProjects`, `BatchGetProjects`; `codepipeline:ListPipelines`, `GetPipeline`.
- Secrets/Parameters/Queues: `secretsmanager:ListSecrets`, `GetResourcePolicy`; `ssm:DescribeParameters`, `GetParameter*`; `sns:ListTopics`, `GetTopicAttributes`; `sqs:ListQueues`, `GetQueueAttributes`.
- Security services: `securityhub:GetFindings|GetEnabledStandards|DescribeHub`; `detective:ListGraphs`, `ListMembers`, `ListDatasources`; `inspector2:ListFindings`, `ListDelegatedAdminAccounts`; `waf-regional:ListWebACLs`, `wafv2:ListWebACLs`.

## Modes & Safety
- `stealth`: serial or low-concurrency, region filter required, skip noisy APIs (e.g., large list-objects), use cached describe per ARN; user-agent/time randomization optional; warn about CloudTrail/GuardDuty presence.
- `fast`: higher concurrency, all regions by default, collects richer metadata (tags, policies, last-used where available).
- `scoped`: user-supplied allowlists for accounts/regions/services.
- Detection awareness: surface if CloudTrail disabled, GuardDuty absent, Config missing; include bypass warnings (from training) but do not alter configs.

## Execution Flow
1) Auth: resolve credentials (profile/env/sso cache), test with `sts:GetCallerIdentity`.
2) Context: detect partition/region defaults, org membership, and SCP boundaries.
3) Collect: run service modules respecting mode, pagination, and throttling; serialize raw responses to bundle.
4) Normalize: build nodes/edges with evidence metadata (source service, timestamp, region).
5) Output: write manifest (schema version, services collected, errors), raw data, and normalized graph files.

## Error Handling & Resilience
- Continue on per-service errors; log missing permissions with action names.
- Retry with backoff on throttling; honor API limits.
- Resume support via manifest checkpoints.
