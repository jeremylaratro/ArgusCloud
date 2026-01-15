# Production Hardening Plan (ArgusCloud)

## Goals
- Reliable, large-scale collection across orgs (100+ accounts) with throttling, retries, and resumability.
- Accurate modeling of effective permissions (IAM allow/deny, SCP, boundaries, session policies, resource policies, conditions).
- Comprehensive attack-path coverage for training scenarios and common AWS misconfigurations.
- Usable API/UI with status, pagination, and guardrails for large graphs.
- Repeatable testing and fixtures for collectors, rules, API, and UI.

## Workstreams & Steps

### 1) Collector Resilience & Coverage
- Add throttling/rate-limit settings and exponential backoff on throttling errors.
- Implement resumable runs with checkpoints in the manifest.
- Add collectors: Access Advisor/last-used (where available), CloudWatch Events/EventBridge, Step Functions, CodeDeploy, Kinesis/Firehose, EBS sharing, IAM last-used, EC2 IMDS reachability check (flag via security groups/public IP), CloudWatch Logs delivery status.
- Add per-service error reporting and soft-fail (continue).

### 2) Effective Permissions Engine
- Compute effective permissions per principal: IAM allows minus denies intersected with SCPs, permission boundaries, session policies; include resource policies that grant access.
- Incorporate conditions (MFA/IP/time) and mark unknown/conditional paths separately.
- Surface privilege tiers (admin/power/reader) and last-used (Access Advisor) where possible.

### 3) Rule Expansion (Attack Paths)
- Add training-focused paths: IMDS→STS, CloudTrail/GuardDuty tamper, EKS API direct access, Lambda/ECR public invocation/pull, RDS snapshot/cluster sharing, CodePipeline/CodeDeploy artifact exfil, SecretsManager/SSM backdoor policies, CloudFormation backdoor, SSO/permission-set misconfig, boundary/session-policy bypass, WAF/Shield gaps, EBS snapshot sharing, ECR pull with cross-account, CloudWatch log tamper.
- Add severities and evidence to each path; keep deduping.

### 4) API/UI Hardening
- API: add pagination/limits for graph endpoints; add health check that tests Neo4j connectivity; add error codes.
- UI: loading/skeleton states, toasts for errors, header status wired to `/health`, saved presets (localStorage), better large-graph handling (limit/filter before render), responsive design.
- Add graph controls: clustering/limit toggle, reset view.

### 5) Neo4j/Storage
- Add indexes/constraints on `Resource.id` and `REL` type/id.
- Add schema version tagging in Neo4j load; optional cleanup script.
- Optional: export filtered subgraphs for UI.

### 6) Testing & Fixtures
- Integration tests for collectors against recorded fixtures/localstack.
- API endpoint tests (graph/query).
- UI smoke (headless) for file upload, API fetch, tab switch, theme toggle.
- Rule output regression tests with expanded fixtures (sample_nodes_expanded/edges).

## Tracking
- Use `docs/progress.md` to record current status per workstream and step.
- Add a simple checklist table for the production plan.
