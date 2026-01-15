# ArgusCloud Progress Tracker

| Step | Description | Status | Notes |
| --- | --- | --- | --- |
| 1 | Scope, personas, constraints | Completed | See `docs/overview.md`. |
| 2 | Domain model & architecture | Completed | See `docs/domain-model.md`. |
| 3 | Collector MVP outline | Completed | See `docs/collector-mvp.md`. |
| 4 | Progress tracking setup | Completed | This file. |
| 5 | Implement collector skeleton | Completed | CLI scaffolding, auth resolver, manifest writer, initial collectors (sts/org/iam). |
| 6 | Normalize graph schema | In progress | Normalizer covers IAM/Org/CloudTrail/GuardDuty/S3/KMS/VPC/EC2/AMI/Snapshots/EKS/ECR/Lambda/CloudFormation/CodeBuild/Secrets/SSM/SNS/SQS/SecurityHub/Detective/Config/SSO with deduping for scale. |
| 7 | Rule engine (attack paths) | In progress | Rules include open trust, missing GuardDuty/CloudTrail/Config, public resource policies, open SGs, KMS external access, assume-role chains, CodeBuild risks, snapshot/AMI exposure, ECR cross-account (with severity). |
| 8 | Storage adapters | In progress | JSONL loaders and Neo4j loader with batch MERGE. |
| 9 | UI/visualization | In progress | Offline SPA prototype at `ui/index.html` with Cytoscape graph, filters, sample data. |
| 10 | Testing/lab | In progress | Pytest coverage for rules and normalizer; lab plan in `docs/lab.md`. |

## Production Hardening Checklist
| Workstream | Status | Notes |
| --- | --- | --- |
| Collector resilience & coverage | Not started | Add throttling/resume, Access Advisor, EventBridge/StepFunctions/CodeDeploy/Kinesis/EBS/last-used |
| Effective permissions engine | Not started | Compute IAM+SCP+boundary+session/resource policies; conditions awareness |
| Rule expansion (training paths) | In progress | Add IMDS→STS, tamper paths, SSO misconfig, CloudFormation backdoor, etc. |
| API/UI hardening | In progress | Add pagination, health wiring, toasts, presets, large-graph limits |
| Neo4j/storage | Not started | Indexes/constraints, schema tagging |
| Testing/fixtures | In progress | Integration/API/UI smoke, expanded fixtures |

Update cadence: after each milestone or significant sub-task completion.
