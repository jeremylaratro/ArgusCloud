# AWSHound Current Status

## Completed
- Scope/personas/objectives defined (`docs/overview.md`).
- Graph schema and architecture captured (`docs/domain-model.md`).
- Collector MVP plan with minimal read policy (`docs/collector-mvp.md`).
- CLI collector implemented with manifest/bundle writer and default collectors for IAM/Org/CloudTrail/GuardDuty/S3/KMS/VPC/EC2/EKS/ECR/Lambda/CloudFormation/CodeBuild/Secrets/SSM/SNS/SQS/SecurityHub/Detective/Config.
- Normalizer covers collected services, dedupes nodes/edges for scale, and marks admin-ish roles.
- Rule engine with severity/explanations: open trust, missing GuardDuty/CloudTrail/Config, public resource policies, open SGs, KMS external access, assume-role chains (BFS to admin), CodeBuild env/privileged risks.
- Neo4j loader with batch MERGE; JSONL bundle I/O; docs/neo4j.md.
- Offline UI prototype (`ui/index.html`) for bundle upload, stats, and attack-path table.
- Testing: pytest suite for rules and normalization; fixtures added; tests passing.
- Lab/test scaffold (`docs/lab.md`) and UI notes.

## In Progress / Next
- Expand rules for training pathways: snapshot/AMI exfil, ECR cross-account pulls, EKS API direct access, GuardDuty tamper, CloudTrail tamper, privileged CodeBuild credential theft, Lambda/ECR public exposure.
- Enrich normalization/admin detection and add more collectors if needed (SSO/Identity Center details, Access Advisor).
- Evolve UI to render graphs and filters, add query presets, and improve UX for large graphs.
- Build lab automation and CI fixtures to regress collectors and rules.
