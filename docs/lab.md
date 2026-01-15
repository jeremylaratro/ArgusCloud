# ArgusCloud Lab Scaffold

Goal: reproducible lab mirroring training scenarios for integration testing of collectors and rules.

Planned setup:
- Org with management + 2 child accounts.
- Open and restricted IAM roles (one with wildcard trust), permission boundaries, and session policies.
- GuardDuty/CloudTrail/Config toggled across accounts for detection posture checks.
- Sample services: S3 bucket with/without public access, KMS key with lax policy, EKS cluster, CodeBuild project with secret, EC2 instance + snapshot.

Execution:
- Deploy via CloudFormation/Terraform with parametrized regions.
- Emit fixtures by running `arguscloud collect` then `normalize` to create golden bundles for regression.

Next steps:
- Author infra templates and CI job to deploy/destroy lab on demand.
