# Testing Plan

- Unit tests to cover normalizers and rule evaluations with fixtures.
- Integration tests to run `collect` against recorded responses or localstack.
- Neo4j loader smoke test with in-memory Neo4j (or skip if not available).

Pending: add fixtures for IAM/S3/KMS/VPC and write pytest cases.
