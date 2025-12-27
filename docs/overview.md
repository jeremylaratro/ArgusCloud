# awshound Overview

## Product Vision
BloodHound-style graph analytics for AWS that ingests org- and account-level data, models trust and permission relationships, visualizes attack/defense paths, and produces actionable reports for red, purple, and blue teams.

## Personas
- Red team/RT operators: black-box and assumed-breach scenarios; need stealth, evasion tips, and attack path suggestions.
- Blue team/IR/security engineering: org-wide exposure map, detections coverage, least-privilege gaps, and misconfig hygiene.
- Auditors/GRC: permission summaries, data handling constraints, and evidence for control effectiveness.

## Engagement Modes
- White-box read-only: provided read credentials (minimal policy set), optional MFA/session policies; focuses on coverage and safety.
- Black-box/adversarial: scoped brute-force and trust abuse, controlled enumeration pace, assumes CloudTrail/GuardDuty present.
- Partition/region scope: aws, aws-us-gov, aws-cn as options; region filters and throttling to avoid noisy cross-region calls.

## Core Objectives
1) Generate reports on supplied AWS creds and their effective permissions (including SCPs, boundaries, session policies, resource policies, and Access Advisor last-used).  
2) Visualize AWS environment graphs: org structure, principals, trust/assume edges, resource policies, service relationships, network reachability, and potential attack or defense paths.

## Non-Goals (initial)
- Active exploitation or disruptive changes.
- Non-AWS clouds; multi-cloud only as future work.
- Comprehensive coverage of every AWS service on day one; focus on high-impact training set first.

## Success Metrics
- Time-to-first-graph (TTFG) and time-to-permission-report (TTPR) on a fresh account.
- Coverage: % of org accounts enumerated; % of targeted services collected.
- Detection footprint: number of API calls vs baseline; optional “stealth profile” adherence.
- Path fidelity: precision/recall of attack-path rules validated against lab scenarios.

## Data Handling & Safety
- Offline-first: collectors can export bundles without uploading externally.
- No secret exfil beyond explicit outputs; PII minimization and redact toggles.
- Stealth controls: rate limiting, region scoping, user-agent/time mimicry guidance; avoid noisy APIs when possible (per training detection notes).

## Detection & Evasion Context (from training material)
- CloudTrail: enumerate status/regions/digests; warn on tamper risk and S3/KMS ransomware angles.
- GuardDuty: detect presence/admin; note trusted IPs, filters, archiving rules, and alert-bypass misconfigs.
- IAM/STS: highlight open trust policies, cross-account assumptions, boundary/session caps, and MFA gaps.
- EKS/API direct access: callouts that off-AWS API access may bypass CloudTrail; flag when discovered.

## Constraints & Assumptions
- Requires at least read permissions; black-box may attempt safe role-name discovery where allowed.
- Large orgs: must handle 100+ accounts; pagination, parallel-safe throttling, and resumable collection.
- Graph backend can be swapped (initially defined in architecture doc).

## Deliverables (MVP)
- CLI collector with minimal read policy template.
- Graph schema + export format (JSON/CSV) and optional Neo4j ingest.
- Web/desktop viewer with core BloodHound-like queries.
- Report generator: permission summary and misconfig findings.
