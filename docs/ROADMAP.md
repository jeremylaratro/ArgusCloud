# ArgusCloud Development Roadmap

**Version:** 0.3.0
**Last Updated:** 2025-12-31

This document tracks future development priorities and technical debt items.

---

## Immediate Priorities (v0.3.x)

### Technical Debt

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Fix `datetime.utcnow()` deprecations | HIGH | Low | Replace with `datetime.now(UTC)` across 58 occurrences |
| Address Dependabot vulnerabilities | HIGH | Low | 3 moderate alerts on GitHub |
| Register `integration` pytest mark | LOW | Trivial | Add to pyproject.toml |
| Add missing `__init__.py` files | LOW | Trivial | Some test directories |

### Security Improvements

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Review Dependabot alerts | HIGH | Low | Check GitHub security tab |
| Add CSP headers to UI | MEDIUM | Low | Content Security Policy |
| Audit rate limit thresholds | MEDIUM | Low | May need tuning |

---

## Short-Term (v0.4.0)

### Multi-Cloud Support

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| GCP collector foundation | HIGH | High | Service account auth, core resources |
| Azure collector foundation | MEDIUM | High | Service principal auth, ARM resources |
| Cloud-agnostic node types | MEDIUM | Medium | Unified identity/resource model |

### Enhanced Rules

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Snapshot/AMI exfiltration paths | HIGH | Medium | Cross-account sharing risks |
| ECR cross-account pull detection | HIGH | Medium | Container image exposure |
| EKS API direct access analysis | MEDIUM | Medium | Kubernetes RBAC mapping |
| GuardDuty/CloudTrail tamper detection | MEDIUM | Low | Detect security control bypass |
| Lambda/ECR public exposure | MEDIUM | Low | Public function URLs, repos |

### Performance

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Query result pagination | HIGH | Medium | Large graph handling |
| Background job queue (Celery/RQ) | MEDIUM | High | Long-running collections |
| Neo4j connection pooling optimization | LOW | Low | Current pool may be sufficient |

---

## Medium-Term (v0.5.0)

### UI Enhancements

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Interactive graph filtering | HIGH | Medium | Click-to-filter nodes |
| Query builder UI | MEDIUM | High | Visual Cypher construction |
| Diff view for profile comparisons | MEDIUM | Medium | Before/after analysis |
| Dark mode toggle | LOW | Low | CSS variables already in place |
| Mobile responsive improvements | LOW | Medium | Current UI is desktop-focused |

### API Enhancements

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| WebSocket for live updates | MEDIUM | High | Real-time collection progress |
| GraphQL endpoint (optional) | LOW | High | Alternative to REST |
| API versioning (v1/v2) | LOW | Medium | Future-proofing |

### Collectors

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| AWS SSO/Identity Center details | HIGH | Medium | Permission set analysis |
| AWS Access Advisor integration | MEDIUM | Medium | Unused permissions |
| AWS Cost data correlation | LOW | Medium | Cost impact of findings |

---

## Long-Term (v1.0.0)

### Enterprise Features

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Multi-tenant support | HIGH | Very High | Isolated customer data |
| RBAC for API users | HIGH | High | Fine-grained permissions |
| Audit logging | HIGH | Medium | Track all operations |
| SSO integration (SAML/OIDC) | MEDIUM | High | Enterprise auth |
| Scheduled collection jobs | MEDIUM | Medium | Cron-like scheduling |
| Alerting integration | MEDIUM | High | Slack, PagerDuty, email |

### Compliance & Reporting

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| CIS Benchmark mapping | HIGH | High | Map findings to controls |
| SOC2 evidence generation | MEDIUM | Medium | Automated evidence |
| Custom report templates | MEDIUM | Medium | Branded PDF reports |
| Historical trend analysis | LOW | High | Time-series findings |

### Scalability

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Horizontal API scaling | MEDIUM | High | Kubernetes deployment |
| Neo4j cluster support | MEDIUM | High | HA database |
| Distributed collection | LOW | Very High | Parallel multi-account |

---

## Completed (Reference)

### v0.3.0 (2025-12-31)
- [x] Prometheus metrics
- [x] Rate limiting
- [x] Graceful shutdown
- [x] Integration test infrastructure
- [x] Security test suite
- [x] UI modularization
- [x] Enhanced Cypher validation

### v0.2.0 (2024-12)
- [x] Multi-cloud architecture refactor
- [x] Modern UI with attack paths
- [x] JWT authentication
- [x] 20+ AWS collectors

### v0.1.0 (Initial)
- [x] Core graph engine
- [x] AWS collector MVP
- [x] Neo4j integration
- [x] Basic CLI

---

## Contributing

See `CONTRIBUTING.md` for development setup and guidelines.

When picking up roadmap items:
1. Create an issue referencing this roadmap
2. Assign appropriate labels (enhancement, security, performance)
3. Update this document when complete
4. Add entry to CHANGELOG.md

---

## Notes

- Priorities may shift based on user feedback
- "Effort" is relative: Low (~1 day), Medium (~1 week), High (~2-4 weeks), Very High (~1+ month)
- All estimates assume single developer
