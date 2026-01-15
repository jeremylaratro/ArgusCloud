# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

**Please DO NOT open public GitHub issues for security vulnerabilities.**

### How to Report

1. **Email:** Send details to the project maintainers privately
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Resolution Timeline:** Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### What to Expect

1. Acknowledgment of your report
2. Assessment of the vulnerability
3. Development of a fix
4. Coordinated disclosure (if applicable)
5. Credit in release notes (unless you prefer anonymity)

## Security Features

ArgusCloud implements the following security measures:

### Authentication & Authorization

- **JWT Authentication:** Using PyJWT library with HS256 algorithm
- **API Key Support:** SHA256-hashed keys with constant-time comparison
- **Token Expiration:** Configurable JWT expiry (default: 1 hour)

### Input Validation

- **Cypher Query Whitelist:** Only read-only queries allowed (MATCH...RETURN, CALL db.*, CALL apoc.*)
- **Pydantic Models:** Request validation for all API endpoints
- **Profile Name Validation:** Alphanumeric with limited special characters
- **AWS Credential Validation:** Format validation for access keys

### Data Protection

- **Credential Handling:** AWS credentials cleared from memory after use
- **CORS Configuration:** Specific origin validation (no wildcards)
- **Zip Bomb Protection:** Size and file count limits for uploads

### Infrastructure Security

- **Neo4j Connection:** Supports authenticated connections
- **Environment Variables:** Sensitive config via environment only
- **No Credential Storage:** Credentials never persisted to disk

## Security Best Practices

When deploying ArgusCloud:

1. **Use HTTPS:** Always deploy behind TLS-terminating proxy
2. **Restrict CORS:** Configure `ARGUSCLOUD_CORS_ORIGINS` appropriately
3. **Secure Neo4j:** Enable authentication, use strong passwords
4. **Network Isolation:** Run API and Neo4j in private network
5. **Least Privilege:** Use read-only Neo4j users where possible
6. **Audit Logging:** Enable logging for security events
7. **Regular Updates:** Keep ArgusCloud and dependencies updated

## Security Advisories

Security advisories will be published via:
- GitHub Security Advisories
- Release notes

## Scope

The following are in scope for security reports:

- ArgusCloud API server vulnerabilities
- Authentication/authorization bypasses
- Injection vulnerabilities (Cypher, command, etc.)
- Sensitive data exposure
- Denial of service vulnerabilities

The following are out of scope:

- Social engineering attacks
- Physical security
- Third-party service vulnerabilities
- Issues in development/test configurations

## Contact

For security-related questions that don't require private disclosure,
please open a GitHub Discussion.

---

Thank you for helping keep ArgusCloud secure!
