# Requirements Template

## Functional Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-001 | | | |

## Security Requirements

Map each requirement to an [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) control.

| ID | Requirement | ASVS Control | Implementation Notes |
|----|-------------|--------------|----------------------|
| SR-001 | | V1.x | |

## Data Flow Diagram

```
[Source] --> [Process] --> [Destination]
    |            |
    v            v
[Data Store]  [External Service]
```

Describe each data flow, including:
- What data moves between components
- Transport security (TLS, mTLS)
- Authentication at each boundary

## Input Validation Rules

| Input | Source | Validation | Rejection Behavior |
|-------|--------|------------|--------------------|
| | | | |

All validation must reject invalid input upstream — sanitization-only approaches are not acceptable.

## Trust Boundary Crossings

| Boundary | From | To | Auth Mechanism | Validation |
|----------|------|----|----------------|------------|
| Agent → Okta XAA | Agent | Okta | ID-JAG grant | Token structure, expiry, audience |
| Okta → MCP Server | Okta token | MCP Server | Scoped access token | Scope check against badge |
| Badge → AGNTCY JWKS | Badge JWT | Verifier | JWKS signature | Signature verification, not just decode |
| Secrets Manager → Code | AWS SM | Runtime | IAM role | Never log or expose secret values |

## Rollback Plan

1. **Detection**: How will we know the change is causing problems?
2. **Trigger**: What threshold triggers a rollback?
3. **Steps**: Exact rollback procedure
4. **Verification**: How to confirm rollback succeeded
5. **Communication**: Who needs to be notified
