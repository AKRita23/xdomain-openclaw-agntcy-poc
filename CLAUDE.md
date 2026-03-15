# Cross-Domain Agent Identity PoC — Version A: AGNTCY TBAC Middleware

## Project
OpenClaw agent executing cross-domain tasks on behalf of a human user,
with identity attestation via AGNTCY Identity badges, Okta XAA (ID-JAG)
token exchange, and programmatic TBAC middleware enforcement.

## Stack
- Python 3.9+, httpx, pytest
- Okta XAA (ID-JAG grant type)
- AGNTCY Identity Service (badge issuance/verification)
- AWS Secrets Manager (credential management)
- MCP servers: Open-Meteo Weather, Slack

## Enterprise Vibe Coding Rules

### Planning Before Code
Before writing any code from a GitHub Issue, produce a structured
implementation plan covering:
1. Architecture decisions
2. File-by-file changes
3. Security controls per change
4. Test strategy
5. Rollback approach
6. Human review checkpoints

Do NOT write code until the plan is approved.

### Review Requirements
- Never skip the plan step
- Never invent features beyond what the issue documents
- Always run two-pass review before marking a PR ready for human review
- Every change must be traceable to an issue or acceptance criterion

### Trust Boundaries
These boundaries must be validated on every change:
- Agent → Okta XAA: ID-JAG must be validated before use
- Okta → MCP Server: Scopes checked against badge capabilities
- Badge → AGNTCY JWKS: Signature verified, not just decoded
- Secrets Manager → Code: Secrets never logged or exposed
