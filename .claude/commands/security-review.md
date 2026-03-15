Perform a security audit of the current changeset.

## Instructions

Run each check below against the staged or committed changes. Report findings with severity (CRITICAL, HIGH, MEDIUM, LOW, INFO).

### 1. OWASP Top Ten Mapping
For each changed file, identify which OWASP Top Ten categories apply:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Data Integrity Failures
- A09: Logging Failures
- A10: SSRF

### 2. Trust Boundary Crossings
Flag any changes that cross these boundaries:
- **Agent → Okta XAA**: Is ID-JAG validated before use? Are token expiry and audience checked?
- **Okta → MCP Server**: Are scopes checked against badge capabilities? Is the token properly scoped?
- **Badge → AGNTCY JWKS**: Is the signature verified (not just decoded)? Is the JWKS endpoint validated?
- **Secrets Manager → Code**: Are secrets ever logged, printed, or exposed in error messages?

### 3. Per-Boundary Input Validation
For each trust boundary crossing found:
- Is input validated at the boundary?
- Does validation reject (not just sanitize) invalid input?
- Are error messages safe (no secret leakage)?

### 4. Hardcoded Secrets Check
Search the changeset for:
- API keys, tokens, passwords in source code
- Hardcoded URLs with credentials
- `.env` files committed (should be `.env.example` only)
- Private keys or certificates

### 5. Dependency CVE Check
Run: `pip-audit --desc 2>/dev/null || echo "pip-audit not installed — install with: pip install pip-audit"`

### 6. Sanitization-Only Patterns
Flag any pattern that sanitizes input without rejecting it upstream. The correct pattern is: validate → reject if invalid → proceed. Never sanitize-and-continue.

## Verdict

If any CRITICAL findings are detected:
- Report: "BLOCKED — critical security findings must be resolved before merge"
- List each critical finding with remediation steps

If HIGH findings exist:
- Report: "WARNING — high-severity findings require review"

Otherwise:
- Report: "PASSED — no critical or high findings"
