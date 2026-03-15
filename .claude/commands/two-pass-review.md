Perform a two-pass review of the current changeset. Both passes must be green before human review.

## Pass 1: Functional Correctness

### Acceptance Criteria
- Do the changes meet the acceptance criteria from the originating issue?
- If no issue is linked, flag: "WARNING — no issue linked to this changeset"

### Input/Output Contracts
- Are input/output contracts honored?
- Do function signatures match documented contracts?
- Are return types consistent?

### Edge Cases
- Are boundary conditions handled?
- Are error paths covered?
- Are empty/null/missing inputs handled?
- Are concurrent access scenarios considered?

### Test Coverage
- Are there tests for the happy path?
- Are there tests for error cases?
- Are there tests for edge cases?
- Do all tests pass? Run: `pytest tests/ -v`

### Pass 1 Verdict
- PASS: All checks green
- FAIL: List each failing check with details

---

## Pass 2: Security Review

Run the full security review audit (equivalent to /security-review).

### OWASP Mapping
Map each changed file to relevant OWASP Top Ten categories.

### Trust Boundary Validation
Check all trust boundary crossings:
- Agent → Okta XAA: ID-JAG validated before use?
- Okta → MCP Server: Scopes checked against badge?
- Badge → AGNTCY JWKS: Signature verified, not just decoded?
- Secrets Manager → Code: Secrets never logged or exposed?

### Input Validation
Verify per-boundary input validation with upstream rejection.

### Secrets Check
Scan for hardcoded secrets, committed .env files, exposed credentials.

### Dependency Check
Run: `pip-audit --desc 2>/dev/null || echo "pip-audit not installed"`

### Pass 2 Verdict
- PASS: No critical or high findings
- FAIL: List each finding with severity and remediation

---

## Final Verdict

Both passes must be PASS for the changeset to be ready for human review.

- If both pass: "READY FOR HUMAN REVIEW"
- If either fails: "NOT READY — resolve findings before requesting review"
