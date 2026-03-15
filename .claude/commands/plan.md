Read GitHub Issue #$ARGUMENTS and produce a structured implementation plan.

## Instructions

1. Fetch the issue using `gh issue view $ARGUMENTS --json title,body,labels`
2. Parse the issue fields: acceptance_criteria, security_considerations, trust_boundaries_affected, input_output_contracts, testability_criteria, threat_surface
3. **STOP and refuse to proceed if the threat_surface field is empty or missing.** Report: "Cannot plan — threat_surface is required but empty in issue #$ARGUMENTS. Update the issue before proceeding."

## Output Format

### Scope
- Issue title and number
- Summary of what this change does

### Affected Components
List every file that will be created, modified, or deleted.

### Architecture Decisions
- Key design choices and trade-offs
- Why this approach over alternatives

### Security Mapping
For each changed file:
- Trust boundaries crossed
- Input validation required
- OWASP category relevance
- Secrets handling impact

### Sequenced Tasks
Ordered list of implementation steps:
1. Task description
2. Files affected
3. Security controls for this step
4. Dependencies on prior steps

### Edge Cases
- Error scenarios
- Boundary conditions
- Failure modes and recovery

### Test Strategy
- Unit tests needed
- Integration tests needed
- Security-specific tests
- How to verify each acceptance criterion

### Rollback Approach
- How to revert if something goes wrong
- Data migration considerations
- Feature flag requirements (if any)

### Human Review Checkpoints
Mark points where a human must review before proceeding:
- [ ] Plan approved
- [ ] Security mapping reviewed
- [ ] Tests passing before merge
- [ ] Final PR review
