# Punch-List

## Purpose

A punch-list is the typed remediation artifact returned when a verification run is blocked.

It localizes what is missing instead of turning a failed or incomplete run into prose.

## Minimum required fields

- `punchListId`
- `generatedAt`
- `bundleId`
- `verifierVersion`
- `organisation`
- `profileId`
- `blockingIssueCount`
- `blockingIssues`

## Blocking issue entry

Each blocking issue should include:

- `claimId`
- `title`
- `issueType`
- `route`
- `frameworkMappings`
- `controlRefs`
- `requiredAction`
- `reason`

Optional:

- `requiredClaimType`

## Allowed issue types

- `missing_machine_evidence`
- `missing_attestation`
- `failing_machine_evidence`
- `failing_attestation`
- `stale_machine_evidence`
- `stale_attestation`
- `human_judgment_required`

## Rules

1. A punch-list should only include blocking issues, not already-satisfied claims.
2. A punch-list must stay faithful to the proof-bundle result categories.
3. `requiredAction` should be machine-meaningful enough to drive later workflow or docs.
