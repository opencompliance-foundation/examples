# Certificate Lifecycle Event

## Purpose

A certificate lifecycle event records what happened to a previously issued certificate after a normalized source change.

It exists to make drift handling explicit rather than letting certificates silently age.

## Minimum required fields

- `lifecycleEventId`
- `generatedAt`
- `certificateId`
- `organisation`
- `profileId`
- `frameworkIntent`
- `previousStatus`
- `newStatus`
- `decisionReason`
- `sourceChangeId`
- `sourceChange`
- `impactedControlRefs`
- `impactedClaims`
- `deltaRecheck`
- `lineage`
- `compositionBlocked`
- `emittedEvents`
- `proofBundleSha256`

## Rules

1. Lifecycle evaluation starts from a previously issued certificate and a normalized source-change event.
2. A drift event must identify which controls and proof claims are impacted.
3. Delta recheck plans should only include impacted claims and explicitly list reused claims.
4. Revoked or re-verification-required child certificates block higher-level composition until trust is restored.
