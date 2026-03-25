# Certificate

## Purpose

A certificate is the scoped success artifact for a narrow OpenCompliance corridor.

It is not a legal replacement for an auditor or certifying body.

## Minimum required fields

- `certificateId`
- `status`
- `issuedAt`
- `bundleId`
- `verifierVersion`
- `organisation`
- `profileId`
- `scope`
- `controlRefs`
- `coverage`
- `proofBundleSha256`
- `trustSurfaceSha256`

## Rules

1. A certificate is only valid for the declared scope and control references.
2. A certificate may only be issued when the proof summary has zero `failed`, zero `staleEvidence`, zero `judgmentRequired`, and zero `evidenceMissing`.
3. A certificate should be publishable without hiding the underlying trust-surface split between proved and attested claims.
4. A certificate without a replay bundle is weaker and should be treated as an incomplete publication model.
