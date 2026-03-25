# Verification Result

## Purpose

A verification result is the deterministic top-level envelope returned by the Verify surface.

It points at the proof bundle, the trust-surface report, and exactly one outcome artifact:

- `certificate.json` for a narrow corridor with no blocking gaps, or
- `punch-list.json` when the run is blocked by failed claims, stale evidence, missing evidence, or human judgment.

## Minimum required fields

- `verificationResultId`
- `generatedAt`
- `bundleId`
- `verifierVersion`
- `organisation`
- `profileId`
- `outcome`
- `proofBundleSha256`
- `trustSurfaceSha256`
- `outcomeArtifact`
- `blockingIssueCount`

## Allowed outcome values

- `certificate_issued`
- `punch_list_issued`

## Rules

1. The verification result must be derived from deterministic artifacts only.
2. `certificate_issued` is only valid when the proof summary has zero `failed`, zero `staleEvidence`, zero `judgmentRequired`, and zero `evidenceMissing`.
3. `punch_list_issued` must point to a typed remediation artifact, not prose.
4. The verification result is the contract boundary for the Verify surface; it is not an invitation for narrative override.
