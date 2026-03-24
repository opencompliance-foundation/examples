# Medium Public Example

This example is synthetic.

It exists to show a richer public-safe corridor than `../minimal/` without leaking customer or internal deployment material.

## Files

- `company.json`
- `profile.json`
- `source-exports/`
- `evidence-claims.json`
- `classification-result.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `punch-list.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`
- `transparency-log.json`
- `inclusion-proofs.json`
- `oscal/`

## What is different from the minimal pack

- four-framework family mappings across ISO 27001, SOC 2, IRAP, and GDPR,
- more typed machine claims,
- more typed human attestations,
- raw source-export inputs for IAM, cloud config, repo policy, CI policy, and signed attestations,
- explicit `controlRefs` back into the synthetic OpenCompliance corridor catalog,
- a typed blocked outcome via `punch-list.json` and `verification-result.json`,
- and a wider OSCAL-shaped projection.

## Intended use

- test multi-framework import and export logic,
- exercise deterministic claim generation from raw synthetic source exports,
- exercise richer schema payloads,
- validate a larger witness receipt,
- and review how OpenCompliance keeps proofs, attestations, judgment, and missing evidence separate in a more realistic synthetic corridor.

## Connector note

The medium source-export path now includes synthetic repo branch-protection and CI workflow-policy claims so the public connector surface covers repo, CI/CD, IAM/MFA, and cloud/config evidence classes.

Those extra typed claims are not yet consumed by the current checked-in proof corridor. They exist to show the connector substrate and schema surface honestly before the proof corridor widens.
