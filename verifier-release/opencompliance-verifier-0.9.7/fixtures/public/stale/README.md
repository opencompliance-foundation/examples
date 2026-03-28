# Stale-Evidence Public Example

This example is synthetic.

It exists to show the narrow freshness-downgrade path for OpenCompliance without leaking any private customer, deployment, or audit material.

## Files

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

## What is different from the other packs

- the corridor is intentionally narrower than `../medium/`,
- every in-scope control is present,
- two of those claims are blocked because the evidence freshness window has expired,
- there are no missing-evidence or judgment blockers,
- and the deterministic Verify surface therefore emits a typed punch-list instead of a certificate.

## Intended use

- test the stale-evidence Verify path,
- inspect a raw-to-typed evidence conversion path,
- review how freshness blockers differ from failed predicates or missing evidence,
- exercise replay-bundle and witness-receipt generation for a freshness-blocked run,
- and keep the public examples honest about what a scoped certificate means.
