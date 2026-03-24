# Issued Public Example

This example is synthetic.

It exists to show the narrow certificate path for OpenCompliance without leaking any private customer, deployment, or audit material.

## Files

- `profile.json`
- `evidence-claims.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `certificate.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`
- `oscal/`

## What is different from the other packs

- the corridor is intentionally narrower than `../medium/`,
- every in-scope control has either machine evidence or signed attestation,
- there are no judgment-required or missing-evidence blockers,
- and the deterministic Verify surface therefore issues a synthetic certificate artifact instead of a punch-list.

## Intended use

- test the successful Verify path,
- review a narrow certificate artifact without over-claiming whole-framework coverage,
- exercise replay-bundle and witness-receipt generation for a certificate-eligible run,
- and keep the public examples honest about what a scoped certificate means.
